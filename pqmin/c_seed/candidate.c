#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zstd.h>

/* PQCOL01 bundle enums are the standard Parquet enum values. */
enum { PARQUET_DELTA_BINARY_PACKED = 5, PARQUET_ZSTD = 6 };

typedef struct {
    uint8_t *data;
    size_t length;
    size_t capacity;
} Buffer;

typedef struct {
    uint32_t block_values;
    uint64_t page_rows;
    int level;
    int window_log;
    int hash_log;
    int chain_log;
    int search_log;
    int min_match;
    int target_length;
    int strategy;
    uint32_t page_version;
} Options;

static void die(const char *message) {
    fprintf(stderr, "candidate: %s\n", message);
    exit(1);
}

static void die_errno(const char *message) {
    fprintf(stderr, "candidate: %s: %s\n", message, strerror(errno));
    exit(1);
}

static void *xmalloc(size_t size) {
    void *result = malloc(size ? size : 1);
    if (!result) die("out of memory");
    return result;
}

static void reserve(Buffer *buffer, size_t extra) {
    if (extra <= buffer->capacity - buffer->length) return;
    if (extra > SIZE_MAX - buffer->length) die("encoded buffer overflow");
    size_t required = buffer->length + extra;
    size_t capacity = buffer->capacity ? buffer->capacity : (1u << 20);
    while (capacity < required) {
        size_t next = capacity + capacity / 2;
        if (next <= capacity || next > SIZE_MAX) { capacity = required; break; }
        capacity = next;
    }
    void *replacement = realloc(buffer->data, capacity);
    if (!replacement) die("out of memory growing encoded buffer");
    buffer->data = replacement;
    buffer->capacity = capacity;
}

static void put_byte(Buffer *buffer, uint8_t value) {
    reserve(buffer, 1);
    buffer->data[buffer->length++] = value;
}

static void put_uvarint(Buffer *buffer, uint64_t value) {
    while (value >= 0x80) {
        put_byte(buffer, (uint8_t)(value | 0x80));
        value >>= 7;
    }
    put_byte(buffer, (uint8_t)value);
}

static uint64_t zigzag64(int64_t value) {
    return ((uint64_t)value << 1) ^ (uint64_t)(value >> 63);
}

static unsigned bit_width(uint64_t value) {
    return value ? 64u - (unsigned)__builtin_clzll(value) : 0u;
}

static void pack_32(Buffer *output, const uint64_t values[32], unsigned width) {
    if (!width) return;
    reserve(output, (size_t)width * 4);
    __uint128_t accumulator = 0;
    unsigned bits = 0;
    for (unsigned index = 0; index < 32; ++index) {
        accumulator |= (__uint128_t)values[index] << bits;
        bits += width;
        while (bits >= 8) {
            output->data[output->length++] = (uint8_t)accumulator;
            accumulator >>= 8;
            bits -= 8;
        }
    }
    if (bits != 0) die("internal bit-packing error");
}

static void encode_delta_page(
    const int64_t *values,
    uint64_t count,
    uint32_t block_values,
    Buffer *output,
    int64_t *minimum,
    int64_t *maximum
) {
    output->length = 0;
    uint32_t mini_blocks = block_values / 32;
    put_uvarint(output, block_values);
    put_uvarint(output, mini_blocks);
    put_uvarint(output, count);
    if (!count) { put_uvarint(output, 0); return; }
    put_uvarint(output, zigzag64(values[0]));
    *minimum = values[0];
    *maximum = values[0];

    int64_t *deltas = xmalloc((size_t)block_values * sizeof(*deltas));
    uint64_t *normalized = xmalloc((size_t)block_values * sizeof(*normalized));
    uint8_t *widths = xmalloc(mini_blocks);
    uint64_t position = 1;
    while (position < count) {
        uint64_t remaining = count - position;
        uint32_t populated = remaining < block_values ? (uint32_t)remaining : block_values;
        int64_t min_delta = INT64_MAX;
        for (uint32_t index = 0; index < populated; ++index) {
            int64_t current = values[position + index];
            int64_t previous = values[position + index - 1];
            int64_t delta = current - previous;
            deltas[index] = delta;
            if (delta < min_delta) min_delta = delta;
            if (current < *minimum) *minimum = current;
            if (current > *maximum) *maximum = current;
        }
        for (uint32_t index = populated; index < block_values; ++index) deltas[index] = min_delta;
        for (uint32_t index = 0; index < block_values; ++index)
            normalized[index] = (uint64_t)deltas[index] - (uint64_t)min_delta;
        for (uint32_t mini = 0; mini < mini_blocks; ++mini) {
            uint64_t aggregate = 0;
            for (uint32_t index = 0; index < 32; ++index)
                aggregate |= normalized[mini * 32 + index];
            widths[mini] = (uint8_t)bit_width(aggregate);
        }
        put_uvarint(output, zigzag64(min_delta));
        reserve(output, mini_blocks);
        memcpy(output->data + output->length, widths, mini_blocks);
        output->length += mini_blocks;
        for (uint32_t mini = 0; mini < mini_blocks; ++mini)
            pack_32(output, normalized + mini * 32, widths[mini]);
        position += populated;
    }
    free(widths);
    free(normalized);
    free(deltas);
}

static uint64_t parse_u64(const char *text, const char *name) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || !end || *end) {
        fprintf(stderr, "candidate: invalid %s: %s\n", name, text);
        exit(2);
    }
    return (uint64_t)value;
}

static int parse_int(const char *text, const char *name) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || !end || *end || value < INT_MIN || value > INT_MAX) {
        fprintf(stderr, "candidate: invalid %s: %s\n", name, text);
        exit(2);
    }
    return (int)value;
}

static void write_exact(FILE *stream, const void *data, size_t size) {
    if (size && fwrite(data, 1, size, stream) != size) die_errno("write failed");
}

static void write_u32(FILE *stream, uint32_t value) { write_exact(stream, &value, sizeof(value)); }
static void write_u64(FILE *stream, uint64_t value) { write_exact(stream, &value, sizeof(value)); }
static void write_i64(FILE *stream, int64_t value) { write_exact(stream, &value, sizeof(value)); }

static void ensure_output_parent(const char *path) {
    char *copy = strdup(path);
    if (!copy) die("out of memory");
    char *slash = strrchr(copy, '/');
    if (slash) {
        *slash = '\0';
        if (*copy && mkdir(copy, 0777) && errno != EEXIST) die_errno("cannot create output directory");
    }
    free(copy);
}

static Options options_from_args(int argc, char **argv) {
    Options options = {128, 225000000, 10, 31, 23, 25, 7, 6, 128, 5, 1};
    if (argc > 3) options.block_values = (uint32_t)parse_u64(argv[3], "block_values");
    if (argc > 4) options.page_rows = parse_u64(argv[4], "page_rows");
    if (argc > 5) options.level = parse_int(argv[5], "zstd_level");
    if (argc > 6) options.window_log = parse_int(argv[6], "windowLog");
    if (argc > 7) options.hash_log = parse_int(argv[7], "hashLog");
    if (argc > 8) options.chain_log = parse_int(argv[8], "chainLog");
    if (argc > 9) options.search_log = parse_int(argv[9], "searchLog");
    if (argc > 10) options.min_match = parse_int(argv[10], "minMatch");
    if (argc > 11) options.target_length = parse_int(argv[11], "targetLength");
    if (argc > 12) options.strategy = parse_int(argv[12], "strategy");
    if (argc > 13) options.page_version = (uint32_t)parse_u64(argv[13], "page_version");
    if (options.block_values < 128 || options.block_values > 65536 ||
        (options.block_values & (options.block_values - 1)) || options.block_values % 32)
        die("block_values must be a power of two from 128 through 65536");
    if (!options.page_rows || options.page_rows > INT32_MAX) die("page_rows must be 1..2^31-1");
    if (options.page_version != 1 && options.page_version != 2) die("page_version must be 1 or 2");
    return options;
}

static void set_zstd_parameter(ZSTD_CCtx *context, ZSTD_cParameter parameter, int value, const char *name) {
    size_t result = ZSTD_CCtx_setParameter(context, parameter, value);
    if (ZSTD_isError(result)) {
        fprintf(stderr, "candidate: zstd %s=%d: %s\n", name, value, ZSTD_getErrorName(result));
        exit(2);
    }
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 14) {
        fprintf(stderr, "usage: %s INPUT.i64le OUTPUT.column [block pageRows level window hash chain search minMatch target strategy pageVersion]\n", argv[0]);
        return 2;
    }
    const uint16_t endian_probe = 1;
    if (*(const uint8_t *)&endian_probe != 1) die("this starter requires a little-endian host");
    Options options = options_from_args(argc, argv);
    int input_fd = open(argv[1], O_RDONLY);
    if (input_fd < 0) die_errno("cannot open input");
    struct stat status;
    if (fstat(input_fd, &status)) die_errno("cannot stat input");
    if (status.st_size <= 0 || status.st_size % 8) die("input is not a nonempty int64-le stream");
    uint64_t total_rows = (uint64_t)status.st_size / 8;
    const int64_t *values = mmap(NULL, (size_t)status.st_size, PROT_READ, MAP_PRIVATE, input_fd, 0);
    if (values == MAP_FAILED) die_errno("cannot map input");
    uint64_t page_count64 = (total_rows + options.page_rows - 1) / options.page_rows;
    if (page_count64 > UINT32_MAX) die("too many pages");

    ensure_output_parent(argv[2]);
    FILE *output = fopen(argv[2], "wb");
    if (!output) die_errno("cannot open output");
    write_exact(output, "PQCOL01\0", 8);
    write_u32(output, 1);
    write_u32(output, PARQUET_DELTA_BINARY_PACKED);
    write_u32(output, PARQUET_ZSTD);
    write_u32(output, options.page_version);
    write_u32(output, (uint32_t)page_count64);
    write_u64(output, total_rows);

    ZSTD_CCtx *zstd = ZSTD_createCCtx();
    if (!zstd) die("cannot allocate zstd context");
    set_zstd_parameter(zstd, ZSTD_c_compressionLevel, options.level, "level");
    set_zstd_parameter(zstd, ZSTD_c_windowLog, options.window_log, "windowLog");
    set_zstd_parameter(zstd, ZSTD_c_hashLog, options.hash_log, "hashLog");
    set_zstd_parameter(zstd, ZSTD_c_chainLog, options.chain_log, "chainLog");
    set_zstd_parameter(zstd, ZSTD_c_searchLog, options.search_log, "searchLog");
    set_zstd_parameter(zstd, ZSTD_c_minMatch, options.min_match, "minMatch");
    set_zstd_parameter(zstd, ZSTD_c_targetLength, options.target_length, "targetLength");
    set_zstd_parameter(zstd, ZSTD_c_strategy, options.strategy, "strategy");

    Buffer encoded = {0};
    uint8_t *compressed = NULL;
    size_t compressed_capacity = 0;
    for (uint64_t first = 0; first < total_rows; first += options.page_rows) {
        uint64_t rows = total_rows - first;
        if (rows > options.page_rows) rows = options.page_rows;
        int64_t minimum, maximum;
        encode_delta_page(values + first, rows, options.block_values, &encoded, &minimum, &maximum);
        size_t needed = ZSTD_compressBound(encoded.length);
        if (needed > compressed_capacity) {
            void *replacement = realloc(compressed, needed);
            if (!replacement) die("out of memory growing compressed buffer");
            compressed = replacement;
            compressed_capacity = needed;
        }
        size_t reset = ZSTD_CCtx_reset(zstd, ZSTD_reset_session_only);
        if (ZSTD_isError(reset)) die(ZSTD_getErrorName(reset));
        size_t pledged = ZSTD_CCtx_setPledgedSrcSize(zstd, encoded.length);
        if (ZSTD_isError(pledged)) die(ZSTD_getErrorName(pledged));
        size_t compressed_size = ZSTD_compress2(zstd, compressed, compressed_capacity, encoded.data, encoded.length);
        if (ZSTD_isError(compressed_size)) die(ZSTD_getErrorName(compressed_size));
        write_u64(output, rows);
        write_i64(output, minimum);
        write_i64(output, maximum);
        write_u64(output, encoded.length);
        write_u64(output, compressed_size);
        write_exact(output, compressed, compressed_size);
    }

    off_t bundle_bytes = ftello(output);
    if (bundle_bytes < 0 || fflush(output) || fsync(fileno(output)) || fclose(output))
        die_errno("cannot finalize output");
    fprintf(stderr, "rows=%" PRIu64 " pages=%" PRIu64 " bundle_bytes=%jd\n",
            total_rows, page_count64, (intmax_t)bundle_bytes);
    free(compressed);
    free(encoded.data);
    ZSTD_freeCCtx(zstd);
    munmap((void *)values, (size_t)status.st_size);
    close(input_fd);
    return 0;
}
