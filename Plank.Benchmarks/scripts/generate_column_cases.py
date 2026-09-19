#!/usr/bin/env python3
"""Generate column-payload counterparts from the checked-in row case schemas and options."""
from pathlib import Path
import re, json

root = Path(__file__).resolve().parents[1] / 'Published' / 'Cases'
widths = {x['stem']: x['columnCount'] for x in json.loads((root/'matrix.json').read_text())}

def method(source, name):
    m = re.search(r'    public (?:async )?[^\n]+ '+name+r'\([^\n]*\)\s*(\{|=>)',source)
    if not m: return None
    if m[1]=='=>':
        end=source.index(';',m.end())+1
        return source[m.start():end]
    start=m.end()-1; level=1; end=start+1
    while level:
        level+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[m.start():end]

def body(source,name):
    s=method(source,name)
    return s[s.index('{')+1:s.rindex('}')]

def emit_method(name,content,attribute=None,result='void',async_=False):
    return (f'    [{attribute}]\n' if attribute else '')+f'    public {"async " if async_ else ""}{result} {name}()\n    {{\n{content}\n    }}\n'

def replace_method(source, name, content):
    current = method(source, name)
    if current is None:
        return source
    signature = current[:current.index('{')].rstrip()
    replacement = signature + f'\n    {{\n{content}\n    }}'
    start = source.index(current)
    return source[:start] + replacement + source[start + len(current):]

def remove_method(source, name):
    current = method(source, name)
    if current is None:
        return source
    method_start = source.index(current)
    end = method_start + len(current)
    start = method_start
    attribute_start = source.rfind('\n    [', 0, start)
    if attribute_start >= 0 and source[attribute_start + 6:start].strip().endswith(']'):
        start = attribute_start + 1
    return source[:start] + source[end:]

def class_blocks(source):
    for match in list(re.finditer(r'\[MemoryDiagnoser\]\npublic class (\w+)\n\{', source)):
        opening = source.index('{', match.start())
        level = 1
        end = opening + 1
        while level:
            level += (source[end] == '{') - (source[end] == '}')
            end += 1
        yield match[1], match.start(), end, source[match.start():end]

def add_fields(block, fields):
    marker = block.index('\n{', block.index('public class ')) + 2
    return block[:marker] + '\n' + fields + block[marker:]

def remove_fields(block, names):
    for name in names:
        block = re.sub(rf'^    [^;\n]*\b{re.escape(name)}\b[^;\n]*;\n', '', block, flags=re.M)
    return block

def plank_parallel_read_methods(props, width):
    result = []
    for i, (_, typ, _) in enumerate(props):
        lines = [f'    long ReadColumn{i}()', '    {', '        long count = 0;']
        lines += [f'        foreach (var group in _columnReaders[{i}].RowGroups)', '        {']
        if 'Memory<byte>' in typ:
            lines += [f'            foreach (var buffer in group.Column<byte>({i}))', '            {',
                      '                ReadConsumption.Consume(buffer.Values);',
                      '                count += buffer.Count;', '            }']
        else:
            lines += [f'            foreach (var buffer in group.Column<{typ}>({i}))', '            {',
                      '                ReadConsumption.Consume(buffer.Values);',
                      '                count += buffer.Count;', '            }']
        lines += ['        }', '        return count;', '    }', '']
        result.extend(lines)
    result += ['    long ReadColumn(int ordinal)', '        => ordinal switch', '        {']
    result += [f'            {i} => ReadColumn{i}(),' for i in range(width)]
    result += ['            _ => throw new ArgumentOutOfRangeException(nameof(ordinal))', '        };', '']
    return '\n'.join(result)

def parquetsharp_parallel_read_methods(props, width):
    result = []
    for i, (_, typ, _) in enumerate(props):
        result += [f'    long ReadColumn{i}()', '    {', '        long count = 0;',
                   f'        for (var g = 0; g < _columnReaders[{i}].FileMetaData.NumRowGroups; g++)',
                   '        {', f'            using var group = _columnReaders[{i}].RowGroup(g);',
                   f'            using var column = group.Column({i}).LogicalReader<{typ}>();',
                   '            while (column.HasNext)', '            {',
                   f'                var length = column.ReadBatch(_read{i});',
                   f'                ReadConsumption.Consume(_read{i}.AsSpan(0, length));',
                   '                count += length;', '            }', '        }',
                   '        return count;', '    }', '']
    result += ['    long ReadColumn(int ordinal)', '        => ordinal switch', '        {']
    result += [f'            {i} => ReadColumn{i}(),' for i in range(width)]
    result += ['            _ => throw new ArgumentOutOfRangeException(nameof(ordinal))', '        };', '']
    return '\n'.join(result)

def generate_multi_file(stem, generated, props, width):
    output = [generated[:generated.index('[MemoryDiagnoser]')],
              '// Generated by scripts/generate_column_cases.py. Multi adapters own one reader or serializer per column.\n']
    for lib in ('Plank', 'ParquetSharp'):
        class_name = stem + 'Column' + lib + 'Benchmarks'
        match = next((item for item in class_blocks(generated) if item[0] == class_name), None)
        if match is None or width < 2:
            continue
        block = match[3].replace(class_name, stem + 'ColumnMulti' + lib + 'Benchmarks', 1)
        fields = ('    int _columnWorkerCount;\n'
                  '    readonly ColumnParallelism.Tracker _parallelism = new();\n'
                  '    int _writeThreads;\n    int _readThreads;\n')
        if lib == 'Plank':
            fields += ('    MemoryReadSource[] _columnSources = null!;\n'
                       '    Plank.Reading.Logical.ParquetReader[] _columnReaders = null!;\n'
                       '    long[] _columnCounts = null!;\n')
        else:
            fields += ('    ParquetFileReader[] _columnReaders = null!;\n'
                       '    BufferReader[] _columnSources = null!;\n'
                       '    long[] _columnCounts = null!;\n')
        block = add_fields(block, fields)
        # The row adapters use library-specific CLR representations for binary
        # columns (Plank uses ReadOnlyMemory<byte>; ParquetSharp uses string).
        # Recover the exact type from the generated adapter rather than reusing
        # the Parquet.Net row schema below.
        column_props = []
        for i, (column_name, _, property_name) in enumerate(props):
            if lib == 'Plank':
                # The serialized column type can itself be generic (for
                # example ReadOnlyMemory<byte>), so match through the final
                # closing angle bracket before the field name.
                type_match = re.search(rf'SerializedColumn<(.+)> _s{i}', block)
            else:
                type_match = re.search(rf'    ([^ ]+)\[\] _read{i}', block)
            column_props.append((column_name, type_match[1] if type_match else props[i][1], property_name))
        if lib == 'ParquetSharp':
            # ParquetSharp exposes only a row-group writer that appends directly to
            # the output stream, so only its independent-column reader is multi.
            for name in ('GlobalSetupWrite', 'SetupWrite', 'Write', 'CleanupWrite'):
                block = remove_method(block, name)
            block = remove_fields(block, ['_rows', '_output', '_outputBuffer', '_expectedOutputBytes',
                                          '_schema', '_properties', '_managedOutput', '_writer', '_writeThreads',
                                          *[f'_c{i}' for i in range(width)]])
        else:
            serialize = ['    void SerializeColumn(int ordinal, int start, int count)',
                         '    {', '        switch (ordinal)', '        {']
            serialize += [f'            case {i}: _s{i}.Serialize(_c{i}.AsSpan(start, count)); break;' for i in range(width)]
            serialize += ['            default: throw new ArgumentOutOfRangeException(nameof(ordinal));',
                          '        }', '    }', '']
            marker = '    [Benchmark]\n    public void Write()'
            block = block.replace(marker, '\n'.join(serialize) + marker, 1)
            write = [f'        for (var start = 0; start < Rows; start += RowsPerRowGroup)',
                     '        {', '            var count = Math.Min(RowsPerRowGroup, Rows - start);',
                     f'            _writeThreads = Math.Max(_writeThreads, _parallelism.Run({width}, _columnWorkerCount,',
                     '                index => SerializeColumn(index, start, count)));',
                     '            var group = _writer.StartRowGroup();']
            write += [f'            group.Write(_s{i});' for i in range(width)]
            write += ['        }', '        _writer.CloseFile();']
            block = replace_method(block, 'Write', '\n'.join(write))
            block = replace_method(block, 'CleanupWrite',
                '        BenchmarkFixtures.ValidateOutput(_expectedOutputBytes, BenchmarkFixtures.OutputLength(_output));\n'
                '        ColumnParallelism.WriteMarker(GetType().Name, "write", _columnWorkerCount, _writeThreads);\n'
                '        _output?.Dispose();')
            write_setup = body(block, 'GlobalSetupWrite').rstrip()
            block = replace_method(block, 'GlobalSetupWrite',
                                   write_setup + f'\n        _columnWorkerCount = ColumnParallelism.WorkerCount({width});')

        if lib == 'Plank':
            setup = [
                '        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);',
                f'        var file = BenchmarkFixtures.LoadReadFile("{stem}");',
                f'        _columnSources = new MemoryReadSource[{width}];',
                f'        _columnReaders = new Plank.Reading.Logical.ParquetReader[{width}];',
                f'        _columnCounts = new long[{width}];',
                f'        for (var index = 0; index < {width}; index++)', '        {',
                '            _columnSources[index] = new MemoryReadSource(file);',
                '            _columnReaders[index] = new Plank.Reading.Logical.ParquetReader(',
                '                new Plank.Reading.Logical.ParquetReaderOptions { BufferPool = _pool });',
                '        }', '        _source = _columnSources[0];', '        _reader = _columnReaders[0];',
                f'        _columnWorkerCount = ColumnParallelism.WorkerCount({width});']
            iteration = [f'        for (var index = 0; index < {width}; index++)',
                         '            _columnReaders[index].Reset(_columnSources[index]);']
            block = replace_method(block, 'GlobalSetupRead', '\n'.join(setup))
            block = replace_method(block, 'SetupRead', '\n'.join(iteration))
            block = remove_method(block, 'Read')
            read = [plank_parallel_read_methods(column_props, width), '    [Benchmark]', '    public long Read()', '    {',
                    f'        _parallelism.Run({width}, _columnWorkerCount,',
                    '            index => _columnCounts[index] = ReadColumn(index));', '        long count = 0;',
                    f'        for (var index = 0; index < {width}; index++)',
                    '            count += _columnCounts[index];',
                    f'        if (count != (long)Rows * {width})',
                    '            throw new InvalidDataException($"Expected {(long)Rows * ' + str(width) + '} values, got {count}.");',
                    '        _readThreads = _parallelism.LastObserved;', '        return count;', '    }', '']
            insertion = block.rfind('\n    [GlobalCleanup]')
            block = block[:insertion] + '\n' + '\n'.join(read) + block[insertion:]
            cleanup = [
                '        if (_readThreads > 0)',
                '            ColumnParallelism.WriteMarker(GetType().Name, "read", _columnWorkerCount, _readThreads);',
                '        foreach (var reader in _columnReaders ?? [])', '            reader?.Dispose();',
                '        foreach (var source in _columnSources ?? [])', '            source?.Dispose();',
                '        _writer?.Dispose();', '        _pool?.Dispose();', '        _output?.Dispose();']
            block = replace_method(block, 'Cleanup', '\n'.join(cleanup))
        else:
            setup = [f'        var file = BenchmarkFixtures.LoadReadFile("{stem}");',
                     '        _pinned = GCHandle.Alloc(file, GCHandleType.Pinned);',
                     '        _buffer = new NativeBuffer(_pinned.AddrOfPinnedObject(), file.LongLength);',
                     f'        _columnSources = new BufferReader[{width}];',
                     f'        for (var index = 0; index < {width}; index++)',
                     '            _columnSources[index] = new BufferReader(_buffer);',
                     '        _source = _columnSources[0];',
                     f'        _columnReaders = new ParquetFileReader[{width}];',
                     f'        _columnCounts = new long[{width}];',
                     f'        _columnWorkerCount = ColumnParallelism.WorkerCount({width});']
            iteration = ['        foreach (var reader in _columnReaders ?? [])', '            reader?.Dispose();',
                         f'        _columnReaders = new ParquetFileReader[{width}];',
                         f'        for (var index = 0; index < {width}; index++)',
                         '            _columnReaders[index] = new ParquetFileReader(_columnSources[index]);',
                         '        _reader = _columnReaders[0];']
            block = replace_method(block, 'GlobalSetupRead', '\n'.join(setup))
            block = replace_method(block, 'SetupRead', '\n'.join(iteration))
            block = remove_method(block, 'Read')
            read = [parquetsharp_parallel_read_methods(column_props, width), '    [Benchmark]', '    public long Read()', '    {',
                    f'        _parallelism.Run({width}, _columnWorkerCount,',
                    '            index => _columnCounts[index] = ReadColumn(index));', '        long count = 0;',
                    f'        for (var index = 0; index < {width}; index++)',
                    '            count += _columnCounts[index];',
                    f'        if (count != (long)Rows * {width})',
                    '            throw new InvalidDataException($"Expected {(long)Rows * ' + str(width) + '} values, got {count}.");',
                    '        _readThreads = _parallelism.LastObserved;', '        return count;', '    }', '']
            insertion = block.rfind('\n    [GlobalCleanup]')
            block = block[:insertion] + '\n' + '\n'.join(read) + block[insertion:]
            cleanup = ['        if (_readThreads > 0)',
                       '            ColumnParallelism.WriteMarker(GetType().Name, "read", _columnWorkerCount, _readThreads);',
                       '        foreach (var reader in _columnReaders ?? [])', '            reader?.Dispose();',
                       '        foreach (var source in _columnSources ?? [])', '            source?.Dispose();',
                       '        _buffer?.Dispose();', '        if (_pinned.IsAllocated) _pinned.Free();',
                       ]
            block = replace_method(block, 'Cleanup', '\n'.join(cleanup))
        output.append(block + '\n')
    return ''.join(output) if len(output) > 2 else ''

kernels = {}

for path in sorted(root.glob('*.cs')):
    if path.stem.endswith(('Column', 'ColumnMulti')): continue
    text=path.read_text(); stem=path.stem
    header=text[:text.index('[ParquetSchema')]
    out=[header,'// Generated by scripts/generate_column_cases.py. Row cases remain unchanged.\n']
    for lib in ['Plank','ParquetSharp','ParquetNet']:
        name=stem+lib+'Benchmarks'
        if 'public class '+name not in text: continue
        src=text.split('public class '+name,1)[1].split('\n[MemoryDiagnoser]',1)[0]
        rowmatch=re.search(r'    (\w+)\[\] _rows',src) or re.search(r'DeserializeAsync<(\w+)>',src)
        assert rowmatch, (stem,lib)
        rowtype=rowmatch[1]
        rowdef=text.split('sealed partial class '+rowtype,1)[1] if 'sealed partial class '+rowtype in text else text.split('sealed class '+rowtype,1)[1]
        rowdef=rowdef.split('\n[MemoryDiagnoser]',1)[0].split('\nsealed ',1)[0]
        props=re.findall(r'\[[^\n]*JsonPropertyName\("([^"]+)"\)[^\n]*\]\s+public ([^\n]+?) (\w+) \{ get; set; \}',rowdef)
        assert props,(path,rowtype)
        # A source block can include the next row type; stop after the schema's expected width.
        props=props[:widths[stem]]
        width=len(props); rowsper=45455 if stem.startswith('Synthetic') else 1048576
        haswrite=method(src,'Write') is not None; hasread=method(src,'Read') is not None
        # Unsupported read-only classes still have schema properties; their setup has no write side.
        out+=['[MemoryDiagnoser]\npublic class '+stem+'Column'+lib+'Benchmarks\n{\n',
              f'    const int RowsPerRowGroup = {rowsper};\n    {rowtype}[] _rows = null!;\n    MemoryStream _output = null!;\n    byte[] _outputBuffer = null!;\n    long _expectedOutputBytes;\n']
        for i,(_,typ,_) in enumerate(props):out.append(f'    {typ}[] _c{i} = null!;\n')
        if lib=='Plank':
            out+=['    DefaultParquetBufferPool _pool = null!;\n    Plank.Writing.ParquetWriter _writer = null!;\n    MemoryReadSource _source = null!;\n    Plank.Reading.Logical.ParquetReader _reader = null!;\n']
            for i,(_,typ,_) in enumerate(props):out.append(f'    SerializedColumn<{typ}> _s{i} = null!;\n')
        elif lib=='ParquetSharp':
            out+=['    ParquetSharp.Column[] _schema = null!;\n    WriterProperties _properties = null!;\n    ManagedOutputStream _managedOutput = null!;\n    ParquetFileWriter _writer = null!;\n    ParquetFileReader _reader = null!;\n    GCHandle _pinned;\n    NativeBuffer _buffer = null!;\n    BufferReader _source = null!;\n']
            for i,(_,typ,_) in enumerate(props):out.append(f'    {typ}[] _read{i} = new {typ}[65536];\n')
        else:
            out+=['    ParquetOptions _options = null!;\n    Parquet.Schema.ParquetSchema _schema = null!;\n    byte[] _file = null!;\n    MemoryStream _stream = null!;\n']
        out.append('    public IEnumerable<int> RowCounts => [BenchmarkData.'+('SyntheticRows' if stem.startswith('Synthetic') else 'TaxiRows')+'];\n    [ParamsSource(nameof(RowCounts))]\n    public int Rows { get; set; }\n')
        if haswrite:
            setup=body(src,'GlobalSetupWrite')
            marker={'Plank':'        _pool =','ParquetSharp':'        _schema =','ParquetNet':'        _options ='}[lib]
            load=setup[:setup.index(marker)]
            transpose='\n'.join(f'        _c{i} = _rows.Select(value => value.{prop}).ToArray();' for i,(_,_,prop) in enumerate(props))+'\n        _rows = null!;'
            if lib=='Plank':
                extra=f'''        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        using var preparationOutput = new MemoryStream();
        _writer = {rowtype}.Schema.CreateWriter(preparationOutput, new ParquetWriterOptions
        {{ Compression = CompressionKind.None, BufferPool = _pool, DataPageVersion = ParquetDataPageVersion.V2,
           WritePageIndexes = true, WritePageCrc = false }});
'''+ '\n'.join(f'        _s{i} = _writer.CreateSerializedColumn<{typ}>({rowtype}.Schema.LeafColumns[{i}]);' for i,(_,typ,_) in enumerate(props))
            elif lib=='ParquetSharp': extra=setup[setup.index(marker):setup.index('        _outputBuffer =')]
            else:
                extra=setup[setup.index(marker):setup.index('        _outputBuffer =')]
                fields=[]
                for col,typ,_ in props:
                    fields.append(f'new Parquet.Schema.DateTimeDataField("{col}", Parquet.Schema.DateTimeFormat.Timestamp, false, Parquet.Schema.DateTimeTimeUnit.Micros, {str(typ.endswith("?")).lower()})' if 'DateTime' in typ else f'new Parquet.Schema.DataField<{typ}>("{col}", {str(typ.endswith("?")).lower()})')
                extra+='        _schema = new Parquet.Schema.ParquetSchema('+', '.join(fields)+');\n'
            extra+=f'\n        _outputBuffer = new byte[BenchmarkFixtures.GetOutputCapacity("{stem}Column", "'+('Parquet.Net' if lib=='ParquetNet' else lib)+'", out _expectedOutputBytes)];'
            out.append(emit_method('GlobalSetupWrite',load+transpose+'\n'+extra,'GlobalSetup(Target = nameof(Write))'))
            setup='        _output = BenchmarkFixtures.CreateOutput(_outputBuffer);\n'
            if lib=='Plank':setup+='        _writer.Reset(_output);'
            elif lib=='ParquetSharp':setup+='        _managedOutput = new ManagedOutputStream(_output, leaveOpen: true);\n        _writer = new ParquetFileWriter(_managedOutput, _schema, _properties);'
            out.append(emit_method('SetupWrite',setup,'IterationSetup(Target = nameof(Write))'))
            write=''
            if lib=='ParquetNet':
                write='        await using var writer = await Parquet.ParquetWriter.CreateAsync(_schema, _output, _options);\n        var fields = _schema.GetDataFields();\n        for (var start = 0; start < Rows; start += RowsPerRowGroup)\n        {\n            var count = Math.Min(RowsPerRowGroup, Rows - start);\n            using var group = writer.CreateRowGroup();\n'
                for i,(_,typ,_) in enumerate(props):
                    if typ.startswith('string'):
                        write+=f'            await group.WriteAsync(fields[{i}], new ArraySegment<string?>(_c{i}, start, count));\n'
                    else:
                        write+=f'            await group.WriteAsync<{typ.rstrip("?")}>(fields[{i}], _c{i}.AsMemory(start, count));\n'
                write+='        }'

            else:
                write='        for (var start = 0; start < Rows; start += RowsPerRowGroup)\n        {\n            var count = Math.Min(RowsPerRowGroup, Rows - start);\n'
                if lib=='Plank':
                    write+='\n'.join(f'            _s{i}.Serialize(_c{i}.AsSpan(start, count));' for i in range(width))+'\n            var group = _writer.StartRowGroup();\n'
                    write+='\n'.join(f'            group.Write(_s{i});' for i in range(width))
                else:
                    write+='            using var group = _writer.AppendRowGroup();\n'
                    write+='\n'.join(f'            using (var column = group.NextColumn().LogicalWriter<{typ}>())\n                column.WriteBatch(_c{i}.AsSpan(start, count));' for i,(_,typ,_) in enumerate(props))
                write+='\n        }\n        _writer.'+('CloseFile' if lib=='Plank' else 'Close')+'();'
            out.append(emit_method('Write',write,'Benchmark', 'Task' if lib=='ParquetNet' else 'void',lib=='ParquetNet'))
            clean='        BenchmarkFixtures.ValidateOutput(_expectedOutputBytes, BenchmarkFixtures.OutputLength(_output));\n'
            if lib=='ParquetSharp':clean+='        _writer?.Dispose();\n        _managedOutput?.Dispose();\n'
            clean+='        _output?.Dispose();'
            out.append(emit_method('CleanupWrite',clean,'IterationCleanup(Target = nameof(Write))'))
        if hasread:
            if lib=='Plank':
                setup=f'''        _pool = new DefaultParquetBufferPool(ParquetBufferRetentionPolicy.ZeroAllocation);
        _source = new MemoryReadSource(BenchmarkFixtures.LoadReadFile("{stem}"));
        _reader = new Plank.Reading.Logical.ParquetReader(new Plank.Reading.Logical.ParquetReaderOptions {{ BufferPool = _pool }});'''
                iteration='        _reader.Reset(_source);'
            elif lib=='ParquetSharp':
                setup=body(src,'GlobalSetupRead')
                iteration='        _reader?.Dispose();\n        _reader = new ParquetFileReader(_source);'
            else:
                setup=f'        _file = BenchmarkFixtures.LoadReadFile("{stem}");'
                iteration='        _stream?.Dispose();\n        _stream = new MemoryStream(_file, writable: false);'
            out.append(emit_method('GlobalSetupRead',setup,'GlobalSetup(Target = nameof(Read))'))
            out.append(emit_method('SetupRead',iteration,'IterationSetup(Target = nameof(Read))'))
            original=body(src,'Read'); sumtype=re.search(r'(ulong|double|long) sum = 0;',original)[1]
            sums=re.findall(r'sum \+= ([^;]+);',original); assert len(sums)==width,(path,lib,len(sums),width)
            read=f'        {sumtype} sum = 0;\n        long count = 0;\n'
            if lib=='Plank':read+='        foreach (var group in _reader.RowGroups)\n        {\n'
            elif lib=='ParquetSharp':read+='        for (var g = 0; g < _reader.FileMetaData.NumRowGroups; g++)\n        {\n            using var group = _reader.RowGroup(g);\n'
            else:read+='        await using var reader = await Parquet.ParquetReader.CreateAsync(_stream);\n        var fields = reader.Schema.GetDataFields();\n        for (var g = 0; g < reader.RowGroupCount; g++)\n        {\n            using var group = reader.OpenRowGroupReader(g);\n'
            for i,(_,typ,prop) in enumerate(props):
                expr=sums[i].replace('row.'+prop,'value')
                numeric = typ.rstrip('?') in {'bool', 'int', 'long', 'double', 'DateTime'}
                if numeric:
                    key = (typ, sumtype)
                    assert key not in kernels or kernels[key] == expr, (key, expr)
                    kernels[key] = expr
                plank_consume = 'sum = ColumnChecksum.Accumulate(buffer.Values, sum);' if numeric else f'foreach (var value in buffer.Values) sum += {expr};'
                sharp_consume = f'sum = ColumnChecksum.Accumulate(_read{i}.AsSpan(0, length), sum);' if numeric else f'for (var index = 0; index < length; index++)\n                    {{\n                        var value = _read{i}[index];\n                        sum += {expr};\n                    }}'

                if lib=='Plank':
                    if 'Memory<byte>' in typ:
                        read+=f'            foreach (var buffer in group.Column<byte>({i}))\n            {{\n                for (var index = 0; index < buffer.Count; index++)\n                    sum += ({sumtype})(buffer.IsNull(index) ? 0 : buffer.GetValue(index).Length);\n                count += buffer.Count;\n            }}\n'
                    else:read+=f'            foreach (var buffer in group.Column<{typ}>({i}))\n            {{\n                {plank_consume}\n                count += buffer.Count;\n            }}\n'
                elif lib=='ParquetSharp':
                    read+=f'            using (var column = group.Column({i}).LogicalReader<{typ}>())\n            {{\n                while (column.HasNext)\n                {{\n                    var length = column.ReadBatch(_read{i});\n                    {sharp_consume}\n                    count += length;\n                }}\n            }}\n'
                else:
                    readtype = 'string?' if typ == 'string' else typ
                    if typ == 'string': expr = expr.replace('value', 'value!')
                    read+=f'            var column{i} = new {readtype}[checked((int)group.RowCount)];\n'
                    generic='' if typ.startswith('string') else '<'+typ.rstrip('?')+'>'
                    net_consume = f'sum = ColumnChecksum.Accumulate(column{i}.AsSpan(), sum);' if numeric else f'foreach (var value in column{i}) sum += {expr};'
                    read+=f'            await group.ReadAsync{generic}(fields[{i}], column{i}.AsMemory());\n            {net_consume}\n            count += column{i}.Length;\n'

            read+=f'        }}\n        if (count != (long)Rows * {width}) throw new InvalidDataException($"Expected {{(long)Rows * {width}}} values, got {{count}}.");\n        return sum;'
            # Keep the complete value check available to tests, outside timed work.
            out.append(emit_method('VerifyRead',read,None,f'Task<{sumtype}>' if lib=='ParquetNet' else sumtype,lib=='ParquetNet'))
            consumed = read.replace(f'        {sumtype} sum = 0;\n', '')
            consumed = re.sub(r'sum = ColumnChecksum.Accumulate\((.*), sum\);',
                              r'ReadConsumption.Consume(\1);', consumed)
            consumed = re.sub(r'foreach \(var value in buffer.Values\) sum \+= [^;]+;',
                              'ReadConsumption.Consume(buffer.Values);', consumed)
            consumed = re.sub(r'for \(var index = 0; index < buffer.Count; index\+\+\)\s+sum \+= [^;]+;',
                              'ReadConsumption.Consume(buffer.Values);', consumed)
            consumed = re.sub(r'for \(var index = 0; index < length; index\+\+\)\s*\{\s*var value = _read(\d+)\[index\];\s*sum \+= [^;]+;\s*\}',
                              r'ReadConsumption.Consume(_read\1.AsSpan(0, length));', consumed)
            consumed = re.sub(r'foreach \(var value in column(\d+)\) sum \+= [^;]+;',
                              r'ReadConsumption.Consume(column\1.AsSpan());', consumed)
            consumed = consumed.replace('return sum;', 'return count;')
            assert not re.search(r'\bsum\b', consumed), (stem, lib)
            assert consumed.count('ReadConsumption.Consume(') == width, (stem, lib)
            out.append(emit_method('Read',consumed,'Benchmark','Task<long>' if lib=='ParquetNet' else 'long',lib=='ParquetNet'))
        clean={'Plank':'        _writer?.Dispose();\n        _reader?.Dispose();\n        _source?.Dispose();\n        _pool?.Dispose();', 'ParquetSharp':'        _reader?.Dispose();\n        _source?.Dispose();\n        _buffer?.Dispose();\n        if (_pinned.IsAllocated) _pinned.Free();\n        _properties?.Dispose();', 'ParquetNet':'        _stream?.Dispose();'}[lib]
        out.append(emit_method('Cleanup',clean+'\n        _output?.Dispose();','GlobalCleanup'))
        out.append('}\n')
    generated=''.join(out)
    # Read-only adapters have no input column arrays or output buffers.
    for match in list(re.finditer(r'public class (\w+)\n\{', generated))[::-1]:
        start=match.start(); end=generated.find('\n[MemoryDiagnoser]',start)
        if end<0: end=len(generated)
        block=generated[start:end]
        if 'public async Task Write()' not in block and 'public void Write()' not in block:
            block=re.sub(r'^    (?:\w+(?:<[^>]+>)?\??\[\]|MemoryStream|byte\[\]|long|ParquetOptions|Parquet.Schema.ParquetSchema) (_rows|_output|_outputBuffer|_expectedOutputBytes|_c\d+|_options|_schema)[^\n]*\n','',block,flags=re.M)
            block=block.replace('        _output?.Dispose();\n','')
            generated=generated[:start]+block+generated[end:]
    generated = '\n'.join(line.rstrip() for line in generated.splitlines()) + '\n'
    (root/(stem+'Column.cs')).write_text(generated)
    multi = generate_multi_file(stem, generated, props, width)
    if multi:
        (root/(stem+'ColumnMulti.cs')).write_text('\n'.join(line.rstrip() for line in multi.splitlines()) + '\n')

# Untimed correctness kernels. Passing the accumulator preserves floating-point addition order across buffer boundaries.
helper = ['using System.Runtime.CompilerServices;\n\nnamespace Plank.Benchmarks;\n\n',
          '// Generated by scripts/generate_column_cases.py. Used only by untimed VerifyRead checks.\n',
          'static class ColumnChecksum\n{\n']
for (typ, sumtype), expr in sorted(kernels.items()):
    helper.append(f'    [MethodImpl(MethodImplOptions.NoInlining)]\n    internal static {sumtype} Accumulate(ReadOnlySpan<{typ}> values, {sumtype} sum)\n    {{\n        foreach (var value in values) sum += {expr};\n        return sum;\n    }}\n\n')
helper.append('}\n')
(root.parent / 'ColumnChecksum.cs').write_text(''.join(helper))
