"""Small, dependency-free reader for the Thrift Compact Protocol.

Parquet stores its footer, page headers, and page indexes in this format.  The
validator deliberately carries a read-only decoder instead of using Plank's
reader, so structural validation remains independent from the code under
research.  Compact Protocol values are self-describing; the Parquet field
numbers are interpreted by :mod:`validate`.
"""

from __future__ import annotations

import struct
from typing import Any


class CompactThriftError(ValueError):
    """The input is not a well-formed Compact Protocol value."""


STOP = 0
BOOLEAN_TRUE = 1
BOOLEAN_FALSE = 2
BYTE = 3
I16 = 4
I32 = 5
I64 = 6
DOUBLE = 7
BINARY = 8
LIST = 9
SET = 10
MAP = 11
STRUCT = 12


class CompactReader:
    """Decode one Compact Protocol value from an in-memory byte buffer."""

    def __init__(self, data: bytes | bytearray | memoryview, *, max_items: int = 10_000_000):
        self._data = memoryview(data)
        self.position = 0
        self._max_items = max_items

    @property
    def remaining(self) -> int:
        return len(self._data) - self.position

    def _take(self, count: int) -> memoryview:
        if count < 0 or count > self.remaining:
            raise CompactThriftError("truncated Compact Protocol value")
        start = self.position
        self.position += count
        return self._data[start : start + count]

    def _byte(self) -> int:
        return self._take(1)[0]

    def _uvarint(self) -> int:
        value = 0
        for shift in range(0, 70, 7):
            current = self._byte()
            value |= (current & 0x7F) << shift
            if not current & 0x80:
                return value
        raise CompactThriftError("Compact Protocol varint is too long")

    @staticmethod
    def _zigzag(value: int) -> int:
        return (value >> 1) ^ -(value & 1)

    def read_struct(self) -> dict[int, Any]:
        fields: dict[int, Any] = {}
        previous_field_id = 0
        while True:
            header = self._byte()
            if header == STOP:
                return fields

            compact_type = header & 0x0F
            delta = header >> 4
            if delta:
                field_id = previous_field_id + delta
            else:
                field_id = self._zigzag(self._uvarint())
            if field_id <= 0:
                raise CompactThriftError(f"invalid field id {field_id}")
            if field_id in fields:
                raise CompactThriftError(f"duplicate field id {field_id}")
            previous_field_id = field_id

            inline_bool: bool | None = None
            if compact_type == BOOLEAN_TRUE:
                inline_bool = True
            elif compact_type == BOOLEAN_FALSE:
                inline_bool = False
            fields[field_id] = self.read_value(compact_type, inline_bool=inline_bool)

    def read_struct_with_spans(self) -> tuple[dict[int, Any], list[tuple[int, int, int]]]:
        """Decode a struct and retain each top-level field's byte span."""
        fields: dict[int, Any] = {}
        spans: list[tuple[int, int, int]] = []
        previous_field_id = 0
        while True:
            start = self.position
            header = self._byte()
            if header == STOP:
                return fields, spans
            compact_type = header & 0x0F
            delta = header >> 4
            field_id = previous_field_id + delta if delta else self._zigzag(self._uvarint())
            if field_id <= 0:
                raise CompactThriftError(f"invalid field id {field_id}")
            if field_id in fields:
                raise CompactThriftError(f"duplicate field id {field_id}")
            previous_field_id = field_id
            inline_bool: bool | None = None
            if compact_type == BOOLEAN_TRUE:
                inline_bool = True
            elif compact_type == BOOLEAN_FALSE:
                inline_bool = False
            fields[field_id] = self.read_value(compact_type, inline_bool=inline_bool)
            spans.append((field_id, start, self.position))

    def read_value(self, compact_type: int, *, inline_bool: bool | None = None) -> Any:
        if compact_type in (BOOLEAN_TRUE, BOOLEAN_FALSE):
            if inline_bool is not None:
                return inline_bool
            encoded = self._byte()
            if encoded == BOOLEAN_TRUE:
                return True
            if encoded == BOOLEAN_FALSE:
                return False
            raise CompactThriftError(f"invalid boolean value {encoded}")
        if compact_type == BYTE:
            return struct.unpack("b", self._take(1))[0]
        if compact_type in (I16, I32, I64):
            return self._zigzag(self._uvarint())
        if compact_type == DOUBLE:
            return struct.unpack("<d", self._take(8))[0]
        if compact_type == BINARY:
            length = self._uvarint()
            return bytes(self._take(length))
        if compact_type in (LIST, SET):
            header = self._byte()
            count = header >> 4
            element_type = header & 0x0F
            if count == 15:
                count = self._uvarint()
            self._check_collection_size(count)
            return [self.read_value(element_type) for _ in range(count)]
        if compact_type == MAP:
            count = self._uvarint()
            self._check_collection_size(count)
            if count == 0:
                return []
            types = self._byte()
            key_type = types >> 4
            value_type = types & 0x0F
            return [
                (self.read_value(key_type), self.read_value(value_type))
                for _ in range(count)
            ]
        if compact_type == STRUCT:
            return self.read_struct()
        raise CompactThriftError(f"unknown Compact Protocol type {compact_type}")

    def _check_collection_size(self, count: int) -> None:
        if count < 0 or count > self._max_items:
            raise CompactThriftError(f"unreasonable collection size {count}")


def read_struct(data: bytes | bytearray | memoryview, *, require_eof: bool = True) -> tuple[dict[int, Any], int]:
    """Read a Compact Protocol struct and return it with its encoded length."""

    reader = CompactReader(data)
    result = reader.read_struct()
    if require_eof and reader.remaining:
        raise CompactThriftError(f"{reader.remaining} trailing bytes after struct")
    return result, reader.position


def read_struct_with_spans(
    data: bytes | bytearray | memoryview, *, require_eof: bool = True,
) -> tuple[dict[int, Any], list[tuple[int, int, int]], int]:
    """Read one struct and return its ordered top-level field byte spans."""
    reader = CompactReader(data)
    result, spans = reader.read_struct_with_spans()
    if require_eof and reader.remaining:
        raise CompactThriftError(f"{reader.remaining} trailing bytes after struct")
    return result, spans, reader.position
