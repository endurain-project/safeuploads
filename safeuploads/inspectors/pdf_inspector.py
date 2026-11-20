"""PDF inspector for active content, encryption and stream bombs.

Parses the syntax of a PDF without rendering it. The whole file is
tokenized, so names in objects that no cross-reference entry lists
are checked too, and the structure readers rely on is verified so
that no reader can parse an object the scan did not see: every
cross-reference entry must point at a parsed object, every stream
``/Length`` must end where the scan found ``endstream``, and every
object stream offset must start one of its parsed objects. Anything
that does not verify is rejected instead of being repaired.
"""

from __future__ import annotations

import base64
import itertools
import logging
import re
import zlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn, TypeAlias

from ..audit import get_correlation_id, log_extra
from ..exceptions import ErrorCode, PdfSecurityError
from ..utils import bytes_to_mb, check_resource_limits
from .base import BaseInspector

if TYPE_CHECKING:
    from ..config import FileSecurityConfig
    from ..protocols import SeekableFile


logger = logging.getLogger(__name__)

# PDF whitespace, and the pattern of a regular character: one that
# is neither whitespace nor a delimiter
_WHITESPACE = b"\x00\t\n\x0c\r "
_REGULAR = rb"[^\x00\t\n\x0c\r ()<>\[\]{}/%]"
_SEPARATORS = frozenset(b"\x00\t\n\x0c\r ()<>[]{}/%")

# One token after any whitespace and comments. The token group is
# optional, so a match with no group is the end of the region or a
# character no token starts with.
_TOKEN = re.compile(
    rb"(?:[\x00\t\n\x0c\r ]+|%[^\r\n]*)*(?:"
    rb"(?P<name>/" + _REGULAR + rb"*)"
    rb"|(?P<number>[+-]?(?:\d+\.?\d*|\.\d+)(?!" + _REGULAR + rb"))"
    rb"|(?P<dict_open><<)"
    rb"|(?P<dict_close>>>)"
    rb"|(?P<hex_string><[0-9A-Fa-f\x00\t\n\x0c\r ]*>)"
    rb"|(?P<string>\()"
    rb"|(?P<array_open>\[)"
    rb"|(?P<array_close>\])"
    rb"|(?P<keyword>" + _REGULAR + rb"+)"
    rb")?"
)
_STRING_PART = re.compile(rb"\\.|[()]", re.DOTALL)
_NAME_ESCAPES = re.compile(rb"(?:[^#]|#[0-9A-Fa-f]{2})*")
_NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_NON_WHITESPACE = re.compile(rb"[^\x00\t\n\x0c\r ]")
_HEADER = re.compile(rb"%PDF-[12]\.\d")
_TAIL = re.compile(rb"[\x00\t\n\x0c\r ]*%%EOF[\x00\t\n\x0c\r ]*\Z")

_OBJECT_END = frozenset({b"endobj", b"stream"})
_NO_KEYWORDS: frozenset[bytes] = frozenset()

# Filters by their full and abbreviated names; readers accept both
# in stream dictionaries.
_FLATE = frozenset({b"FlateDecode", b"Fl"})
_ASCII_HEX = frozenset({b"ASCIIHexDecode", b"AHx"})
_ASCII_85 = frozenset({b"ASCII85Decode", b"A85"})
# Image codecs decode to pixels, never to PDF objects, so their data
# is not decoded here.
_IMAGE_FILTERS = frozenset(
    {
        b"DCTDecode",
        b"DCT",
        b"JPXDecode",
        b"JBIG2Decode",
        b"CCITTFaxDecode",
        b"CCF",
    }
)
# Stream dictionary entries that make readers load the data from
# another file
_EXTERNAL_STREAM_KEYS = (b"F", b"FFilter", b"FDecodeParms")


@dataclass(frozen=True, slots=True)
class _Name:
    """A PDF name with its ``#xx`` escapes decoded."""

    value: bytes


@dataclass(frozen=True, slots=True)
class _Ref:
    """An indirect reference ``num gen R``."""

    num: int
    gen: int


class _String:
    """A literal or hex string; its contents are never needed."""


_STRING = _String()


class _Dict(dict[bytes, "_Value"]):
    """
    A dictionary keyed by decoded key names.

    Attributes:
        conflicting: Whether a key appeared twice with different
            values; the last value is kept.
    """

    conflicting = False


_Value: TypeAlias = (
    "int | float | bool | _Name | _Ref | _String | list[_Value] | _Dict | None"
)
# A token: keywords are returned as bytes, delimiters as None
_Token: TypeAlias = tuple[str, "_Value | bytes", int]


@dataclass(slots=True)
class _Stream:
    """
    A stream found by the scan.

    Attributes:
        entries: Stream dictionary.
        start: Offset of the first data byte.
        end: Offset of the ``endstream`` keyword.
        decoded: Whether the data was decoded already.
    """

    entries: _Dict
    start: int
    end: int
    decoded: bool = False


@dataclass(slots=True)
class _Object:
    """
    A top-level ``num gen obj ... endobj`` object.

    Attributes:
        num: Object number.
        gen: Generation number.
        value: Object value; the dictionary for a stream.
        stream: The stream, for a stream object.
        members: Numbers and values of the objects it holds, for an
            object stream.
    """

    num: int
    gen: int
    value: _Value
    stream: _Stream | None
    members: list[tuple[int, _Value]] | None = None


@dataclass(frozen=True, slots=True)
class _Entry:
    """
    An in-use cross-reference entry.

    Attributes:
        num: Object number.
        kind: 1 for an object at a file offset, 2 for an object in
            an object stream.
        field2: File offset (kind 1) or object stream number
            (kind 2).
        field3: Generation (kind 1) or index in the object stream
            (kind 2).
    """

    num: int
    kind: int
    field2: int
    field3: int


def _name(value: _Value | None) -> bytes | None:
    """Return the bytes of a name value, or None for other values."""
    return value.value if isinstance(value, _Name) else None


class _Lexer:
    """Tokenizer over one region of PDF bytes."""

    def __init__(
        self, document: _Document, data: bytes, pos: int, end: int
    ) -> None:
        """
        Start tokenizing ``data[pos:end]``.

        Args:
            document: Document whose names are checked.
            data: Bytes holding the region.
            pos: Start of the region.
            end: End of the region.
        """
        self._document = document
        self.data = data
        self.pos = pos
        self.end = end

    def next(self) -> _Token:
        """
        Read the next token.

        Returns:
            The token kind, its value and its start offset. The kind
            is a group name of ``_TOKEN`` or ``"eof"``.

        Raises:
            PdfSecurityError: The bytes do not start a valid token,
                or a name is blocked or marks encryption.
        """
        self._document.count_token()
        match = _TOKEN.match(self.data, self.pos, self.end)
        if match is None or match.lastgroup is None:
            if match is not None and match.end() == self.end:
                self.pos = self.end
                return "eof", None, self.end
            self._document.fail("PDF contains an invalid character")
        kind = match.lastgroup
        start = match.start(kind)
        self.pos = match.end()
        text = match.group(kind)
        if kind == "name":
            return kind, self._document.name(text[1:]), start
        if kind == "number":
            return kind, self._number(text), start
        if kind == "string":
            self.pos = self._string_end(self.pos)
            return kind, _STRING, start
        if kind == "hex_string":
            return kind, _STRING, start
        if kind == "keyword":
            return kind, text, start
        return kind, None, start

    def _number(self, text: bytes) -> int | float:
        """
        Convert a number token.

        Args:
            text: Token bytes.

        Returns:
            The integer or real value.

        Raises:
            PdfSecurityError: The integer is too long to convert.
        """
        if b"." in text:
            return float(text)
        try:
            return int(text)
        except ValueError as err:
            raise self._document.error(
                "PDF contains an invalid number"
            ) from err

    def _string_end(self, pos: int) -> int:
        """
        Find the end of a literal string.

        Args:
            pos: Offset just after the opening parenthesis.

        Returns:
            Offset just after the closing parenthesis.

        Raises:
            PdfSecurityError: The string is not closed in the region.
        """
        depth = 1
        while True:
            match = _STRING_PART.search(self.data, pos, self.end)
            if match is None:
                self._document.fail("PDF contains an unterminated string")
            pos = match.end()
            part = match.group()
            if part == b"(":
                depth += 1
            elif part == b")":
                depth -= 1
                if depth == 0:
                    return pos


class _Document:
    """State of one PDF inspection."""

    def __init__(
        self,
        config: FileSecurityConfig,
        data: bytes,
        filename: str | None,
    ) -> None:
        """
        Prepare the inspection of ``data``.

        Args:
            config: Configuration with the limits and blocked names.
            data: The whole PDF.
            filename: Sanitized filename for error context.
        """
        self.data = data
        self.filename = filename
        self.limits = config.limits
        self.blocked = frozenset(
            name.encode("ascii") for name in config.BLOCKED_PDF_NAMES
        )
        self.objects: dict[int, _Object] = {}
        self.streams: list[_Stream] = []
        self.xref_tables: dict[int, tuple[list[_Entry], _Dict]] = {}
        self.xref: dict[int, _Entry] = {}
        self.compressed: list[_Entry] = []
        self.startxref = 0
        self.decoded = 0
        self.tokens = 0

    def error(
        self,
        message: str,
        code: ErrorCode = ErrorCode.PDF_INVALID_STRUCTURE,
    ) -> PdfSecurityError:
        """
        Build the error for a rejected document.

        Args:
            message: Description safe to show to the client.
            code: Error code of the rejection.

        Returns:
            The error, carrying the filename.
        """
        return PdfSecurityError(
            message, filename=self.filename, error_code=code
        )

    def fail(
        self,
        message: str,
        code: ErrorCode = ErrorCode.PDF_INVALID_STRUCTURE,
    ) -> NoReturn:
        """
        Reject the document.

        Args:
            message: Description safe to show to the client.
            code: Error code of the rejection.

        Raises:
            PdfSecurityError: Always.
        """
        raise self.error(message, code)

    def count_token(self) -> None:
        """
        Count a token and enforce the resource limits periodically.

        Raises:
            ResourceLimitError: The active monitor's time or memory
                limit is exceeded.
        """
        self.tokens += 1
        if self.tokens % 1024 == 0:
            check_resource_limits()

    def name(self, raw: bytes) -> _Name:
        """
        Decode a name and reject a blocked one.

        Args:
            raw: Name bytes without the leading ``/``.

        Returns:
            The decoded name.

        Raises:
            PdfSecurityError: The name has an invalid escape, is
                blocked, or is ``/Encrypt``.
        """
        if b"#" in raw:
            if not _NAME_ESCAPES.fullmatch(raw):
                self.fail("PDF contains an invalid name escape")
            raw = _NAME_ESCAPE.sub(
                lambda match: bytes([int(match.group(1), 16)]), raw
            )
        if raw in self.blocked:
            self.fail(
                f"PDF contains blocked feature /{raw.decode('ascii')}",
                ErrorCode.PDF_ACTIVE_CONTENT,
            )
        if raw == b"Encrypt":
            self.fail(
                "Encrypted PDF documents cannot be inspected",
                ErrorCode.PDF_ENCRYPTED,
            )
        return _Name(raw)

    def inspect(self) -> None:
        """
        Run every check on the document.

        Raises:
            PdfSecurityError: The document is rejected.
            ResourceLimitError: A resource limit is exceeded.
        """
        if not _HEADER.match(self.data):
            self.fail("PDF header is missing or has an invalid version")
        self._scan()
        self._read_xref_chain()
        self._read_object_streams()
        self._check_lengths()
        # Bound what readers decompress from the remaining streams
        for stream in self.streams:
            if not stream.decoded:
                self._decode(stream, keep=False)

    # -- Syntax ---------------------------------------------------------

    def _parse(
        self,
        lexer: _Lexer,
        terminators: frozenset[bytes],
        *,
        single: bool = False,
    ) -> tuple[list[_Value], bytes | None]:
        """
        Parse values until a terminating keyword or the region end.

        Arrays and dictionaries are built with an explicit stack, so
        nesting depth costs memory only, and ``num gen R`` is folded
        into a reference.

        Args:
            lexer: Lexer positioned at the first value.
            terminators: Keywords that end the sequence outside any
                array or dictionary.
            single: Stop after the first complete value.

        Returns:
            The values and the terminating keyword, or None when the
            region ended (or ``single`` stopped the parse).

        Raises:
            PdfSecurityError: The syntax is invalid.
        """
        root: list[_Value] = []
        stack: list[list[_Value]] = [root]
        closers: list[str] = []
        while True:
            kind, value, _ = lexer.next()
            items = stack[-1]
            if kind == "eof":
                if closers:
                    self.fail(
                        "PDF contains an unterminated array or dictionary"
                    )
                return root, None
            if kind in ("array_open", "dict_open"):
                stack.append([])
                closers.append(
                    "array_close" if kind == "array_open" else "dict_close"
                )
                continue
            if kind in ("array_close", "dict_close"):
                if not closers or closers.pop() != kind:
                    self.fail("PDF contains an unbalanced array or dictionary")
                stack.pop()
                stack[-1].append(
                    items if kind == "array_close" else self._dictionary(items)
                )
            elif isinstance(value, bytes):
                if value == b"R":
                    self._fold_reference(items)
                elif value in (b"true", b"false"):
                    items.append(value == b"true")
                elif value == b"null":
                    items.append(None)
                elif not closers and value in terminators:
                    return root, value
                else:
                    self.fail("PDF contains an unexpected keyword")
            else:
                items.append(value)
            if single and not closers:
                return root, None

    def _fold_reference(self, items: list[_Value]) -> None:
        """
        Replace the last two integers of ``items`` with a reference.

        Args:
            items: Values of the current array, dictionary or
                sequence.

        Raises:
            PdfSecurityError: The ``R`` keyword does not follow a
                valid object and generation number.
        """
        if len(items) < 2:
            self.fail("PDF contains an invalid reference")
        num, gen = items[-2], items[-1]
        if (
            type(num) is not int
            or type(gen) is not int
            or num < 1
            or not 0 <= gen <= 65535
        ):
            self.fail("PDF contains an invalid reference")
        del items[-2:]
        items.append(_Ref(num, gen))

    def _dictionary(self, items: list[_Value]) -> _Dict:
        """
        Build a dictionary from alternating keys and values.

        Args:
            items: Values between ``<<`` and ``>>``.

        Returns:
            The dictionary keyed by the decoded key names.

        Raises:
            PdfSecurityError: A key is missing its value or is not a
                name.
        """
        if len(items) % 2:
            self.fail("PDF contains a dictionary key without a value")
        result = _Dict()
        for key, value in zip(items[::2], items[1::2], strict=True):
            if not isinstance(key, _Name):
                self.fail("PDF contains a dictionary key that is not a name")
            # Readers disagree on which duplicate wins. Strings compare
            # equal, as no check reads their contents.
            if result.get(key.value, value) != value:
                result.conflicting = True
            result[key.value] = value
        return result

    def _ints(self, value: _Value, what: str) -> list[int]:
        """
        Return an array value whose items are all integers.

        Args:
            value: Value to check.
            what: Description of the value for the error message.

        Returns:
            The integers.

        Raises:
            PdfSecurityError: The value is not an array of integers.
        """
        if not isinstance(value, list):
            self.fail(f"PDF {what} is not an array of integers")
        result = [item for item in value if type(item) is int]
        if len(result) != len(value):
            self.fail(f"PDF {what} is not an array of integers")
        return result

    # -- File scan ------------------------------------------------------

    def _scan(self) -> None:
        """
        Tokenize the file and record its objects and xref tables.

        Raises:
            PdfSecurityError: The file has invalid syntax, a token
                outside any object, or does not end with
                ``startxref``, its offset and ``%%EOF``.
        """
        lexer = _Lexer(self, self.data, 0, len(self.data))
        startxref_end: int | None = None
        while True:
            kind, value, start = lexer.next()
            if kind == "eof":
                break
            startxref_end = None
            if type(value) is int:
                self._read_object(lexer, value, start)
            elif value == b"xref":
                self._read_xref_table(lexer, start)
            elif value == b"startxref":
                _, offset, _ = lexer.next()
                if type(offset) is not int:
                    self.fail("PDF startxref is not followed by an offset")
                self.startxref = offset
                startxref_end = lexer.pos
            else:
                self.fail("PDF contains data outside its objects")
        # Readers look for the last startxref near the end, so nothing
        # but %%EOF may follow it.
        if startxref_end is None or not _TAIL.match(self.data, startxref_end):
            self.fail("PDF does not end with startxref and %%EOF")

    def _read_object(self, lexer: _Lexer, num: int, offset: int) -> None:
        """
        Read one ``num gen obj ... endobj`` object.

        Args:
            lexer: Lexer positioned after the object number.
            num: Object number.
            offset: Offset of the object number.

        Raises:
            PdfSecurityError: The object is malformed.
        """
        _, gen, _ = lexer.next()
        _, keyword, _ = lexer.next()
        if type(gen) is not int or keyword != b"obj":
            self.fail("PDF contains an invalid object header")
        if num < 1 or not 0 <= gen <= 65535:
            self.fail("PDF contains an invalid object number")
        items, terminator = self._parse(lexer, _OBJECT_END)
        if terminator is None:
            self.fail("PDF contains an object without endobj")
        if len(items) != 1:
            self.fail("PDF object does not hold exactly one value")
        value = items[0]
        stream = None
        if terminator == b"stream":
            if not isinstance(value, _Dict):
                self.fail("PDF stream has no dictionary")
            stream = self._read_stream(lexer, value)
            _, keyword, _ = lexer.next()
            if keyword != b"endobj":
                self.fail("PDF contains an object without endobj")
        self.objects[offset] = _Object(num, gen, value, stream)

    def _read_stream(self, lexer: _Lexer, entries: _Dict) -> _Stream:
        """
        Find the data of a stream and move the lexer past it.

        The data ends at the first ``endstream``, whatever
        ``/Length`` says; ``_check_lengths`` later requires the two
        to agree.

        Args:
            lexer: Lexer positioned after the ``stream`` keyword.
            entries: Stream dictionary.

        Returns:
            The recorded stream.

        Raises:
            PdfSecurityError: The dictionary repeats a key with
                another value, the data is read from another file, or
                the stream is not framed by an end of line and
                ``endstream``.
        """
        # Its entries decide how the data is framed and decoded
        if entries.conflicting:
            self.fail("PDF stream dictionary repeats a key")
        if any(key in entries for key in _EXTERNAL_STREAM_KEYS):
            self.fail(
                "PDF stream data is read from an external file",
                ErrorCode.PDF_ACTIVE_CONTENT,
            )
        data = self.data
        start = lexer.pos
        if data.startswith(b"\r\n", start):
            start += 2
        elif data[start : start + 1] in (b"\n", b"\r"):
            start += 1
        else:
            self.fail("PDF stream keyword is not followed by an end of line")
        end = data.find(b"endstream", start)
        if end < 0:
            self.fail("PDF stream has no endstream")
        after = end + len(b"endstream")
        if after < len(data) and data[after] not in _SEPARATORS:
            self.fail("PDF stream has no endstream")
        lexer.pos = after
        stream = _Stream(entries, start, end)
        self.streams.append(stream)
        return stream

    def _read_xref_table(self, lexer: _Lexer, offset: int) -> None:
        """
        Read an xref table and its trailer dictionary.

        Args:
            lexer: Lexer positioned after the ``xref`` keyword.
            offset: Offset of the ``xref`` keyword.

        Raises:
            PdfSecurityError: The table or trailer is malformed, or
                the trailer repeats a key with another value.
        """
        entries: list[_Entry] = []
        while True:
            _, first, _ = lexer.next()
            if first == b"trailer":
                break
            _, count, _ = lexer.next()
            if (
                type(first) is not int
                or type(count) is not int
                or first < 0
                or count < 0
            ):
                self.fail("PDF xref table has an invalid subsection")
            for num in range(first, first + count):
                _, position, _ = lexer.next()
                _, gen, _ = lexer.next()
                _, flag, _ = lexer.next()
                if (
                    type(position) is not int
                    or type(gen) is not int
                    or flag not in (b"n", b"f")
                ):
                    self.fail("PDF xref table has an invalid entry")
                if flag == b"n":
                    entries.append(_Entry(num, 1, position, gen))
        items, _ = self._parse(lexer, _NO_KEYWORDS, single=True)
        if len(items) != 1 or not isinstance(items[0], _Dict):
            self.fail("PDF xref table has no trailer dictionary")
        if items[0].conflicting:
            self.fail("PDF trailer dictionary repeats a key")
        self.xref_tables[offset] = (entries, items[0])

    # -- Cross-reference ------------------------------------------------

    def _skip_whitespace(self, offset: int) -> int:
        """
        Return the first non-whitespace offset from ``offset``.

        Readers skip whitespace at a cross-reference offset, so an
        offset just before an object still points at it.

        Args:
            offset: Offset from a cross-reference section.

        Returns:
            The offset of the next non-whitespace byte, or the file
            length.

        Raises:
            PdfSecurityError: The offset is outside the file.
        """
        if not 0 <= offset <= len(self.data):
            self.fail("PDF cross-reference offset is outside the file")
        match = _NON_WHITESPACE.search(self.data, offset)
        return match.start() if match else len(self.data)

    def _object_at(self, offset: int, num: int, gen: int) -> _Object:
        """
        Return the parsed object a cross-reference offset points at.

        Args:
            offset: File offset from the entry.
            num: Object number the entry is for.
            gen: Generation the entry is for.

        Returns:
            The object.

        Raises:
            PdfSecurityError: No parsed object with that number and
                generation starts at the offset.
        """
        obj = self.objects.get(self._skip_whitespace(offset))
        if obj is None or obj.num != num or obj.gen != gen:
            self.fail("PDF cross-reference entry does not point to its object")
        return obj

    def _read_xref_chain(self) -> None:
        """
        Follow ``startxref``, ``/XRefStm`` and ``/Prev`` and verify.

        Each entry is recorded under its object number unless a
        newer section listed that number already, and every in-use
        file offset is verified.

        Raises:
            PdfSecurityError: A section is missing, malformed or
                visited twice, or an entry does not verify.
        """
        visited: set[int] = set()
        offset: int | None = self.startxref
        while offset is not None:
            trailer = self._read_xref_section(offset, visited, table=True)
            hybrid = trailer.get(b"XRefStm")
            if hybrid is not None:
                if type(hybrid) is not int:
                    self.fail("PDF trailer has an invalid /XRefStm")
                self._read_xref_section(hybrid, visited, table=False)
            prev = trailer.get(b"Prev")
            if prev is not None and type(prev) is not int:
                self.fail("PDF trailer has an invalid /Prev")
            offset = prev

    def _read_xref_section(
        self, offset: int, visited: set[int], *, table: bool
    ) -> _Dict:
        """
        Read and verify the cross-reference section at ``offset``.

        Args:
            offset: Offset of an xref table or xref stream object.
            visited: Offsets of the sections read so far.
            table: Whether an xref table is allowed at the offset.

        Returns:
            The trailer or xref stream dictionary.

        Raises:
            PdfSecurityError: No section starts at the offset, it was
                read before, or one of its entries does not verify.
        """
        pos = self._skip_whitespace(offset)
        if pos in visited:
            self.fail("PDF cross-reference sections form a loop")
        visited.add(pos)
        found = self.xref_tables.get(pos) if table else None
        if found is not None:
            entries, trailer = found
        else:
            obj = self.objects.get(pos)
            if (
                obj is None
                or obj.stream is None
                or _name(obj.stream.entries.get(b"Type")) != b"XRef"
            ):
                self.fail(
                    "PDF cross-reference offset does not point to an"
                    " xref section"
                )
            entries = self._xref_stream_entries(obj.stream)
            trailer = obj.stream.entries
        for entry in entries:
            self.xref.setdefault(entry.num, entry)
            if entry.kind == 1:
                self._object_at(entry.field2, entry.num, entry.field3)
            else:
                self.compressed.append(entry)
        return trailer

    def _xref_stream_entries(self, stream: _Stream) -> list[_Entry]:
        """
        Decode the in-use entries of an xref stream.

        Args:
            stream: The xref stream.

        Returns:
            Its in-use entries.

        Raises:
            PdfSecurityError: The dictionary or data is invalid.
        """
        entries = stream.entries
        widths = self._ints(entries.get(b"W"), "xref stream /W")
        size = entries.get(b"Size")
        if (
            len(widths) != 3
            or not all(0 <= width <= 8 for width in widths)
            or sum(widths) == 0
            or type(size) is not int
            or size < 0
        ):
            self.fail("PDF xref stream has an invalid /W or /Size")
        raw_index = entries.get(b"Index")
        index = (
            [0, size]
            if raw_index is None
            else self._ints(raw_index, "xref stream /Index")
        )
        if len(index) % 2 or any(value < 0 for value in index):
            self.fail("PDF xref stream has an invalid /Index")
        data = self._decode(stream, keep=True)
        row = sum(widths)
        if len(data) != sum(index[1::2]) * row:
            self.fail("PDF xref stream data does not match its /W and /Index")
        type_end = widths[0]
        field2_end = type_end + widths[1]
        result: list[_Entry] = []
        pos = 0
        for first, count in zip(index[::2], index[1::2], strict=True):
            for num in range(first, first + count):
                record = data[pos : pos + row]
                pos += row
                kind = int.from_bytes(record[:type_end]) if type_end else 1
                if kind == 0:
                    continue
                if kind not in (1, 2):
                    self.fail("PDF xref stream has an unknown entry type")
                result.append(
                    _Entry(
                        num,
                        kind,
                        int.from_bytes(record[type_end:field2_end]),
                        int.from_bytes(record[field2_end:]),
                    )
                )
        return result

    # -- Object streams -------------------------------------------------

    def _read_object_streams(self) -> None:
        """
        Parse every object stream and verify compressed entries.

        A stream is parsed when it is typed ``/ObjStm`` or when a
        compressed entry names its object number, since readers load
        the container by number.

        Raises:
            PdfSecurityError: An object stream is malformed or a
                compressed entry does not point to its object.
        """
        containers = {entry.field2 for entry in self.compressed}
        for obj in self.objects.values():
            if obj.stream is not None and (
                obj.num in containers
                or _name(obj.stream.entries.get(b"Type")) == b"ObjStm"
            ):
                obj.members = self._object_stream_members(obj.stream)
        for entry in self.compressed:
            self._compressed_value(entry)

    def _object_stream_members(
        self, stream: _Stream
    ) -> list[tuple[int, _Value]]:
        """
        Parse the objects of an object stream.

        Each object is parsed on its own from the offset the header
        gives, exactly as a reader does, and the bytes between the
        header and the first object must hold no token.

        Args:
            stream: The object stream.

        Returns:
            Object numbers and values in header order.

        Raises:
            PdfSecurityError: The dictionary, header or an object is
                invalid.
        """
        count = stream.entries.get(b"N")
        first = stream.entries.get(b"First")
        if (
            type(count) is not int
            or type(first) is not int
            or count < 0
            or first < 0
        ):
            self.fail("PDF object stream has an invalid /N or /First")
        data = self._decode(stream, keep=True)
        if first > len(data):
            self.fail("PDF object stream /First is past its data")
        lexer = _Lexer(self, data, 0, first)
        header: list[int] = []
        for _ in range(2 * count):
            _, value, _ = lexer.next()
            if type(value) is not int:
                self.fail("PDF object stream header is invalid")
            header.append(value)
        if lexer.next()[0] != "eof":
            self.fail("PDF object stream header is invalid")
        numbers = header[::2]
        starts = [first + offset for offset in header[1::2]]
        if any(num < 1 for num in numbers):
            self.fail("PDF contains an invalid object number")
        # Offsets must increase so the objects cannot overlap
        if starts and (
            starts[0] < first
            or starts[-1] > len(data)
            or any(b <= a for a, b in itertools.pairwise(starts))
        ):
            self.fail("PDF object stream offsets are invalid")
        gap_end = starts[0] if starts else len(data)
        if _Lexer(self, data, first, gap_end).next()[0] != "eof":
            self.fail("PDF object stream has data outside its objects")
        ends = [*starts[1:], len(data)]
        members: list[tuple[int, _Value]] = []
        for num, start, end in zip(numbers, starts, ends, strict=True):
            items, _ = self._parse(
                _Lexer(self, data, start, end), _NO_KEYWORDS
            )
            if len(items) != 1:
                self.fail(
                    "PDF compressed object does not hold exactly one value"
                )
            members.append((num, items[0]))
        return members

    def _compressed_value(self, entry: _Entry) -> _Value:
        """
        Return the value a compressed entry points at.

        Args:
            entry: Entry of kind 2.

        Returns:
            The value of the object in its object stream.

        Raises:
            PdfSecurityError: The object stream is not listed at a
                file offset, or does not hold the object at the
                entry's index.
        """
        container = self.xref.get(entry.field2)
        if container is None or container.kind != 1:
            self.fail("PDF object stream is missing from the cross-reference")
        members = self._object_at(
            container.field2, container.num, container.field3
        ).members
        if (
            members is None
            or entry.field3 >= len(members)
            or members[entry.field3][0] != entry.num
        ):
            self.fail("PDF cross-reference entry does not point to its object")
        return members[entry.field3][1]

    # -- Streams --------------------------------------------------------

    def _check_lengths(self) -> None:
        """
        Require every ``/Length`` to end the data at ``endstream``.

        Only whitespace may lie between the end ``/Length`` gives
        and ``endstream``, so readers that trust ``/Length`` and
        readers that look for ``endstream`` read the same data.

        Raises:
            PdfSecurityError: A length is missing, invalid, or does
                not match the data.
        """
        for stream in self.streams:
            length = self._direct(stream.entries.get(b"Length"))
            if (
                type(length) is not int
                or not 0 <= length <= stream.end - stream.start
                or self.data[stream.start + length : stream.end].strip(
                    _WHITESPACE
                )
            ):
                self.fail("PDF stream /Length does not match its data")

    def _direct(self, value: _Value) -> _Value:
        """
        Resolve a value that may be an indirect reference.

        Args:
            value: A value from a dictionary or array.

        Returns:
            The value, or the value of the object it refers to.

        Raises:
            PdfSecurityError: The reference does not resolve.
        """
        return self._resolve(value) if isinstance(value, _Ref) else value

    def _resolve(self, ref: _Ref) -> _Value:
        """
        Return the value an indirect reference points at.

        Args:
            ref: The reference.

        Returns:
            The value of the object, or a sentinel string for a
            stream object.

        Raises:
            PdfSecurityError: The object is not in the
                cross-reference or has another generation.
        """
        entry = self.xref.get(ref.num)
        if entry is None:
            self.fail("PDF refers to an object that does not exist")
        if entry.kind == 1:
            obj = self._object_at(entry.field2, entry.num, entry.field3)
            if obj.gen != ref.gen:
                self.fail("PDF refers to an object that does not exist")
            return _STRING if obj.stream is not None else obj.value
        if ref.gen != 0:
            self.fail("PDF refers to an object that does not exist")
        return self._compressed_value(entry)

    def _filters(self, stream: _Stream) -> list[tuple[bytes, _Dict | None]]:
        """
        Return the filters of a stream with their parameters.

        Args:
            stream: The stream.

        Returns:
            Filter names in decoding order, each with its
            ``/DecodeParms`` dictionary or None.

        Raises:
            PdfSecurityError: ``/Filter`` or ``/DecodeParms`` is not
                a name, dictionary or array of matching length, an
                indirect reference in them does not resolve, or a
                parameter dictionary repeats a key with another
                value.
        """
        raw_filters = self._direct(stream.entries.get(b"Filter"))
        if raw_filters is None:
            names: list[bytes] = []
        elif isinstance(raw_filters, _Name):
            names = [raw_filters.value]
        elif isinstance(raw_filters, list):
            resolved = [self._direct(item) for item in raw_filters]
            names = [
                item.value for item in resolved if isinstance(item, _Name)
            ]
            if len(names) != len(raw_filters):
                self.fail("PDF stream has an invalid /Filter")
        else:
            self.fail("PDF stream has an invalid /Filter")
        raw_parms = self._direct(stream.entries.get(b"DecodeParms"))
        parms: list[_Dict | None]
        if raw_parms is None:
            parms = [None] * len(names)
        elif isinstance(raw_parms, _Dict) and len(names) == 1:
            parms = [raw_parms]
        elif isinstance(raw_parms, list) and len(raw_parms) == len(names):
            parms = [
                item
                for item in map(self._direct, raw_parms)
                if item is None or isinstance(item, _Dict)
            ]
            if len(parms) != len(raw_parms):
                self.fail("PDF stream has an invalid /DecodeParms")
        else:
            self.fail("PDF stream has an invalid /DecodeParms")
        if any(item is not None and item.conflicting for item in parms):
            self.fail("PDF stream /DecodeParms repeats a key")
        return list(zip(names, parms, strict=True))

    def _decode(self, stream: _Stream, *, keep: bool) -> bytes:
        """
        Decode a stream, counting the inflated bytes.

        Args:
            stream: The stream.
            keep: Return the decoded data; otherwise the last Flate
                stage is only counted. Kept data cannot end in an
                image codec.

        Returns:
            The decoded data, or ``b""`` when it is not kept or ends
            in an image codec.

        Raises:
            PdfSecurityError: A filter is unsupported or cannot
                decode its input, an image codec is not the last
                filter or is applied to kept data, or the decoded
                size exceeds the limits.
        """
        stream.decoded = True
        # A direct /Length excludes the end of line before endstream;
        # an indirect one may not be resolvable yet, and the trailing
        # whitespace it would exclude is checked by _check_lengths.
        end = stream.end
        length = stream.entries.get(b"Length")
        if type(length) is int and 0 <= length <= end - stream.start:
            end = stream.start + length
        data = self.data[stream.start : end]
        filters = self._filters(stream)
        for index, (name, parms) in enumerate(filters):
            needed = keep or index < len(filters) - 1
            if name in _IMAGE_FILTERS:
                if needed:
                    self.fail("PDF stream applies an image codec too early")
                return b""
            if name in _FLATE:
                data = self._inflate(data, keep=needed)
                if needed:
                    data = self._unpredict(data, parms)
            elif name in _ASCII_HEX:
                data = self._ascii_hex(data)
            elif name in _ASCII_85:
                data = self._ascii_85(data)
            else:
                self.fail("PDF stream uses an unsupported filter")
        return data

    def _count_decoded(self, size: int) -> None:
        """
        Add inflated bytes to the total and enforce the limits.

        Args:
            size: Bytes just inflated.

        Raises:
            PdfSecurityError: The total exceeds
                ``max_pdf_uncompressed_size`` or
                ``max_compression_ratio`` times the file size.
        """
        self.decoded += size
        limit = self.limits.max_pdf_uncompressed_size
        if self.decoded > limit:
            self.fail(
                f"PDF streams decompress to more than {bytes_to_mb(limit)}MB",
                ErrorCode.PDF_STREAM_BOMB,
            )
        ratio = self.limits.max_compression_ratio
        if self.decoded > ratio * len(self.data):
            self.fail(
                f"PDF streams decompress to more than {ratio} times"
                " the file size",
                ErrorCode.PDF_STREAM_BOMB,
            )

    def _inflate(self, data: bytes, *, keep: bool) -> bytes:
        """
        Inflate zlib data in bounded steps.

        A stream that ends before its end marker yields what it
        holds, as readers do.

        Args:
            data: Compressed data.
            keep: Return the output; otherwise only count it.

        Returns:
            The inflated data, or ``b""`` when not kept.

        Raises:
            PdfSecurityError: The data is not valid zlib data, or
                the decoded size exceeds the limits.
            ResourceLimitError: A resource limit is exceeded.
        """
        decompressor = zlib.decompressobj()
        output = bytearray()
        chunk_size = self.limits.chunk_size
        pending = data
        try:
            while True:
                check_resource_limits()
                piece = decompressor.decompress(pending, chunk_size)
                self._count_decoded(len(piece))
                if keep:
                    output += piece
                pending = decompressor.unconsumed_tail
                if decompressor.eof or not (piece or pending):
                    return bytes(output)
        except zlib.error as err:
            raise self.error(
                "PDF contains an undecodable Flate stream"
            ) from err

    def _ascii_hex(self, data: bytes) -> bytes:
        """
        Decode ASCIIHexDecode data up to its ``>`` end marker.

        Args:
            data: Encoded data.

        Returns:
            The decoded bytes.

        Raises:
            PdfSecurityError: The data holds a non-hex character.
        """
        digits = data.translate(None, _WHITESPACE).split(b">", 1)[0]
        if len(digits) % 2:
            digits += b"0"
        try:
            return bytes.fromhex(digits.decode("ascii"))
        except ValueError as err:
            raise self.error(
                "PDF contains an undecodable ASCIIHex stream"
            ) from err

    def _ascii_85(self, data: bytes) -> bytes:
        """
        Decode ASCII85Decode data up to its ``~>`` end marker.

        Args:
            data: Encoded data.

        Returns:
            The decoded bytes.

        Raises:
            PdfSecurityError: The data is not valid ASCII85.
        """
        digits = data.translate(None, _WHITESPACE).split(b"~>", 1)[0]
        try:
            return base64.a85decode(digits)
        except ValueError as err:
            raise self.error(
                "PDF contains an undecodable ASCII85 stream"
            ) from err

    def _unpredict(self, data: bytes, parms: _Dict | None) -> bytes:
        """
        Undo a PNG predictor given by Flate decode parameters.

        Args:
            data: Inflated data.
            parms: The filter's ``/DecodeParms``, or None.

        Returns:
            The data without the predictor.

        Raises:
            PdfSecurityError: The predictor is not None or PNG, its
                parameters are invalid, or the rows do not fit the
                data.
        """
        if parms is None:
            return data
        predictor = parms.get(b"Predictor", 1)
        if predictor == 1 and type(predictor) is int:
            return data
        if type(predictor) is not int or not 10 <= predictor <= 15:
            self.fail("PDF stream uses an unsupported predictor")
        colors = parms.get(b"Colors", 1)
        bits = parms.get(b"BitsPerComponent", 8)
        columns = parms.get(b"Columns", 1)
        if (
            type(colors) is not int
            or type(bits) is not int
            or type(columns) is not int
            or not 1 <= colors <= 32
            or bits not in (1, 2, 4, 8, 16)
            or columns < 1
        ):
            self.fail("PDF stream has invalid predictor parameters")
        pixel = max(1, colors * bits // 8)
        row = (colors * bits * columns + 7) // 8
        stride = row + 1
        if len(data) % stride:
            self.fail("PDF predictor rows do not match the stream data")
        output = bytearray()
        previous = bytearray(row if data else 0)
        for start in range(0, len(data), stride):
            check_resource_limits()
            kind = data[start]
            current = bytearray(data[start + 1 : start + stride])
            if kind == 1:
                for i in range(pixel, row):
                    current[i] = (current[i] + current[i - pixel]) & 0xFF
            elif kind == 2:
                for i in range(row):
                    current[i] = (current[i] + previous[i]) & 0xFF
            elif kind == 3:
                for i in range(row):
                    left = current[i - pixel] if i >= pixel else 0
                    current[i] = (
                        current[i] + (left + previous[i]) // 2
                    ) & 0xFF
            elif kind == 4:
                for i in range(row):
                    left = current[i - pixel] if i >= pixel else 0
                    up = previous[i]
                    corner = previous[i - pixel] if i >= pixel else 0
                    estimate = left + up - corner
                    near_left = abs(estimate - left)
                    near_up = abs(estimate - up)
                    near_corner = abs(estimate - corner)
                    if near_left <= near_up and near_left <= near_corner:
                        predicted = left
                    elif near_up <= near_corner:
                        predicted = up
                    else:
                        predicted = corner
                    current[i] = (current[i] + predicted) & 0xFF
            elif kind != 0:
                self.fail("PDF predictor row has an unknown filter type")
            output += current
            previous = current
        return bytes(output)


class PdfContentInspector(BaseInspector):
    """
    Inspects PDF documents for active content and stream bombs.

    Rejects a PDF that is encrypted, names a feature from
    ``BLOCKED_PDF_NAMES`` anywhere outside strings, comments and
    stream data (including inside object streams), reads stream
    data from another file, uses a stream filter it cannot decode,
    has a structure readers could parse differently from the scan,
    or whose Flate streams decompress past
    ``max_pdf_uncompressed_size`` or ``max_compression_ratio``.

    Attributes:
        config: File security configuration.
    """

    def inspect_pdf_content(
        self, file_obj: SeekableFile, *, filename: str | None = None
    ) -> None:
        """
        Inspect a PDF held in a seekable file.

        The whole file is read into memory; its size is bounded by
        ``max_pdf_size`` before inspection.

        Args:
            file_obj: Seekable file holding the PDF; rewound to the
                start on return.
            filename: Sanitized filename for error context.

        Raises:
            PdfSecurityError: The PDF is malformed, encrypted,
                carries blocked content or is a stream bomb.
            ResourceLimitError: The active resource monitor's time
                or memory limit is exceeded.
        """
        file_obj.seek(0)
        data = file_obj.read()
        file_obj.seek(0)
        try:
            _Document(self.config, data, filename).inspect()
        except PdfSecurityError as err:
            if err.error_code != ErrorCode.PDF_INVALID_STRUCTURE:
                logger.warning(
                    "PDF rejected: %s",
                    err.message,
                    extra=log_extra(),
                )
                cid = get_correlation_id()
                if cid:
                    self._audit.threat(filename or "", cid, err.message)
            raise
        logger.debug("PDF inspection passed (%d bytes)", len(data))
