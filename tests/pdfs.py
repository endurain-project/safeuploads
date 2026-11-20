"""In-memory PDF builders for tests."""

import re
import zlib

CATALOG = b"<< /Type /Catalog /Pages 2 0 R >>"
PAGES = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
PAGE = (
    b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>"
)
CONTENT = b"BT /F1 12 Tf 72 720 Td (Hello) Tj ET"


def stream(
    entries: bytes,
    data: bytes,
    *,
    flate: bool = False,
    length: bytes | None = None,
) -> bytes:
    """
    Build a stream object body.

    Args:
        entries: Dictionary entries besides /Length and /Filter.
        data: Stream data, compressed first when ``flate`` is set.
        flate: Compress the data and add ``/Filter /FlateDecode``.
        length: /Length value; the data length when omitted.

    Returns:
        Body of the stream object.
    """
    if flate:
        data = zlib.compress(data)
        entries += b" /Filter /FlateDecode"
    if length is None:
        length = str(len(data)).encode()
    return (
        b"<< "
        + entries
        + b" /Length "
        + length
        + b" >>\nstream\n"
        + data
        + b"\nendstream"
    )


def _png_up(rows: list[bytes]) -> bytes:
    """Encode rows with the PNG Up predictor."""
    out = bytearray()
    previous = bytes(len(rows[0]))
    for row in rows:
        out.append(2)
        out += bytes(
            (a - b) & 0xFF for a, b in zip(row, previous, strict=True)
        )
        previous = row
    return bytes(out)


def build(
    objects: list[bytes],
    *,
    compressed: list[bytes] = (),
    xref_stream: bool = False,
    trailer: bytes = b"",
    version: bytes = b"1.7",
    tail: bytes = b"",
) -> bytes:
    """
    Build a PDF from object bodies with a correct xref section.

    Objects are numbered from 1 in order. ``compressed`` bodies
    follow them in one object stream, and an xref stream, when
    used, comes last.

    Args:
        objects: Bodies of the top-level objects.
        compressed: Bodies stored in an object stream.
        xref_stream: Use a compressed xref stream with the PNG Up
            predictor instead of an xref table.
        trailer: Extra trailer dictionary entries.
        version: Header version.
        tail: Bytes appended after the final ``%%EOF``.

    Returns:
        The PDF bytes.
    """
    out = bytearray(b"%PDF-" + version + b"\n%\xe2\xe3\xcf\xd3\n")
    entries: dict[int, tuple[int, int, int]] = {}
    for num, body in enumerate(objects, start=1):
        entries[num] = (1, len(out), 0)
        out += b"%d 0 obj\n%s\nendobj\n" % (num, body)

    next_num = len(objects) + 1
    if compressed:
        container = next_num + len(compressed)
        header = bytearray()
        payload = bytearray()
        for index, body in enumerate(compressed):
            num = next_num + index
            header += b"%d %d " % (num, len(payload))
            payload += body + b"\n"
            entries[num] = (2, container, index)
        first = len(header)
        entries[container] = (1, len(out), 0)
        body = stream(
            b"/Type /ObjStm /N %d /First %d" % (len(compressed), first),
            bytes(header) + bytes(payload),
            flate=True,
        )
        out += b"%d 0 obj\n%s\nendobj\n" % (container, body)
        next_num = container + 1

    size = next_num + (1 if xref_stream else 0)
    root = b"/Root 1 0 R /Size %d" % size
    if xref_stream:
        xref_num = next_num
        entries[xref_num] = (1, len(out), 0)
        rows = [b"\x00\x00\x00\x00\x00\xff\xff"]
        for num in range(1, size):
            kind, field2, field3 = entries[num]
            rows.append(
                bytes([kind]) + field2.to_bytes(4, "big") + bytes([0, field3])
            )
        body = stream(
            b"/Type /XRef /W [1 4 2] "
            + root
            + b" "
            + trailer
            + b" /DecodeParms << /Predictor 12 /Columns 7 >>",
            _png_up(rows),
            flate=True,
        )
        startxref = len(out)
        out += b"%d 0 obj\n%s\nendobj\n" % (xref_num, body)
    else:
        startxref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % size
        for num in range(1, size):
            kind, offset, _ = entries[num]
            if kind != 1:
                raise ValueError("compressed objects need an xref stream")
            out += b"%010d 00000 n \n" % offset
        out += b"trailer\n<< " + root + b" " + trailer + b" >>\n"
    out += b"startxref\n%d\n%%%%EOF\n" % startxref
    return bytes(out) + tail


def document(
    *,
    catalog: bytes = b"",
    page: bytes = b"",
    extra: list[bytes] = (),
    compressed: list[bytes] = (),
    **kwargs: object,
) -> bytes:
    """
    Build a one-page PDF.

    Objects 1-4 are the catalog, page tree, page and content
    stream; ``extra`` bodies are objects 5 onwards.

    Args:
        catalog: Extra catalog dictionary entries.
        page: Extra page dictionary entries.
        extra: Bodies of further top-level objects.
        compressed: Bodies stored in an object stream.
        **kwargs: Passed to ``build``.

    Returns:
        The PDF bytes.
    """
    objects = [
        CATALOG[:-2] + catalog + b" >>",
        PAGES,
        PAGE[:-2] + page + b" >>",
        stream(b"", CONTENT, flate=True),
        *extra,
    ]
    return build(objects, compressed=list(compressed), **kwargs)


def linearized(*, startxref_main: bool = False) -> bytes:
    """
    Build a linearized one-page PDF.

    The linearization dictionary (object 5) comes first, then the
    first-page xref table for objects 3-5, whose trailer /Prev
    points at the main xref table for objects 1-2 at the end of the
    file, and a ``startxref 0``. The final startxref points at the
    first-page table.

    Args:
        startxref_main: Point the final startxref at the main table
            instead, so no section links to the first-page table.

    Returns:
        The PDF bytes.
    """
    bodies = {
        3: PAGE,
        4: stream(b"", CONTENT, flate=True),
        1: CATALOG,
        2: PAGES,
    }
    offsets = dict.fromkeys(range(1, 6), 0)
    main = 0
    # Every offset is fixed width, so the second pass lays the file
    # out exactly as the first one and writes the offsets it found.
    for _ in range(2):
        out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
        offsets[5] = len(out)
        out += b"5 0 obj\n<< /Linearized 1 /O 3 /N 1 >>\nendobj\n"
        first_page = len(out)
        out += b"xref\n3 3\n"
        for num in (3, 4, 5):
            out += b"%010d 00000 n \n" % offsets[num]
        out += b"trailer\n<< /Root 1 0 R /Size 6 /Prev %010d >>\n" % main
        out += b"startxref\n0\n%%EOF\n"
        for num, body in bodies.items():
            offsets[num] = len(out)
            out += b"%d 0 obj\n%s\nendobj\n" % (num, body)
        main = len(out)
        out += b"xref\n0 3\n0000000000 65535 f \n"
        for num in (1, 2):
            out += b"%010d 00000 n \n" % offsets[num]
        out += b"trailer\n<< /Root 1 0 R /Size 6 >>\n"
    out += b"startxref\n%d\n%%%%EOF\n" % (
        main if startxref_main else first_page
    )
    return bytes(out)


def append_update(pdf: bytes, objects: dict[int, bytes]) -> bytes:
    """
    Append an incremental update replacing or adding objects.

    Args:
        pdf: PDF with an xref table to update.
        objects: Object bodies by object number.

    Returns:
        The PDF with an update section whose trailer has /Prev.
    """
    prev = int(re.findall(rb"startxref\s+(\d+)", pdf)[-1])
    size = int(re.findall(rb"/Size (\d+)", pdf)[-1])
    out = bytearray(pdf)
    offsets = {}
    for num, body in objects.items():
        offsets[num] = len(out)
        out += b"%d 0 obj\n%s\nendobj\n" % (num, body)
    startxref = len(out)
    out += b"xref\n0 1\n0000000000 65535 f \n"
    for num, offset in offsets.items():
        out += b"%d 1\n%010d 00000 n \n" % (num, offset)
    size = max(size, *(num + 1 for num in objects))
    out += b"trailer\n<< /Root 1 0 R /Size %d /Prev %d >>\n" % (size, prev)
    out += b"startxref\n%d\n%%%%EOF\n" % startxref
    return bytes(out)
