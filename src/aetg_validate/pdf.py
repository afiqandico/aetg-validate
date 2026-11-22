"""Self-contained PDF rendering — pure standard library.

The PDF is the artefact people forward to an auditor, so it must not depend on
a browser, a headless Chrome, or a LaTeX toolchain being installed. This module
writes PDF 1.4 directly: one font (Helvetica), no images, no compression, and
an explicit signature block.

It is deliberately small. If you need rich layout, render HTML and print it —
this exists so a report can be produced on an air-gapped machine with nothing
but Python.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Sequence, Tuple

PAGE_W = 595.28  # A4 points
PAGE_H = 841.89
MARGIN = 56.0
LINE_H = 14.0
BODY_SIZE = 9.5
TITLE_SIZE = 16.0
MONO_MAX_CHARS = 96


_TRANSLITERATE = {
    "\u2014": "-",
    "\u2013": "-",
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2026": "...",
    "\u00d7": "x",
    "\u2264": "<=",
    "\u2265": ">=",
    "\u03a6": "Phi",
    "\u03c6": "phi",
    "\u2192": "->",
    "\u00a0": " ",
}


def _escape(text: str) -> str:
    # Helvetica's default encoding is Latin-1: fold typography down rather than
    # crash or emit mojibake in an audit artefact.
    for source, target in _TRANSLITERATE.items():
        text = text.replace(source, target)
    text = text.encode("latin-1", errors="replace").decode("latin-1")
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _wrap(text: str, width: int = MONO_MAX_CHARS) -> List[str]:
    """Wrap on characters, not words — report lines are mostly digests."""
    if len(text) <= width:
        return [text]
    out: List[str] = []
    current = ""
    for word in text.split(" "):
        candidate = word if not current else current + " " + word
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                out.append(current)
            while len(word) > width:
                out.append(word[:width])
                word = word[width:]
            current = word
    if current:
        out.append(current)
    return out


def _build_pages(lines: Sequence[Tuple[str, float]]) -> List[str]:
    """Lay out (text, size) rows into page content streams."""
    pages: List[str] = []
    stream: List[str] = []
    y = PAGE_H - MARGIN

    for text, size in lines:
        for chunk in _wrap(text):
            if y < MARGIN + LINE_H:
                pages.append("\n".join(stream))
                stream, y = [], PAGE_H - MARGIN
            stream.append(
                f"BT /F1 {size:.2f} Tf {MARGIN:.2f} {y:.2f} Td ({_escape(chunk)}) Tj ET"
            )
            y -= LINE_H if size >= BODY_SIZE else LINE_H * 0.75

    if stream:
        pages.append("\n".join(stream))
    if not pages:
        pages = [""]
    return pages


def render_pdf(lines: Sequence[Tuple[str, float]], title: str) -> bytes:
    """Build a PDF from (text, font-size) rows."""
    pages = _build_pages(lines)

    objects: List[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    font_id = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids: List[int] = []
    content_ids: List[int] = []

    # Reserve page objects first so /Kids can reference them by number.
    pages_id = 0
    for page_no, content in enumerate(pages, start=1):
        stream = (
            f"<< /Length {len(content.encode('latin-1'))} >>\nstream\n{content}\nendstream"
        ).encode("latin-1")
        content_id = add(stream)
        content_ids.append(content_id)
        page_ids.append(0)  # placeholder index, filled below

    pages_id = len(objects) + len(pages) + 1
    for index, content_id in enumerate(content_ids):
        page_id = add(
            (
                f"<< /Type /Page /Parent {pages_id} 0 R "
                f"/MediaBox [0 0 {PAGE_W:.2f} {PAGE_H:.2f}] "
                f"/Resources << /Font << /F1 {font_id} 0 R >> >> "
                f"/Contents {content_id} 0 R >>"
            ).encode("latin-1")
        )
        page_ids[index] = page_id

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    actual_pages_id = add(
        (
            f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>"
        ).encode("latin-1")
    )
    assert actual_pages_id == pages_id, (actual_pages_id, pages_id)

    info_id = add(
        f"<< /Title ({_escape(title)}) /Producer (aetg-validate) /Creator (aetg-validate) >>".encode(
            "latin-1"
        )
    )
    catalog_id = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("latin-1"))

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: List[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode("latin-1")
        out += body
        out += b"\nendobj\n"

    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode("latin-1")
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode("latin-1")
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R /Info {info_id} 0 R >>\n"
        f"startxref\n{xref_at}\n%%EOF\n"
    ).encode("latin-1")
    return bytes(out)


def write_pdf(path: Path | str, lines: Sequence[Tuple[str, float]], title: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(render_pdf(lines, title))
    return path
