"""mkpdf.py [N]: a minimal valid PDF with N pages (one short text line each), printed as a base64
data URI (the PDF-parsing cases of v3-node-check.sh and the OpenRouter pin probes)."""
import base64


def pdf(n: int) -> bytes:
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", None, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    kids = []
    for i in range(n):
        content = f"BT /F1 24 Tf 72 700 Td (Page {i + 1}: the word is OK.) Tj ET".encode()
        objs.append(f"<< /Length {len(content)} >>\nstream\n{content.decode()}\nendstream")
        cid = len(objs)
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {cid} 0 R /Resources << /Font << /F1 3 0 R >> >> >>")
        kids.append(f"{len(objs)} 0 R")
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {n} >>"
    out, offs = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs):
        offs.append(len(out))
        out += f"{i + 1} 0 obj\n{o}\nendobj\n".encode()
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for o in offs:
        out += f"{o:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
    return bytes(out)


def data_uri(n: int) -> str:
    return "data:application/pdf;base64," + base64.b64encode(pdf(n)).decode()


if __name__ == "__main__":
    import sys
    print(data_uri(int(sys.argv[1]) if len(sys.argv) > 1 else 1))
