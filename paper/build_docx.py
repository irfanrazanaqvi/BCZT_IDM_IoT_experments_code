"""Build the 2-column IEEE-style DOCX from the LaTeX sources (pandoc + OOXML post-processing)."""
import re, subprocess, sys, copy, os
from docx import Document
from docx.shared import Pt, Emu, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from lxml import etree

OUT = sys.argv[1] if len(sys.argv) > 1 else "paper.docx"
aux = open("main.aux").read()
cites = {k: v for k, v in re.findall(r"\\bibcite\{([^}]*)\}\{([^}]*)\}", aux)}
labels = {k: v for k, v in re.findall(r"\\newlabel\{([^}]*)\}\{\{([^}]*)\}", aux)}

def flat(name):
    t = open(name + ".tex").read()
    return re.sub(r"\\input\{([^}]*)\}", lambda m: flat(m.group(1)) if not m.group(1).startswith("tab_") else open(m.group(1) + ".tex").read(), t)

main = open("main.tex").read()
body = main.split("\\begin{document}")[1].split("\\end{document}")[0]
body = re.sub(r"\\input\{([^}]*)\}", lambda m: flat(m.group(1)) if not m.group(1).startswith("tab_") else open(m.group(1) + ".tex").read(), body)
# expand nested tab inputs inside flattened sections
body = re.sub(r"\\input\{(tab_[^}]*)\}", lambda m: open(m.group(1) + ".tex").read(), body)

abstract = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", body, re.S).group(1)
body = body.split("\\end{abstract}")[1]
body = body.split("\\balance")[0] + "\\balance" + body.split("\\balance")[1] if "\\balance" in body else body
bib_part = body.split("\\begin{thebibliography}")[1].split("\\end{thebibliography}")[0]
body = body.split("\\begin{thebibliography}")[0].replace("\\balance", "")

# ---------- math -> unicode/text
GREEK = {"theta": "θ", "pm": "±", "le": "≤", "ge": "≥", "ne": "≠", "notin": "∉", "in": "∈", "approx": "≈", "cdot": "·",
         "dots": "…", "ldots": "…", "lfloor": "⌊", "rfloor": "⌋", "sum": "Σ", "square": "∎", "quad": "  ", "lvert": "|", "rvert": "|"}
CAL = {"D": "𝒟", "O": "𝒪"}
def math(m, display=False):
    s = m
    s = re.sub(r"\\xrightarrow\{\\text\{([^}]*)\}\}", lambda x: " →(" + x.group(1) + ") ", s)
    s = re.sub(r"\\mathcal\{(\w)\}", lambda x: CAL.get(x.group(1), x.group(1)), s)
    s = re.sub(r"\\(?:mathrm|text|texttt)\{((?:[^{}]|\{[^{}]*\})*)\}", lambda x: "\x01" + x.group(1).replace("{-}", "-").replace("{,}", ",") + "\x02", s)
    s = s.replace("\\{", "{").replace("\\}", "}").replace("\\,", " ").replace("\\textstyle", "").replace("{,}", ",").replace("{:}", ":").replace("{=}", "=")
    s = re.sub(r"\\([A-Za-z]+)", lambda x: GREEK.get(x.group(1), ""), s)
    s = s.replace("'", "′")
    # subscripts/superscripts
    def sub(mm):
        g = mm.group(2) if mm.group(2) is not None else mm.group(3)
        tag = "textsubscript" if mm.group(1) == "_" else "textsuperscript"
        return "\x03" + tag + "\x04" + g + "\x05"
    s = re.sub(r"([_^])(?:\{([^{}]*)\}|(\w))", sub, s)
    s = s.replace("{", "").replace("}", "")
    # italicize single-letter variables (outside \x01..\x02 and sub/sup groups)
    out, i, prot = [], 0, 0
    for ch in s:
        if ch == "\x01": prot += 1
        if ch == "\x02": prot -= 1
        out.append(ch)
    s2 = "".join(out)
    parts = re.split(r"(\x01.*?\x02)", s2)
    res = []
    for p in parts:
        if p.startswith("\x01"):
            res.append(p[1:-1])
        else:
            p = re.sub(r"(?<![A-Za-z\x03\x04])([A-Za-z])(?![A-Za-z])", r"\\emph{\1}", p)
            res.append(p)
    s = "".join(res)
    s = re.sub(r"\x03(\w+)\x04([^\x05]*)\x05", lambda x: "\\" + x.group(1) + "{" + x.group(2).replace("\x01", "").replace("\x02", "") + "}", s)
    s = s.replace("\x01", "").replace("\x02", "")
    return s.replace("%", "\\%").replace("#", "\\#")

body = re.sub(r"\\\[(.*?)\\\]", lambda m: "\n\\begin{center}\n" + math(m.group(1), True) + "\n\\end{center}\n", body, flags=re.S)
body = re.sub(r"(?<!\\)\$(.*?)(?<!\\)\$", lambda m: math(m.group(1)), body, flags=re.S)
abstract = re.sub(r"(?<!\\)\$(.*?)(?<!\\)\$", lambda m: math(m.group(1)), abstract, flags=re.S)

# ---------- refs / cites
body = re.sub(r"\\cite\{([^}]*)\}", lambda m: "[" + ", ".join(sorted((cites[k.strip()] for k in m.group(1).split(",")), key=int)) + "]", body)
body = re.sub(r"\\ref\{([^}]*)\}", lambda m: labels[m.group(1)], body)
abstract = abstract
# propositions
cnt = [0]
def prop(m):
    cnt[0] += 1
    title = m.group(1) or ""
    inner = m.group(2)
    inner = re.sub(r"\\label\{[^}]*\}", "", inner)
    return f"\n\n\\textbf{{Proposition {cnt[0]}{' (' + title + ')' if title else ''}.}} \\emph{{{inner.strip()}}}\n\n"
body = re.sub(r"\\begin\{proposition\}(?:\[([^\]]*)\])?(?:\\label\{[^}]*\})?(.*?)\\end\{proposition\}", lambda m: prop(m), body, flags=re.S)
# floats: caption numbering
def num_caption(env, prefix):
    global body
    def f(m):
        blk = m.group(0)
        lab = re.search(r"\\label\{([^}]*)\}", blk)
        n = labels[lab.group(1)] if lab else "?"
        blk = re.sub(r"\\caption\{", f"\\\\caption{{{prefix} {n}. ", blk, count=1)
        return blk
    body = re.sub(r"\\begin\{" + env + r"\*?\}.*?\\end\{" + env + r"\*?\}", f, body, flags=re.S)
num_caption("table", "TABLE"); num_caption("figure", "Fig.")
body = re.sub(r"\\begin\{(table|figure)\*\}", r"\\begin{\1}", body); body = re.sub(r"\\end\{(table|figure)\*\}", r"\\end{\1}", body)
# sections numbering
sec = [0, 0]
def sx(m):
    if m.group(1) == "section":
        sec[0] += 1; sec[1] = 0
        return f"\\section{{{sec[0]}~~{m.group(2)}}}"
    sec[1] += 1
    return f"\\subsection{{{sec[0]}.{sec[1]}~~{m.group(2)}}}"
body = re.sub(r"\\(section|subsection)\{([^}]*)\}(?:\\label\{[^}]*\})?", sx, body)
body = re.sub(r"\\label\{[^}]*\}", "", body)
body = re.sub(r"\\begin\{(itemize|enumerate)\}\[[^\]]*\]", r"\\begin{\1}", body)
for junk in [r"\\scriptsize", r"\\small", r"\\centering", r"\\vspace\{[^}]*\}", r"\\begin\{minipage\}\{[^}]*\}", r"\\end\{minipage\}", r"\\hfill", r"\\noindent"]:
    body = re.sub(junk, "", body)
body = re.sub(r"\\includegraphics\[[^\]]*\]\{\.\./figures/([^}]*)\}", r"\\includegraphics{../figures/\1}", body)
body = body.replace("\\begin{center}\n\n\\textbf{Algorithm", "\\begin{center}\n\\textbf{Algorithm")
body = re.sub(r"\\begin\{tabular\}\{[^\n]*\}\n", lambda m: m.group(0), body)
body += "\n\\section{References}\n"
items = re.split(r"\\bibitem\{[^}]*\}", bib_part)[1:]
keys = re.findall(r"\\bibitem\{([^}]*)\}", bib_part)
for k, it in zip(keys, items):
    it = it.strip()
    it = re.sub(r"\\href\{([^}]*)\}\{\[Online\]\}", r"\\href{\1}{[Online]}", it)
    body += f"\n\n\\textbf{{[{cites[k]}]}} {it}\n"
abstract = re.sub(r"\\noindent\\textbf\{Index Terms\}\\textemdash", "\n\n\\\\textbf{\\\\emph{Index Terms}}---", abstract)
abstract = abstract.replace("\\noindent", "")
tex = ("\\documentclass{article}\\usepackage{graphicx}\\begin{document}\n"
       "\\begin{center}{\\Large\\textbf{A Blockchain-Enabled Zero Trust Architecture for Industrial IoT Identity Management: Tiered Continuous Authorization and Quorum-Governed Revocation}}\n\n"
       "Author Name\\textsuperscript{1}, Author Name\\textsuperscript{2}\n\n"
       "\\textsuperscript{1}Department of Computer Science, University Name, City, Country; \\textsuperscript{2}Department of Computer Science, University Name, City, Country\n\n"
       "\\end{center}\n\n\\textbf{\\emph{Abstract}}---" + abstract.strip() + "\n\n\\section*{ABSTRACTEND}\n" + body + "\n\\end{document}")
open("_flat.tex", "w").write(tex)
subprocess.run(["pandoc", "_flat.tex", "-f", "latex", "-t", "docx", "-o", "_raw.docx", "--resource-path=."], check=True)

# ---------- post-process
doc = Document("_raw.docx")
B = doc.element.body
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
st = doc.styles
class _S:
    def __init__(self, st): self.st = st
    def __getitem__(self, n): return next(x for x in self.st if x.name == n)
    def __iter__(self): return iter(self.st)
st = _S(st)
for name in ["Normal", "Body Text", "First Paragraph", "Compact", "Table Caption", "Image Caption", "Captioned Figure"]:
    if name in [x.name for x in st]:
        f = st[name].font; f.name = "Times New Roman"; f.size = Pt(9.5)
        rpr = st[name].element.get_or_add_rPr(); rf = rpr.find(qn("w:rFonts"))
        if rf is None: rf = OxmlElement("w:rFonts"); rpr.append(rf)
        for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"): rf.set(qn(a), "Times New Roman")
        if name in ("Body Text", "First Paragraph", "Normal"):
            st[name].paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            st[name].paragraph_format.space_after = Pt(3); st[name].paragraph_format.space_before = Pt(0)
for name, size in [("Heading 1", 12), ("Heading 2", 10.5)]:
    f = st[name].font; f.name = "Times New Roman"; f.size = Pt(size); f.bold = True
    from docx.shared import RGBColor
    f.color.rgb = RGBColor(0, 0, 0)
    rf = st[name].element.get_or_add_rPr().find(qn("w:rFonts"))
    if rf is None: rf = OxmlElement("w:rFonts"); st[name].element.get_or_add_rPr().append(rf)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"): rf.set(qn(a), "Times New Roman")
    for a in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"): rf.attrib.pop(qn(a), None)
    st[name].paragraph_format.space_before = Pt(6); st[name].paragraph_format.space_after = Pt(2)
for name in ["Hyperlink"]:
    pass

children = list(B)
def text(el): return "".join(t.text or "" for t in el.iter(qn("w:t")))
# title block formatting
paras = [c for c in children if c.tag == qn("w:p")]
# find ABSTRACTEND heading
idx_end = next(i for i, c in enumerate(children) if c.tag == qn("w:p") and text(c).strip() == "ABSTRACTEND")
for c in children[:idx_end]:
    if c.tag == qn("w:p"):
        jc = OxmlElement("w:jc"); jc.set(qn("w:val"), "center" if c is children[0] or children.index(c) < 3 else "both")
        ppr = c.get_or_add_pPr() if hasattr(c, "get_or_add_pPr") else None
B.remove(children[idx_end])
for c in list(B):
    if c.tag in (qn("w:bookmarkStart"), qn("w:bookmarkEnd")): B.remove(c)

def sect(cols, cont=True, final=False):
    sp = OxmlElement("w:sectPr")
    if cont:
        t = OxmlElement("w:type"); t.set(qn("w:val"), "continuous"); sp.append(t)
    pg = OxmlElement("w:pgSz"); pg.set(qn("w:w"), "12240"); pg.set(qn("w:h"), "15840"); sp.append(pg)
    pm = OxmlElement("w:pgMar")
    for k, v in dict(top="1080", right="980", bottom="1080", left="980", header="500", footer="500", gutter="0").items(): pm.set(qn("w:" + k), v)
    sp.append(pm)
    c = OxmlElement("w:cols"); c.set(qn("w:num"), str(cols)); c.set(qn("w:space"), "317"); sp.append(c)
    return sp
def sect_par(cols, cont=True):
    p = OxmlElement("w:p"); ppr = OxmlElement("w:pPr"); ppr.append(sect(cols, cont)); p.append(ppr); return p

children = list(B)
# first heading (Introduction) index
first_h = next(i for i, c in enumerate(children) if c.tag == qn("w:p") and c.find(".//" + qn("w:pStyle")) is not None and c.find(".//" + qn("w:pStyle")).get(qn("w:val")) == "Heading1")
B.insert(list(B).index(children[first_h]), sect_par(1, cont=False))

# image sizing: column images 3.05in wide; wide image (fig5) full width
for dr in B.iter("{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}inline"):
    ext = dr.find("{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}extent")
    cx, cy = int(ext.get("cx")), int(ext.get("cy"))
    alt = "".join(dr.itertext())
    pic = dr.find(".//{http://schemas.openxmlformats.org/drawingml/2006/main}blip")
    wide = True   # both figures are full-width
    newcx = 5200000 if wide else 3000000
    ext.set("cx", str(newcx)); ext.set("cy", str(int(cy * newcx / cx)))
    for e in dr.iter("{http://schemas.openxmlformats.org/drawingml/2006/main}ext"):
        e.set("cx", str(newcx)); e.set("cy", str(int(cy * newcx / cx)))

# tables: borders, font, width
def fix_table(t):
    tp = t.find(qn("w:tblPr"))
    for ch in list(tp):
        if ch.tag in (qn("w:tblW"), qn("w:tblBorders")): tp.remove(ch)
    w = OxmlElement("w:tblW"); w.set(qn("w:type"), "pct"); w.set(qn("w:w"), "5000"); tp.append(w)
    b = OxmlElement("w:tblBorders")
    for side in ("top", "bottom", "insideH"):
        e = OxmlElement("w:" + side); e.set(qn("w:val"), "single"); e.set(qn("w:sz"), "4"); e.set(qn("w:color"), "444444"); b.append(e)
    tp.append(b)
    for r in t.iter(qn("w:r")):
        rp = r.find(qn("w:rPr"))
        if rp is None: rp = OxmlElement("w:rPr"); r.insert(0, rp)
        sz = OxmlElement("w:sz"); sz.set(qn("w:val"), "15"); rp.append(sz)
    for p in t.iter(qn("w:p")):
        ppr = p.find(qn("w:pPr"))
        if ppr is None: ppr = OxmlElement("w:pPr"); p.insert(0, ppr)
        jc = OxmlElement("w:jc"); jc.set(qn("w:val"), "left"); ppr.append(jc)
for t in B.iter(qn("w:tbl")): fix_table(t)

# centre equations; keep tables together
for p in B.iter(qn("w:p")):
    t = text(p).strip()
    if t.startswith(("UNKNOWN", "ACTIVE", "did", "T = ")) and len(t) < 90:
        ppr = p.find(qn("w:pPr"))
        if ppr is None: ppr = OxmlElement("w:pPr"); p.insert(0, ppr)
        for j in ppr.findall(qn("w:jc")): ppr.remove(j)
        jc = OxmlElement("w:jc"); jc.set(qn("w:val"), "center"); ppr.append(jc)
for t in B.iter(qn("w:tbl")):
    rows = t.findall(qn("w:tr"))
    for r in rows[:-1]:
        for p in r.iter(qn("w:p")):
            ppr = p.find(qn("w:pPr"))
            if ppr is None: ppr = OxmlElement("w:pPr"); p.insert(0, ppr)
            ppr.insert(0, OxmlElement("w:keepNext"))
    prev = t.getprevious()
    if prev is not None and prev.tag == qn("w:p"):
        ppr = prev.find(qn("w:pPr"))
        if ppr is None: ppr = OxmlElement("w:pPr"); prev.insert(0, ppr)
        ppr.insert(0, OxmlElement("w:keepNext"))
# wrap wide blocks (Table 1 and Fig. 5) in one-column continuous sections
children = list(B)
def find_idx(pred):
    for i, c in enumerate(children):
        if pred(c): return i
    return None
def wrap(i0, i1):
    ch = list(B)
    a, b = ch[i0], ch[i1]
    B.insert(list(B).index(a), sect_par(2))
    B.insert(list(B).index(b) + 1, sect_par(1))
# Table 1: caption paragraph "TABLE 1." then table
i_cap = find_idx(lambda c: c.tag == qn("w:p") and text(c).startswith("TABLE 1."))
i_tab = find_idx(lambda c: c.tag == qn("w:tbl") and "System" in text(c)[:40])
if i_cap is not None and i_tab is not None:
    lo, hi = min(i_cap, i_tab), max(i_cap, i_tab); wrap(lo, hi)
children = list(B)
for figlabel in ("Fig. 1.", "Fig. 2."):
    children = list(B)
    i_cap = find_idx(lambda c: c.tag == qn("w:p") and text(c).startswith(figlabel))
    i_img = None
    if i_cap is not None:
        for j in range(i_cap, max(-1, i_cap - 4), -1):
            c = children[j]
            if c.tag == qn("w:p") and c.find(".//" + qn("w:drawing")) is not None: i_img = j; break
        if i_img is None:
            for j in range(i_cap, min(len(children), i_cap + 4)):
                c = children[j]
                if c.tag == qn("w:p") and c.find(".//" + qn("w:drawing")) is not None: i_img = j; break
    if i_cap is not None and i_img is not None:
        lo, hi = min(i_cap, i_img), max(i_cap, i_img); wrap(lo, hi)
# final section: 2 columns
final = B.find(qn("w:sectPr"))
if final is not None: B.remove(final)
B.append(sect(2, cont=True))
doc.core_properties.title = "A Blockchain-Enabled Zero Trust Architecture for Industrial IoT Identity Management: Tiered Continuous Authorization and Quorum-Governed Revocation"
doc.save(OUT)
print("saved", OUT)
