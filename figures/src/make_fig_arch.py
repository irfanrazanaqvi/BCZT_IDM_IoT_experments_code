"""Single source for the architecture figure: writes an editable draw.io file, an SVG and (via rsvg-convert) a 600 dpi PNG and a vector PDF."""
import os, subprocess, html
from xml.sax.saxutils import escape
HERE = os.path.dirname(os.path.abspath(__file__)); OUT = os.path.join(HERE, "..")
W, H = 1260, 725
FS, FST, FSL = 20, 21, 18            # box text, zone title, legend sizes (px)
INK = "#1b2733"; EDGE = "#3a4654"
Z = {  # fill, stroke, title colour
 "field": ("#FFF6E3", "#D9902B", "#8A5200"),
 "site":  ("#EAF2FC", "#2D6CB5", "#14407A"),
 "cons":  ("#E8F5EB", "#3C8D4B", "#1E5B2B")}
zones = [("zf","field","Field zone (Purdue levels 0–1)",15,15,1230,205),
         ("zs","site","Site operations zone (levels 2–3)",15,235,1230,200),
         ("zc","cons","Consortium zone (OEM, operator, auditor)",15,445,1230,170)]
# id, zone, lines (first line bold), x,y,w,h, dashed, fill, stroke
B = [
 ("sen","field",["Sensor /","actuator"],45,65,170,100,0,"#FFE9B8","#D9902B"),
 ("plc","field",["PLC /","robot"],230,65,170,100,0,"#FFE9B8","#D9902B"),
 ("leg","field",["Legacy device","(no keys)"],415,65,180,100,1,"#FFE0CF","#D9692F"),
 ("gw","field",["Protocol gateway","identity proxy for","legacy devices"],630,65,250,100,0,"#FFE0CF","#D9692F"),
 ("pep","field",["Zone PEP","verify, enforce, log","fast path + audited path"],915,65,300,100,0,"#CFE3F8","#2D6CB5"),
 ("hmi","site",["HMI /","engineering","workstation"],45,285,200,110,0,"#CFE3F8","#2D6CB5"),
 ("eng","site",["Trust engine (PDP)","signals P, A, N, R;","per-tier policy"],285,285,265,110,0,"#CFE3F8","#2D6CB5"),
 ("ora","site",["Trust oracle","signs DID, resource,","T, A, nonce"],620,285,250,110,0,"#CFE3F8","#2D6CB5"),
 ("rep","site",["Local replica of","chain state +","decision log"],915,285,300,110,0,"#CFE3F8","#2D6CB5"),
 ("reg","cons",["IdentityRegistry","status FSM, key blacklist,","batch revoke / quarantine"],45,495,360,100,0,"#D2EBD8","#3C8D4B"),
 ("zta","cons",["ZeroTrustAccess","tier policy, anomaly gate,","strict mode, root anchoring"],435,495,380,100,0,"#D2EBD8","#3C8D4B"),
 ("gov","cons",["RevocationGovernance","quorum q = ⌊N/2⌋+1;","vendor, operator, auditor vote"],845,495,370,100,0,"#D2EBD8","#3C8D4B"),
]
bx = {b[0]: b for b in B}
def pt(i, fx, fy):
    b = bx[i]; return (b[3] + fx * b[5], b[4] + fy * b[6])
# edges: id, src, (fx,fy), dst, (fx,fy), waypoints, dashed
E = [
 ("e_lg","leg",(1,.5),"gw",(0,.5),[],0),
 ("e_gp","gw",(1,.5),"pep",(0,.5),[],0),
 ("e2","pep",(2/7*1+0.0,1),"eng",(.5,0),None,0),   # placeholder, set below
]
E = [
 ("e_lg","leg",(1,.5),"gw",(0,.5),[],0),
 ("e_gp","gw",(1,.5),"pep",(0,.5),[],0),
 ("e2","pep",((1000-915)/300,1),"eng",(.5,0),[(1000,228),(417.5,228)],0),
 ("e3","eng",(1,.5),"ora",(0,.5),[],0),
 ("e4","ora",(.5,1),"zta",((745-435)/380,0),[],0),
 ("e5","rep",((1150-915)/300,0),"pep",((1150-915)/300,1),[],0),
 ("e6","gov",(.5,0),"rep",((1030-915)/300,1),[],1),
]
# the signed-request line starts under the keyed devices and enters the PEP from below
E1 = dict(start=(222.5,180), pts=[(222.5,196),(930,196)], end=(930,165))
BRACKET = [((45,172),(45,180)),((45,180),(400,180)),((400,180),(400,172))]
BADGES = [("1",600,196),("2",700,228),("3",571,340),("4",745,445),("5",1150,225),("6",1030,445)]
LEG1 = ["Signed request (DID, nonce, signature)","Request context to the trust engine","Trust score T and anomaly A to the oracle"]
LEG2 = ["Signed attestation on the audited path (T2–T3)","Chain state for the local fast path (T0–T1)","Contract events synchronised to the replica"]
def edge_poly(e):
    _, s, sf, d, df, w, dash = e
    return [pt(s,*sf)] + list(w) + [pt(d,*df)]

# ---------- SVG ----------
def svg(font):
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{font}">',
         f'<title>Architecture of the blockchain-enabled Zero Trust system for Industrial IoT identity management</title>',
         f'<desc>Three stacked zones: field zone (sensors, PLCs, legacy devices, protocol gateway, zone PEP), site operations zone (HMI, trust engine, trust oracle, local replica) and consortium zone (IdentityRegistry, ZeroTrustAccess, RevocationGovernance).</desc>',
         '<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="%s"/></marker></defs>' % EDGE,
         f'<rect width="{W}" height="{H}" fill="#ffffff"/>']
    for zid, k, t, x, y, w, h in zones:
        f, s, tc = Z[k]
        o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="16" fill="{f}" stroke="{s}" stroke-width="2" stroke-dasharray="9 6"/>')
        o.append(f'<text x="{x+20}" y="{y+30}" font-size="{FST}" font-weight="bold" fill="{tc}">{escape(t)}</text>')
    for (a, b) in BRACKET:
        o.append(f'<line x1="{a[0]}" y1="{a[1]}" x2="{b[0]}" y2="{b[1]}" stroke="{EDGE}" stroke-width="2.5"/>')
    pts = [E1["start"]] + E1["pts"] + [E1["end"]]
    o.append('<polyline points="%s" fill="none" stroke="%s" stroke-width="2.5" marker-end="url(#a)"/>' % (" ".join("%g,%g" % p for p in pts), EDGE))
    for e in E:
        p = edge_poly(e)
        da = ' stroke-dasharray="10 7"' if e[6] else ""
        o.append('<polyline points="%s" fill="none" stroke="%s" stroke-width="2.5"%s marker-end="url(#a)"/>' % (" ".join("%g,%g" % q for q in p), EDGE, da))
    for bid, zk, lines, x, y, w, h, dash, fill, stroke in B:
        da = ' stroke-dasharray="8 5"' if dash else ""
        o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" stroke="{stroke}" stroke-width="2.5"{da}/>')
        n = len(lines); lh = 25; y0 = y + h / 2 - (n - 1) * lh / 2 + 7
        for i, ln in enumerate(lines):
            wt = ' font-weight="bold"' if i == 0 and n > 1 and bid not in ("sen","plc","leg","hmi") else ""
            if bid in ("sen","plc","leg","hmi") and i == 0: wt = ' font-weight="bold"'
            o.append(f'<text x="{x+w/2}" y="{y0+i*lh:.1f}" font-size="{FS}" text-anchor="middle" fill="{INK}"{wt}>{escape(ln)}</text>')
    for n, x, y in BADGES:
        o.append(f'<circle cx="{x}" cy="{y}" r="14" fill="#ffffff" stroke="{EDGE}" stroke-width="2.5"/>')
        o.append(f'<text x="{x}" y="{y+7}" font-size="19" font-weight="bold" text-anchor="middle" fill="{INK}">{n}</text>')
    # legend
    ly = 640
    o.append(f'<line x1="30" y1="628" x2="{W-30}" y2="628" stroke="#c9d1da" stroke-width="1.5"/>')
    for col, items, x0 in ((0, LEG1, 30), (1, LEG2, 650)):
        for i, t in enumerate(items):
            n = i + 1 + 3 * col; yy = ly + 14 + i * 27
            o.append(f'<circle cx="{x0+14}" cy="{yy-6}" r="12" fill="#ffffff" stroke="{EDGE}" stroke-width="2"/>')
            o.append(f'<text x="{x0+14}" y="{yy}" font-size="16" font-weight="bold" text-anchor="middle" fill="{INK}">{n}</text>')
            o.append(f'<text x="{x0+38}" y="{yy}" font-size="{FSL}" fill="{INK}">{escape(t)}</text>')
    o.append('</svg>')
    return "\n".join(o)

# ---------- draw.io ----------
def drawio():
    c = ['<mxGraphModel adaptiveColors="auto" dx="0" dy="0" grid="1" gridSize="5" guides="1" page="1" pageWidth="%d" pageHeight="%d" math="0" shadow="0"><root>' % (W, H),
         '<mxCell id="0"/><mxCell id="1" parent="0"/>']
    fnt = "fontFamily=Helvetica;fontColor=%s;" % INK
    for zid, k, t, x, y, w, h in zones:
        f, s, tc = Z[k]
        c.append(f'<mxCell id="{zid}" value="{escape(t)}" style="rounded=1;arcSize=4;whiteSpace=wrap;html=1;dashed=1;dashPattern=9 6;fillColor={f};strokeColor={s};strokeWidth=2;verticalAlign=top;align=left;spacingLeft=14;spacingTop=6;fontSize={FST};fontStyle=1;fontFamily=Helvetica;fontColor={tc};" vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
    for bid, zk, lines, x, y, w, h, dash, fill, stroke in B:
        lab = "<b>%s</b>" % escape(lines[0]) + "".join("<br>" + escape(l) for l in lines[1:])
        d = "dashed=1;dashPattern=8 5;" if dash else ""
        c.append(f'<mxCell id="{bid}" value="{escape(lab)}" style="rounded=1;arcSize=12;whiteSpace=wrap;html=1;{d}fillColor={fill};strokeColor={stroke};strokeWidth=2.5;fontSize={FS};{fnt}" vertex="1" parent="1"><mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
    base = f"html=1;endArrow=classic;endFill=1;strokeColor={EDGE};strokeWidth=2.5;"
    for e in E:
        eid, s, sf, d, df, w, dash = e
        st = base + f"exitX={sf[0]:.4f};exitY={sf[1]:.4f};exitDx=0;exitDy=0;entryX={df[0]:.4f};entryY={df[1]:.4f};entryDx=0;entryDy=0;" + ("dashed=1;dashPattern=10 7;" if dash else "")
        pts = "".join(f'<mxPoint x="{p[0]:g}" y="{p[1]:g}"/>' for p in w)
        arr = f'<Array as="points">{pts}</Array>' if w else ""
        c.append(f'<mxCell id="{eid}" style="{st}" edge="1" parent="1" source="{s}" target="{d}"><mxGeometry relative="1" as="geometry">{arr}</mxGeometry></mxCell>')
    pts = "".join(f'<mxPoint x="{p[0]:g}" y="{p[1]:g}"/>' for p in E1["pts"])
    c.append(f'<mxCell id="e1" style="{base}" edge="1" parent="1" target="pep"><mxGeometry relative="1" as="geometry"><mxPoint x="{E1["start"][0]}" y="{E1["start"][1]}" as="sourcePoint"/><mxPoint x="{E1["end"][0]}" y="{E1["end"][1]}" as="targetPoint"/><Array as="points">{pts}</Array></mxGeometry></mxCell>')
    for i, (a, b) in enumerate(BRACKET):
        c.append(f'<mxCell id="br{i}" style="html=1;endArrow=none;strokeColor={EDGE};strokeWidth=2.5;" edge="1" parent="1"><mxGeometry relative="1" as="geometry"><mxPoint x="{a[0]}" y="{a[1]}" as="sourcePoint"/><mxPoint x="{b[0]}" y="{b[1]}" as="targetPoint"/></mxGeometry></mxCell>')
    for n, x, y in BADGES:
        c.append(f'<mxCell id="n{n}" value="{n}" style="ellipse;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor={EDGE};strokeWidth=2.5;fontStyle=1;fontSize=19;{fnt}" vertex="1" parent="1"><mxGeometry x="{x-14}" y="{y-14}" width="28" height="28" as="geometry"/></mxCell>')
    for col, items, x0 in ((0, LEG1, 30), (1, LEG2, 650)):
        for i, t in enumerate(items):
            n = i + 1 + 3 * col; yy = 640 + 14 + i * 27
            c.append(f'<mxCell id="l{n}" value="{n}" style="ellipse;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor={EDGE};strokeWidth=2;fontStyle=1;fontSize=16;{fnt}" vertex="1" parent="1"><mxGeometry x="{x0+2}" y="{yy-18}" width="24" height="24" as="geometry"/></mxCell>')
            c.append(f'<mxCell id="lt{n}" value="{escape(t)}" style="text;html=1;align=left;verticalAlign=middle;fontSize={FSL};{fnt}" vertex="1" parent="1"><mxGeometry x="{x0+38}" y="{yy-20}" width="560" height="28" as="geometry"/></mxCell>')
    c.append('</root></mxGraphModel>')
    return "".join(c)

if __name__ == "__main__":
    base = os.path.join(OUT, "fig7_iiot_arch")
    open(base + ".drawio", "w").write('<mxfile host="app.diagrams.net"><diagram name="Architecture" id="arch">' + drawio() + '</diagram></mxfile>')
    open(base + ".svg", "w").write(svg("DejaVu Sans Condensed, Arial, Helvetica, sans-serif"))
    subprocess.check_call(["rsvg-convert", "-w", "4320", "-o", base + ".png", base + ".svg"])
    subprocess.check_call(["rsvg-convert", "-f", "pdf", "-o", base + ".pdf", base + ".svg"])
    from PIL import Image
    im = Image.open(base + ".png"); im.save(base + ".png", dpi=(600, 600), optimize=True); print(im.size)
    open(os.path.join(HERE, "fig7_drawio_xml.txt"), "w").write(drawio())
