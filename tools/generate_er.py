#!/usr/bin/env python3
"""Generate the SkyRecon ER diagram from app/models.py.

Parses the SQLModel table classes so the diagram cannot drift from the schema
the application actually creates. Writes draw.io XML and a standalone SVG.

    python tools/generate_er.py            # from the repo root
"""
import ast, html, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'app', 'models.py')
OUT    = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, 'docs', 'diagrams')

C = dict(bg='#100808', panel='#1a0c0a', head='#2a100c', line='#a71d08', soft='#4a1a10',
         text='#f7ece7', dim='#bfa79f', faint='#8b6a61', gold='#fbc856', hot='#e73b0d',
         moss='#7f9e6a', ash='#8aa3c0')
E = lambda s: html.escape(str(s))

def _fk(default):
    """ast.unparse normalises quote style, so accept either."""
    for q in ('"', "'"):
        token = 'foreign_key=' + q
        if token in default:
            return default.split(token)[1].split(q)[0]
    return None


def unparse(node):
    try: return ast.unparse(node)
    except Exception: return ''

tree = ast.parse(open(MODELS, encoding='utf-8').read())
enums, tables = {}, []

for node in tree.body:
    if isinstance(node, ast.ClassDef):
        bases = [unparse(b) for b in node.bases]
        if 'StrEnum' in bases:
            enums[node.name] = [n.value.value for n in node.body
                                if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)]
            continue
        if not any('SQLModel' in b for b in bases):
            continue
        tname, cols, doc = node.name, [], ast.get_docstring(node) or ''
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and getattr(stmt.targets[0], 'id', '') == '__tablename__':
                tname = stmt.value.value
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                name = stmt.target.id
                if name.startswith('__'): continue
                ann = unparse(stmt.annotation)
                default = unparse(stmt.value) if stmt.value else ''
                cols.append(dict(
                    name=name,
                    type=ann.replace(' | None', '?').replace('datetime', 'datetime'),
                    pk='primary_key=True' in default,
                    unique='unique=True' in default,
                    index='index=True' in default,
                    fk=_fk(default),
                    sealed=name.endswith('_sealed'),
                    blind=name.endswith('_index') and name != 'index',
                ))
        tables.append(dict(cls=node.name, name=tname, cols=cols, doc=doc.split('\n')[0]))

# ── layout ──────────────────────────────────────────────────────────────────
ORDER = ['users', 'sessions', 'indicators', 'events', 'alerts', 'rules', 'audit_log']
tables.sort(key=lambda t: ORDER.index(t['name']) if t['name'] in ORDER else 99)
COLS = [['users', 'sessions'], ['indicators', 'events'], ['alerts'], ['rules', 'audit_log']]
by = {t['name']: t for t in tables}

RH, HH, W, GX, GY = 17, 30, 268, 92, 46
pos, parts = {}, []
x, maxy = 48, 0
for group in COLS:
    y = 118
    for n in [g for g in group if g in by]:
        t = by[n]; h = HH + len(t['cols']) * RH
        pos[n] = (x, y, W, h)
        parts.append(f'<rect x="{x}" y="{y}" width="{W}" height="{h}" rx="7" fill="{C["bg"]}" stroke="{C["line"]}" stroke-width="1.4"/>')
        parts.append(f'<rect x="{x}" y="{y}" width="{W}" height="{HH}" rx="7" fill="{C["head"]}"/>'
                     f'<rect x="{x}" y="{y+HH-8}" width="{W}" height="8" fill="{C["head"]}"/>'
                     f'<path d="M{x} {y+HH} h{W}" stroke="{C["line"]}" stroke-width="1.1"/>')
        parts.append(f'<text x="{x+11}" y="{y+19}" font-family="Archivo,sans-serif" font-weight="700" font-size="13" fill="{C["text"]}">{E(n)}</text>')
        parts.append(f'<text x="{x+W-11}" y="{y+19}" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="8.5" fill="{C["faint"]}">{E(t["cls"])}</text>')
        for i, c in enumerate(t['cols']):
            ry = y + HH + i * RH
            if i % 2: parts.append(f'<rect x="{x+1}" y="{ry}" width="{W-2}" height="{RH}" fill="#1a0c0a"/>')
            key = 'PK' if c['pk'] else ('FK' if c['fk'] else ('U' if c['unique'] else ('i' if c['index'] else '')))
            kc = C['gold'] if c['pk'] else (C['hot'] if c['fk'] else C['faint'])
            if key: parts.append(f'<text x="{x+8}" y="{ry+12}" font-family="JetBrains Mono,monospace" font-size="7.5" font-weight="600" fill="{kc}">{key}</text>')
            # sealed columns and blind indexes are the whole point of this schema — mark them
            mark, mc = ('', C['text'])
            if c['sealed']: mark, mc = ' 🔒', C['moss']
            elif c['blind']: mark, mc = ' #', C['ash']
            nm = c['name'][:30]
            parts.append(f'<text x="{x+28}" y="{ry+12}" font-family="JetBrains Mono,monospace" font-size="9" fill="{mc}">{E(nm)}</text>')
            parts.append(f'<text x="{x+W-8}" y="{ry+12}" text-anchor="end" font-family="JetBrains Mono,monospace" font-size="7.5" fill="{C["faint"]}">{E(c["type"][:20])}</text>')
        y += h + GY; maxy = max(maxy, y)
    x += W + GX

edges, n_fk = [], 0
for t in tables:
    for i, c in enumerate(t['cols']):
        if not c['fk']: continue
        ref = c['fk'].split('.')[0]
        if ref not in pos or t['name'] not in pos: continue
        sx, sy, sw, _ = pos[t['name']]; dx, dy, dw, _ = pos[ref]
        y1 = sy + HH + i * RH + RH / 2; y2 = dy + HH + 8
        x1, x2 = (sx + sw, dx) if sx < dx else (sx, dx + dw)
        m = (x1 + x2) / 2
        edges.append(f'<path d="M{x1} {y1} C{m} {y1} {m} {y2} {x2} {y2}" fill="none" stroke="{C["line"]}" stroke-width="1.1" opacity=".6"/>')
        edges.append(f'<circle cx="{x2}" cy="{y2}" r="2.6" fill="{C["gold"]}"/>')
        n_fk += 1

Wd, Hd = x + 24, maxy + 60
legend = (f'<text x="48" y="{Hd-26}" font-family="JetBrains Mono,monospace" font-size="10" fill="{C["faint"]}">'
          f'PK primary key &#160; FK foreign key &#160; U unique &#160; i indexed &#160;&#160;'
          f'<tspan fill="{C["moss"]}">🔒 sealed (AES-256-GCM)</tspan> &#160;'
          f'<tspan fill="{C["ash"]}"># blind index (searchable without decrypting)</tspan></text>')
svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {Wd} {Hd}" width="{Wd}" height="{Hd}" font-family="Barlow,sans-serif">'
       f'<rect width="{Wd}" height="{Hd}" fill="{C["bg"]}"/>'
       f'<text x="48" y="52" font-family="Archivo,sans-serif" font-weight="800" font-size="27" fill="{C["text"]}">SkyRecon — entity relationship diagram</text>'
       f'<text x="48" y="76" font-size="13" fill="{C["dim"]}">{len(tables)} tables · {n_fk} foreign keys · generated from app/models.py by tools/generate_er.py</text>'
       f'<text x="48" y="96" font-size="12" fill="{C["faint"]}">SQLModel over SQLite or PostgreSQL. Sealed columns hold ciphertext; blind indexes make equality search possible without decrypting.</text>'
       + ''.join(edges) + ''.join(parts) + legend + '</svg>')

os.makedirs(OUT, exist_ok=True)
open(os.path.join(OUT, 'skyrecon-er.svg'), 'w', encoding='utf-8').write(svg)

# draw.io: editable table shapes
cells = []
for n, (px, py, pw, ph) in pos.items():
    t = by[n]
    cells.append(f'<mxCell id="{n}" value="{E(n)}" style="shape=table;startSize=30;container=1;collapsible=1;childLayout=tableLayout;'
                 f'fixedRows=1;rowLines=0;fontStyle=1;align=center;resizeLast=1;html=1;fillColor={C["bg"]};strokeColor={C["line"]};'
                 f'fontColor={C["text"]};fontSize=13;swimlaneFillColor={C["head"]};" vertex="1" parent="1">'
                 f'<mxGeometry x="{px}" y="{py}" width="{pw}" height="{ph}" as="geometry"/></mxCell>')
    for i, c in enumerate(t['cols']):
        rid = f'{n}_r{i}'
        key = 'PK' if c['pk'] else ('FK' if c['fk'] else ('U' if c['unique'] else ('i' if c['index'] else '')))
        kc = C['gold'] if c['pk'] else (C['hot'] if c['fk'] else C['faint'])
        fc = C['moss'] if c['sealed'] else (C['ash'] if c['blind'] else C['text'])
        cells.append(f'<mxCell id="{rid}" value="" style="shape=tableRow;horizontal=0;startSize=0;swimlaneHead=0;swimlaneBody=0;'
                     f'fillColor=none;collapsible=0;dropTarget=0;points=[[0,0.5],[1,0.5]];portConstraint=eastwest;top=0;left=0;right=0;bottom=0;" '
                     f'vertex="1" parent="{n}"><mxGeometry y="{30+i*RH}" width="{pw}" height="{RH}" as="geometry"/></mxCell>')
        cells.append(f'<mxCell id="{rid}_k" value="{key}" style="shape=partialRectangle;connectable=0;fillColor=none;top=0;left=0;bottom=0;right=0;'
                     f'fontStyle=1;overflow=hidden;fontColor={kc};fontSize=8;fontFamily=Courier New;" vertex="1" parent="{rid}">'
                     f'<mxGeometry width="28" height="{RH}" as="geometry"/></mxCell>')
        lbl = E(c['name']) + '&#160;&#160;' + E(f'<span style="color:{C["faint"]};font-size:8px">{c["type"]}</span>')
        cells.append(f'<mxCell id="{rid}_c" value="{lbl}" style="shape=partialRectangle;connectable=0;fillColor=none;top=0;left=0;bottom=0;right=0;'
                     f'align=left;spacingLeft=6;overflow=hidden;html=1;fontColor={fc};fontSize=9;fontFamily=Courier New;" vertex="1" parent="{rid}">'
                     f'<mxGeometry x="28" width="{pw-28}" height="{RH}" as="geometry"/></mxCell>')
fk_cells, k = [], 0
for t in tables:
    for i, c in enumerate(t['cols']):
        if not c['fk']: continue
        ref = c['fk'].split('.')[0]
        if ref not in pos: continue
        k += 1
        fk_cells.append(f'<mxCell id="fk{k}" style="edgeStyle=entityRelationEdgeStyle;rounded=1;html=1;endArrow=ERone;startArrow=ERmany;'
                        f'strokeColor={C["line"]};strokeWidth=1.3;fontColor={C["dim"]};fontSize=9;" edge="1" parent="1" '
                        f'source="{t["name"]}_r{i}" target="{ref}"><mxGeometry relative="1" as="geometry"/></mxCell>')
title = (f'<mxCell id="t1" value="SkyRecon — entity relationship diagram" style="text;html=1;fontSize=24;fontStyle=1;fontColor={C["text"]};align=left;" '
         f'vertex="1" parent="1"><mxGeometry x="48" y="20" width="760" height="32" as="geometry"/></mxCell>'
         f'<mxCell id="t2" value="{len(tables)} tables · {n_fk} foreign keys · generated from app/models.py — sealed columns hold AES-256-GCM ciphertext, *_index columns are blind indexes" '
         f'style="text;html=1;fontSize=12;fontColor={C["dim"]};align=left;" vertex="1" parent="1">'
         f'<mxGeometry x="50" y="52" width="1200" height="20" as="geometry"/></mxCell>')
xml = (f'<mxfile host="app.diagrams.net" agent="SkyRecon tools/generate_er.py" version="24.0.0">'
       f'<diagram id="er" name="ER diagram"><mxGraphModel dx="1600" dy="900" grid="0" page="1" pageWidth="{Wd}" pageHeight="{Hd}" background="{C["bg"]}">'
       f'<root><mxCell id="0"/><mxCell id="1" parent="0"/>{title}{"".join(cells)}{"".join(fk_cells)}</root></mxGraphModel></diagram></mxfile>')
open(os.path.join(OUT, 'skyrecon-er.drawio'), 'w', encoding='utf-8').write(xml)

print(f'{len(tables)} tables, {n_fk} foreign keys')
for t in tables:
    sealed = sum(1 for c in t['cols'] if c['sealed']); blind = sum(1 for c in t['cols'] if c['blind'])
    print(f'  {t["name"]:<12} {len(t["cols"]):>2} cols  {sealed} sealed  {blind} blind-indexed')
