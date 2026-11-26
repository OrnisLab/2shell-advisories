#!/usr/bin/env python3
"""Build the header banner for each case file (light OrnisLab style).

Reuses the type and scenery helpers from the OrnisLab .github repo:
    python3 tools/build_banners.py /path/to/ornislab-dotgithub/tools
Writes <case>/assets/banner.svg and assets/banner.svg (index).
"""
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else str(ROOT.parent / "ornislab-github" / "tools"))
import build_assets as B  # noqa: E402

B.C.clear()
B.C.update(B.THEMES["light"])
C = B.C
RED, AMBER, GREEN = "#C42B2B", "#B5700A", "#2E7D57"

CASES = {
    ".": dict(title="The *2Shell case files", sub="Six nicknames, three incidents: OrnisLab analysis",
              chips=[("6 names", C["blue"]), ("3 incidents", C["blue"]), ("Dec 2025 – Oct 2026", C["mute"])],
              glyph="map"),
    "react2shell": dict(title="React2Shell", sub="CVE-2025-55182 · React Server Components RCE",
                        chips=[("CVSS 10.0", RED), ("Disclosed 3 Dec 2025", C["mute"]), ("CISA KEV", AMBER)],
                        glyph="react"),
    "php2shell": dict(title="PHP2Shell", sub="CVE-2026-109618 and CVE-2026-109619 · PHP engine RCE",
                      chips=[("CVSS 9.2", RED), ("Disclosed 21 Oct 2026", C["mute"]), ("CISA KEV", AMBER)],
                      glyph="php"),
    "node2shell": dict(title="Node2Shell", sub="CVE-2026-111497 · Brotli decoder in Node.js",
                       chips=[("CVSS 9.2", RED), ("Root cause and timeline", C["blue"]), ("CISA KEV", AMBER)],
                       glyph="node"),
    "python2shell": dict(title="Python2Shell", sub="CVE-2026-111497 · Brotli bindings on PyPI",
                         chips=[("CVSS 9.2", RED), ("83M downloads a month", C["blue"]), ("CISA KEV", AMBER)],
                         glyph="python"),
    "http2shell": dict(title="HTTP2Shell", sub="CVE-2026-111497 · Every stack that decodes br",
                       chips=[("CVSS 9.2", RED), ("Inbound and outbound", C["blue"]), ("CISA KEV", AMBER)],
                       glyph="http"),
    "broccoli2shell": dict(title="Broccoli2Shell", sub="CVE-2026-111497 · Finding every copy of the decoder",
                           chips=[("CVSS 9.2", RED), ("91% of clouds affected", C["blue"]), ("CISA KEV", AMBER)],
                           glyph="cloud"),
}

# Simple line glyphs drawn in a 120x120 box.
GLYPHS = {
    "map": '<circle cx="24" cy="60" r="10"/><circle cx="96" cy="24" r="10"/><circle cx="96" cy="60" r="10"/>'
           '<circle cx="96" cy="96" r="10"/><path d="M34 60H86M32 55 87 29M32 65 87 91"/>',
    "react": '<ellipse cx="60" cy="60" rx="52" ry="20"/><ellipse cx="60" cy="60" rx="52" ry="20" transform="rotate(60 60 60)"/>'
             '<ellipse cx="60" cy="60" rx="52" ry="20" transform="rotate(-60 60 60)"/><circle cx="60" cy="60" r="7" fill="currentColor"/>',
    "php": '<ellipse cx="60" cy="60" rx="54" ry="30"/><path d="M30 76 37 44H50C58 44 58 58 48 58H40M60 40 54 70M57 54H70L66 70'
           'M80 76 87 44H100C108 44 108 58 98 58H90"/>',
    "node": '<path d="M60 6 106 33V87L60 114 14 87V33Z"/><path d="M60 40V80M44 50 60 40 76 50"/>',
    "python": '<path d="M58 8C34 8 36 18 36 28V40H62V46H26C14 46 6 56 6 72S14 96 26 96H34V82C34 70 44 62 56 62H80C90 62 96 56 96 46V28'
              'C96 16 84 8 58 8Z"/><circle cx="50" cy="22" r="4" fill="currentColor"/>'
              '<path d="M62 112C86 112 84 102 84 92V80H58V74H94C106 74 114 64 114 48" opacity=".55"/>',
    "http": '<path d="M8 40H96M78 24 96 40 78 56"/><path d="M112 80H24M42 64 24 80 42 96"/>',
    "cloud": '<path d="M30 92H94C108 92 116 82 116 70S106 48 92 50C90 30 74 20 58 22 42 24 32 36 32 50 18 50 6 60 6 72S16 92 30 92Z"/>'
             '<circle cx="42" cy="70" r="5" fill="currentColor"/><circle cx="62" cy="62" r="5" fill="currentColor"/>'
             '<circle cx="82" cy="72" r="5" fill="currentColor"/>',
}


def chip(label, colour, x, y):
    size = 15
    w = B.face(600).width(label, size) + 28
    return (f'<rect x="{B.fmt(x)}" y="{y}" width="{B.fmt(w)}" height="32" rx="16" fill="{colour}" fill-opacity=".1" '
            f'stroke="{colour}" stroke-opacity=".45"/>'
            + B.text(label, size=size, x=x + 14, y=y + 21, weight=600, fill=colour)), w


def banner(case):
    W, H = 1280, 300
    rng = random.Random(len(case["title"]))
    body = [
        f'<defs><clipPath id="c"><rect width="{W}" height="{H}" rx="16"/></clipPath></defs>',
        f'<rect width="{W}" height="{H}" rx="16" fill="{C["bg"]}"/>',
        '<g clip-path="url(#c)">',
        B.glow("a", 980, 150, 520, 220),
        f'<g fill="none" stroke="{C["orbit"]}" stroke-width="1.1">'
        f'<path d="{B.ellipse_path(980, 150, 330, 92)}" stroke-opacity=".32"/>'
        f'<path d="{B.ellipse_path(980, 150, 470, 140)}" stroke-opacity=".18"/></g>',
        B.stars(rng, 22, (20, 14, W - 20, H - 14), avoid=[(40, 40, 860, 270), (880, 60, 1080, 240)]),
        f'<g transform="translate(920 90)" fill="none" stroke="{C["logo_b"]}" color="{C["logo_b"]}" '
        f'stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round">{GLYPHS[case["glyph"]]}</g>',
        "</g>",
        f'<rect x=".75" y=".75" width="{W - 1.5}" height="{H - 1.5}" rx="15.5" fill="none" stroke="{C["line"]}" stroke-width="1.5"/>',
        B.text("OrnisLab case file", size=17, x=56, y=66, weight=600, fill=C["logo_b"]),
        B.text(case["title"], size=64, x=52, y=140, weight=700, fill=C["text"], tracking=-0.02),
        B.text(case["sub"], size=22, x=56, y=184, weight=500, fill=C["mute"]),
    ]
    x = 56
    for label, colour in case["chips"]:
        svg, w = chip(label, colour, x, 214)
        body.append(svg)
        x += w + 10
    return B.svg_doc(W, H, f'{case["title"]}: {case["sub"]}', "".join(body))


for folder, case in CASES.items():
    out = ROOT / folder / "assets" / "banner.svg"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(banner(case), encoding="utf-8")
    print(out.relative_to(ROOT), f"{out.stat().st_size / 1024:.1f} KB")
