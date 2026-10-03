#!/usr/bin/env python3
"""Qualify that Chinese, Japanese, Korean and emoji text renders in the workspace, without internet.

fontconfig must cover each script with an installed font (colour, for emoji), which every fontconfig client uses:
Chrome, LibreOffice and the PDF renderers. The managed headed browser must then rasterize them: two different Han
characters must give two different pictures (a missing glyph draws the same box for both), and an emoji must draw in
colour.
"""

from functools import partial
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

from browser import QuietHandler, invoke, wait_until

# Code points each script must cover, and whether its font must be a colour font.
COVERAGE = {"han": ("4e2d", False), "kana": ("3042", False), "hangul": ("d55c", False), "emoji": ("1f600", True)}

PAGE = """<!doctype html><html lang="en"><meta charset="utf-8"><title>Font qualification</title><script>
window.glyphs = () => Object.fromEntries(Object.entries({
  han: '\\u4e2d', han2: '\\u56fd', kana: '\\u3042', hangul: '\\ud55c', emoji: '\\u{1f600}'
}).map(([name, text]) => {
  const canvas = document.createElement('canvas'); canvas.width = canvas.height = 64;
  const context = canvas.getContext('2d', {willReadFrequently: true});
  context.fillStyle = '#fff'; context.fillRect(0, 0, 64, 64);
  context.font = '48px sans-serif'; context.textBaseline = 'top'; context.fillStyle = '#000';
  context.fillText(text, 4, 4);
  const data = context.getImageData(0, 0, 64, 64).data;
  let ink = 0, colour = 0, hash = 0;
  for (let i = 0; i < data.length; i += 4) {
    const [r, g, b] = [data[i], data[i + 1], data[i + 2]];
    if (r < 250 || g < 250 || b < 250) ink++;
    if (Math.max(r, g, b) - Math.min(r, g, b) > 60) colour++;
    hash = (hash * 31 + r * 3 + g * 5 + b * 7) >>> 0;
  }
  return [name, {ink, colour, hash}];
}));
</script>"""


def coverage():
    """The families fontconfig resolves each script's code point to."""
    families = {}
    for script, (codepoint, colour) in COVERAGE.items():
        pattern = f":charset={codepoint}" + (":color=true" if colour else "")
        listed = subprocess.run(["fc-list", pattern, "family"], text=True, capture_output=True, check=True).stdout
        families[script] = sorted({line.split(",")[0] for line in listed.splitlines() if line})
    return families


def assert_rasterized(glyphs):
    assert all(glyphs[name]["ink"] > 100 for name in glyphs), glyphs
    distinct = {glyphs[name]["hash"] for name in ("han", "han2", "kana", "hangul")}
    assert len(distinct) == 4, f"CJK characters draw the same picture (a missing glyph's box): {glyphs}"
    assert glyphs["emoji"]["colour"] > 200, f"the emoji is not drawn in colour: {glyphs['emoji']}"


def main():
    assert os.geteuid() != 0, "Font qualification must run as the workspace user"
    evidence = {"coverage": coverage()}
    assert all(evidence["coverage"].values()), evidence["coverage"]
    session = f"fonts-{os.getpid()}"
    with tempfile.TemporaryDirectory(prefix="ambit-fonts-") as temporary:
        root = Path(temporary)
        (root / "index.html").write_text(PAGE)
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(root)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        daemon = subprocess.Popen(["agent-browser", "--session", session, "daemon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            socket = Path("/workspace/.ambit/browser/sockets") / f"{session}.sock"
            wait_until(lambda: socket.exists() or daemon.poll() is not None)
            assert daemon.poll() is None, "Browser daemon exited during startup"
            url = f"http://127.0.0.1:{server.server_port}/index.html"
            evidence["open"] = invoke(session, "open", url)
            evidence["glyphs"] = invoke(session, "eval", "glyphs()")["result"]
            assert_rasterized(evidence["glyphs"])
            evidence["status"] = "passed"
            print(json.dumps(evidence))
        finally:
            try:
                invoke(session, "close")
            except Exception:
                daemon.terminate()
            daemon.wait(timeout=10)
            server.shutdown()


if __name__ == "__main__":
    main()
