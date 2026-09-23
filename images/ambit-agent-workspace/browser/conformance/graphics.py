#!/usr/bin/env python3
"""Qualify actual WebGL pixels in the managed headed browser, without internet."""

import base64
from functools import partial
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

from PIL import Image
from browser import QuietHandler, capture_live_frame, invoke, native_display_evidence, renderer_sandbox_evidence


PAGE = """<!doctype html><html lang="en"><meta charset="utf-8">
<title>Browser graphics qualification</title><style>
body{margin:16px;background:#eee;color:#111;font:20px system-ui}
canvas{display:inline-block;margin-right:16px;width:256px;height:192px;background:#000}
</style><h1>WebGL rendering</h1><main></main><script>
window.graphics = [];
window.renderGraphics = () => {
  document.querySelector('main').replaceChildren();
  window.graphics = ['webgl','webgl2'].map(api => {
    const canvas=document.createElement('canvas'); canvas.width=256;canvas.height=192;
    document.querySelector('main').append(canvas);
    const gl=canvas.getContext(api,{preserveDrawingBuffer:true});
    if(!gl) return {api,available:false};
    const draw=() => {
      const modern=api==='webgl2';
      const vertex=modern?'#version 300 es\\nin vec2 p;void main(){gl_Position=vec4(p,0,1);}':'attribute vec2 p;void main(){gl_Position=vec4(p,0,1);}';
      const fragment=modern?'#version 300 es\\nprecision mediump float;out vec4 color;void main(){color=vec4(0,1,0,1);}':'precision mediump float;void main(){gl_FragColor=vec4(1,0,0,1);}';
      const shader=(kind,source)=>{const s=gl.createShader(kind);gl.shaderSource(s,source);gl.compileShader(s);if(!gl.getShaderParameter(s,gl.COMPILE_STATUS))throw Error(gl.getShaderInfoLog(s));return s;};
      const program=gl.createProgram();gl.attachShader(program,shader(gl.VERTEX_SHADER,vertex));gl.attachShader(program,shader(gl.FRAGMENT_SHADER,fragment));gl.linkProgram(program);if(!gl.getProgramParameter(program,gl.LINK_STATUS))throw Error(gl.getProgramInfoLog(program));gl.useProgram(program);
      const buffer=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,buffer);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,0,1]),gl.STATIC_DRAW);const position=gl.getAttribLocation(program,'p');gl.enableVertexAttribArray(position);gl.vertexAttribPointer(position,2,gl.FLOAT,false,0,0);
      gl.viewport(0,0,canvas.width,canvas.height);gl.clearColor(0,0,0,1);gl.clear(gl.COLOR_BUFFER_BIT);gl.drawArrays(gl.TRIANGLES,0,3);
      const pixel=new Uint8Array(4);gl.readPixels(canvas.width/2,canvas.height/2,1,1,gl.RGBA,gl.UNSIGNED_BYTE,pixel);return {pixel:Array.from(pixel),error:gl.getError(),width:canvas.width,height:canvas.height};
    };
    const ext=gl.getExtension('WEBGL_debug_renderer_info');
    return {api,available:true,canvas,gl,draw,initial:draw(),renderer:ext?gl.getParameter(ext.UNMASKED_RENDERER_WEBGL):null};
  });
  return window.graphics.map(({api,available,initial,renderer})=>({api,available,initial,renderer}));
};
window.resizeGraphics=()=>window.graphics.map(({api,canvas,draw})=>{canvas.width=192;canvas.height=128;return{api,...draw()};});
window.restoreGraphics=()=>Promise.all(window.graphics.map(({api,canvas,gl,draw})=>new Promise((resolve,reject)=>{
  const loss=gl.getExtension('WEBGL_lose_context');if(!loss){resolve({api,supported:false});return;}
  const timeout=setTimeout(()=>reject(Error('context recovery timed out')),5000);
  canvas.addEventListener('webglcontextlost',event=>{event.preventDefault();setTimeout(()=>loss.restoreContext(),0);},{once:true});
  canvas.addEventListener('webglcontextrestored',()=>{clearTimeout(timeout);resolve({api,supported:true,restored:draw()});},{once:true});
  loss.loseContext();
})));
</script></html>"""


def assert_pixels(values, key=None):
    assert len(values) == 2, values
    for value in values:
        observed = value[key] if key else value
        expected = [255, 0, 0, 255] if value["api"] == "webgl" else [0, 255, 0, 255]
        assert observed["pixel"] == expected and observed["error"] == 0, value


def main():
    assert os.geteuid() != 0, "Graphics qualification must run as the workspace user"
    session = f"graphics-{os.getpid()}"
    with tempfile.TemporaryDirectory(prefix="ambit-graphics-") as temporary:
        root = Path(temporary)
        (root / "index.html").write_text(PAGE)
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(root)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        daemon = subprocess.Popen(["agent-browser", "--session", session, "daemon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            from browser import wait_until
            socket = Path("/workspace/.ambit/browser/sockets") / f"{session}.sock"
            wait_until(lambda: socket.exists() or daemon.poll() is not None)
            assert daemon.poll() is None, "Browser daemon exited during startup"
            url = f"http://127.0.0.1:{server.server_port}/index.html"
            evidence = {"origin": url, "open": invoke(session, "open", url)}
            evidence["render"] = invoke(session, "eval", "renderGraphics()")['result']
            assert all(value["available"] for value in evidence["render"]), evidence["render"]
            assert_pixels(evidence["render"], "initial")
            evidence["display"] = native_display_evidence()
            evidence["sandbox"] = renderer_sandbox_evidence(daemon.pid)
            evidence["resize"] = invoke(session, "eval", "resizeGraphics()")['result']
            assert_pixels(evidence["resize"])
            evidence["recovery"] = invoke(session, "eval", "restoreGraphics()")['result']
            assert all(value["supported"] for value in evidence["recovery"]), evidence["recovery"]
            assert_pixels(evidence["recovery"], "restored")
            evidence["windowLayouts"] = [
                invoke(session, "set", "viewport", str(width), str(height))
                for width, height in ((800, 600), (1280, 720))
            ]
            invoke(session, "eval", "new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve(true))))")
            screenshot = root / "graphics.png"
            invoke(session, "screenshot", str(screenshot))
            raw = screenshot.read_bytes()
            with Image.open(screenshot) as image:
                counts = {"red": 0, "green": 0}
                for r, g, b in image.convert("RGB").getdata():
                    if r > 220 and g < 30 and b < 30:
                        counts["red"] += 1
                    if g > 220 and r < 30 and b < 30:
                        counts["green"] += 1
            assert min(counts.values()) > 1000, counts
            evidence["screenshot"] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "coloredPixels": counts, "base64": base64.b64encode(raw).decode()}
            frame = root / "graphics-window.jpg"
            evidence["liveFrame"] = capture_live_frame(session, frame)
            with Image.open(frame) as image:
                green = sum(g > 200 and r < 70 and b < 70 for r, g, b in image.convert("RGB").getdata())
            assert green > 1000, "WebGL pixels are absent from the actual native window stream"
            evidence["liveFrame"]["greenPixels"] = green
            evidence["liveFrame"]["base64"] = base64.b64encode(frame.read_bytes()).decode()
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
