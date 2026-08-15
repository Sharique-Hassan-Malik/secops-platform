/**
 * WebGL fingerprinting.
 *
 * The RENDERER and VENDOR strings expose the physical GPU and driver version.
 * Supported extension lists and numeric parameter limits further differentiate
 * devices with the same GPU but different driver versions or OS configurations.
 *
 * WEBGL_debug_renderer_info is intentionally queried — browsers permit it
 * but it leaks the underlying GPU string rather than a generic string.
 */

export function collectWebGL() {
  const result = {
    supported: false,
    vendor:         null,
    renderer:       null,
    unmaskedVendor:   null,
    unmaskedRenderer: null,
    version:        null,
    shadingVersion: null,
    extensions:     [],
    parameters:     {},
    imageHash:      null,
    error:          null,
  }

  try {
    const canvas = document.createElement("canvas")
    const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl")
    if (!gl) {
      result.error = "WebGL not supported"
      return result
    }

    result.supported      = true
    result.vendor         = gl.getParameter(gl.VENDOR)
    result.renderer       = gl.getParameter(gl.RENDERER)
    result.version        = gl.getParameter(gl.VERSION)
    result.shadingVersion = gl.getParameter(gl.SHADING_LANGUAGE_VERSION)

    // Unmasked strings (more specific — GPU model + driver)
    const dbg = gl.getExtension("WEBGL_debug_renderer_info")
    if (dbg) {
      result.unmaskedVendor   = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)
      result.unmaskedRenderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)
    }

    // Extension list — sorted for stability
    result.extensions = (gl.getSupportedExtensions() || []).sort()

    // Numeric parameters that vary by GPU/driver
    const params = [
      ["MAX_TEXTURE_SIZE",                gl.MAX_TEXTURE_SIZE],
      ["MAX_VIEWPORT_DIMS",               gl.MAX_VIEWPORT_DIMS],
      ["MAX_VERTEX_ATTRIBS",             gl.MAX_VERTEX_ATTRIBS],
      ["MAX_VERTEX_UNIFORM_VECTORS",     gl.MAX_VERTEX_UNIFORM_VECTORS],
      ["MAX_FRAGMENT_UNIFORM_VECTORS",   gl.MAX_FRAGMENT_UNIFORM_VECTORS],
      ["MAX_VARYING_VECTORS",            gl.MAX_VARYING_VECTORS],
      ["MAX_COMBINED_TEXTURE_IMAGE_UNITS", gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS],
      ["MAX_CUBE_MAP_TEXTURE_SIZE",      gl.MAX_CUBE_MAP_TEXTURE_SIZE],
      ["MAX_RENDERBUFFER_SIZE",          gl.MAX_RENDERBUFFER_SIZE],
      ["ALIASED_LINE_WIDTH_RANGE",       gl.ALIASED_LINE_WIDTH_RANGE],
      ["ALIASED_POINT_SIZE_RANGE",       gl.ALIASED_POINT_SIZE_RANGE],
    ]
    for (const [name, constant] of params) {
      const val = gl.getParameter(constant)
      result.parameters[name] = val instanceof Float32Array || val instanceof Int32Array
        ? Array.from(val)
        : val
    }

    // WebGL rendering — same principle as canvas: pixel values differ by GPU
    canvas.width  = 256
    canvas.height = 256
    _drawScene(gl)
    result.imageHash = _hashPixels(gl, canvas)
  } catch (e) {
    result.error = String(e)
  }

  return result
}

function _drawScene(gl) {
  const vSrc = `
    attribute vec2 pos;
    void main() { gl_Position = vec4(pos, 0.0, 1.0); }
  `
  const fSrc = `
    precision mediump float;
    void main() { gl_FragColor = vec4(0.2, 0.8, 0.4, 1.0); }
  `
  const vs = _shader(gl, gl.VERTEX_SHADER,   vSrc)
  const fs = _shader(gl, gl.FRAGMENT_SHADER, fSrc)
  if (!vs || !fs) return

  const prog = gl.createProgram()
  gl.attachShader(prog, vs)
  gl.attachShader(prog, fs)
  gl.linkProgram(prog)
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return
  gl.useProgram(prog)

  const vertices = new Float32Array([-0.7, -0.7,  0.7, -0.7,  0.0,  0.7])
  const buf = gl.createBuffer()
  gl.bindBuffer(gl.ARRAY_BUFFER, buf)
  gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW)

  const loc = gl.getAttribLocation(prog, "pos")
  gl.enableVertexAttribArray(loc)
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0)

  gl.clearColor(0.1, 0.1, 0.1, 1.0)
  gl.clear(gl.COLOR_BUFFER_BIT)
  gl.drawArrays(gl.TRIANGLES, 0, 3)
}

function _shader(gl, type, src) {
  const s = gl.createShader(type)
  gl.shaderSource(s, src)
  gl.compileShader(s)
  return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null
}

function _hashPixels(gl, canvas) {
  try {
    const px = new Uint8Array(canvas.width * canvas.height * 4)
    gl.readPixels(0, 0, canvas.width, canvas.height, gl.RGBA, gl.UNSIGNED_BYTE, px)
    let hash = 5381
    for (let i = 0; i < px.length; i += 4) {
      hash = ((hash << 5) + hash) ^ px[i]
      hash |= 0
    }
    return (hash >>> 0).toString(16)
  } catch (e) {
    return null
  }
}
