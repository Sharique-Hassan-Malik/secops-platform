/**
 * Canvas fingerprinting.
 *
 * Different GPU drivers, OS font renderers and anti-aliasing stacks produce
 * subtly different pixel values when drawing the same text and geometry. The
 * resulting data URL is a stable per-device identifier even across private
 * browsing sessions.
 */

export function collectCanvas() {
  const result = { supported: false, hash: null, dataUrl: null, error: null }

  try {
    const canvas = document.createElement("canvas")
    canvas.width  = 280
    canvas.height = 60
    const ctx = canvas.getContext("2d")
    if (!ctx) {
      result.error = "no 2d context"
      return result
    }

    // Background
    ctx.fillStyle = "#f0f0f0"
    ctx.fillRect(0, 0, canvas.width, canvas.height)

    // Text rendering — the exact pixel values depend on font hinting and
    // sub-pixel rendering, which varies by OS and GPU driver.
    ctx.fillStyle   = "#069"
    ctx.font        = "11pt no-real-font,Arial"
    ctx.textBaseline = "alphabetic"
    ctx.fillText("Browser fingerprint \u2603 \u0CA0_\u0CA0 Cwm fjordbank", 2, 15)

    ctx.fillStyle = "rgba(102, 204, 0, 0.75)"
    ctx.font      = "18pt Arial"
    ctx.fillText("Browser fingerprint", 4, 45)

    // Geometry — arc rendering also varies
    ctx.beginPath()
    ctx.arc(260, 30, 18, 0, Math.PI * 2, true)
    ctx.fillStyle = "rgba(255, 0, 255, 0.5)"
    ctx.fill()

    ctx.beginPath()
    ctx.arc(245, 20, 10, 0, Math.PI, false)
    ctx.strokeStyle = "#00f"
    ctx.lineWidth   = 1
    ctx.stroke()

    const dataUrl = canvas.toDataURL()
    result.supported = true
    result.dataUrl   = dataUrl
    result.hash      = _djb2(dataUrl)
  } catch (e) {
    result.error = String(e)
  }

  return result
}

function _djb2(str) {
  let hash = 5381
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash) ^ str.charCodeAt(i)
    hash |= 0  // convert to 32-bit int
  }
  return (hash >>> 0).toString(16)
}
