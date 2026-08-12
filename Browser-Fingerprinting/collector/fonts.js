/**
 * Font detection via glyph width measurement.
 *
 * If a requested font is installed, the browser uses its metrics; otherwise
 * it falls back to a generic font. We measure the rendered width of a test
 * string in each candidate font. A width that differs from the fallback width
 * indicates the font is present.
 *
 * This technique requires no canvas — it works with a hidden DOM element —
 * but it is noisier than canvas measurement. We therefore use three different
 * fallback fonts (monospace, serif, sans-serif) and require agreement between
 * at least two for a positive detection.
 */

const FALLBACKS = ["monospace", "serif", "sans-serif"]

const CANDIDATES = [
  "Arial", "Arial Black", "Arial Narrow", "Arial Rounded MT Bold",
  "Bookman Old Style", "Bradley Hand ITC", "Century", "Century Gothic",
  "Comic Sans MS", "Courier", "Courier New", "Georgia",
  "Gentium", "Impact", "King", "Lucida Console",
  "Lalit", "Modena", "Monotype Corsiva", "Papyrus",
  "Tahoma", "TeX", "Times", "Times New Roman",
  "Trebuchet MS", "Verdana", "Verona",
  // macOS
  "SF Pro Display", "Helvetica Neue", "Avenir",
  // Linux
  "DejaVu Sans", "Ubuntu", "Liberation Sans",
  // Windows
  "Calibri", "Cambria", "Segoe UI", "Consolas",
]

const TEST_STRING = "mmmmmmmmmmlli"
const TEST_SIZE   = "72px"

function _measureWidth(fontFamily, container) {
  const span = document.createElement("span")
  span.style.cssText  = `position:absolute;visibility:hidden;width:auto;height:auto;font-size:${TEST_SIZE};`
  span.style.fontFamily = fontFamily
  span.innerText      = TEST_STRING
  container.appendChild(span)
  const w = span.offsetWidth
  container.removeChild(span)
  return w
}

export function collectFonts() {
  const result = { detected: [], tested: CANDIDATES.length, error: null }

  try {
    const container = document.createElement("div")
    container.style.cssText = "position:absolute;left:-9999px;top:-9999px;"
    document.body.appendChild(container)

    // Measure fallback widths
    const fallbackWidths = FALLBACKS.map(f => _measureWidth(f, container))

    for (const font of CANDIDATES) {
      let matches = 0
      for (let i = 0; i < FALLBACKS.length; i++) {
        const w = _measureWidth(`'${font}',${FALLBACKS[i]}`, container)
        if (w !== fallbackWidths[i]) matches++
      }
      if (matches >= 2) {
        result.detected.push(font)
      }
    }

    document.body.removeChild(container)
  } catch (e) {
    result.error = String(e)
  }

  return result
}
