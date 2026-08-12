/**
 * Browser Fingerprint Collector
 *
 * Collects all fingerprint signals from the current browser and submits them
 * to the analysis server. Each component is collected independently so a
 * failure in one (e.g. WebGL blocked by extension) does not affect the others.
 *
 * The collected object is posted to /api/collect as JSON and the assigned
 * fingerprint ID is stored in sessionStorage for the duration of the session.
 */

import { collectCanvas }  from "./canvas.js"
import { collectWebGL }   from "./webgl.js"
import { collectAudio }   from "./audio.js"
import { collectFonts }   from "./fonts.js"
import { collectTiming }  from "./timing.js"
import { collectNetwork } from "./network.js"


export async function collect() {
  const startTime = performance.now()

  const [audio, network] = await Promise.all([
    collectAudio().catch(e => ({ error: String(e) })),
    collectNetwork().catch(e => ({ error: String(e) })),
  ])

  const canvas  = collectCanvas()
  const webgl   = collectWebGL()
  const fonts   = collectFonts()
  const timing  = collectTiming()

  const fingerprint = {
    collected_at:  new Date().toISOString(),
    collection_ms: parseFloat((performance.now() - startTime).toFixed(2)),
    canvas,
    webgl,
    audio,
    fonts,
    timing,
    network,
  }

  return fingerprint
}


export async function collectAndSubmit(apiBase = "") {
  const fp   = await collect()
  let fpId   = null
  let error  = null

  try {
    const resp = await fetch(`${apiBase}/api/collect`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(fp),
    })
    const data = await resp.json()
    fpId = data.fingerprint_id ?? null
    if (fpId) {
      sessionStorage.setItem("fp_id", String(fpId))
    }
  } catch (e) {
    error = String(e)
  }

  return { fingerprint: fp, fingerprint_id: fpId, error }
}


// Run automatically when loaded as a plain <script> tag in non-module mode
if (typeof window !== "undefined" && !window.__fpCollectorLoaded) {
  window.__fpCollectorLoaded = true
  window.fpCollect = collect
  window.fpCollectAndSubmit = collectAndSubmit
}
