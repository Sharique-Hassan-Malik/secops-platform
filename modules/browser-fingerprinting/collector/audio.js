/**
 * AudioContext fingerprinting.
 *
 * The Web Audio API processes audio through the OS audio stack and DSP
 * implementation. Floating-point accumulation order, floating-point precision
 * and the specific DSP implementation used by each browser/OS combination
 * produce different numerical outputs from the same signal graph.
 *
 * We sum the absolute values of 3000 samples from an OscillatorNode routed
 * through a DynamicsCompressorNode. The resulting number is stable per
 * browser build and OS version.
 */

export async function collectAudio() {
  const result = { supported: false, hash: null, sampleSum: null, error: null }

  if (typeof AudioContext === "undefined" && typeof webkitAudioContext === "undefined") {
    result.error = "AudioContext not supported"
    return result
  }

  return new Promise(resolve => {
    const timeout = setTimeout(() => {
      result.error = "timeout"
      resolve(result)
    }, 3000)

    try {
      const Ctx = window.AudioContext || window.webkitAudioContext
      const ctx = new Ctx({ sampleRate: 44100 })

      const oscillator = ctx.createOscillator()
      const compressor = ctx.createDynamicsCompressor()
      const analyser   = ctx.createAnalyser()
      const dest       = ctx.createMediaStreamDestination()

      // Compressor settings that maximise numerical variation across implementations
      compressor.threshold.value = -50
      compressor.knee.value      = 40
      compressor.ratio.value     = 12
      compressor.attack.value    = 0
      compressor.release.value   = 0.25

      oscillator.type            = "triangle"
      oscillator.frequency.value = 10000

      oscillator.connect(compressor)
      compressor.connect(analyser)
      analyser.connect(dest)

      analyser.fftSize = 2048
      const buffer = new Float32Array(analyser.frequencyBinCount)

      oscillator.start(0)

      // Collect after a short delay so the pipeline has processed samples
      setTimeout(() => {
        analyser.getFloatFrequencyData(buffer)
        oscillator.stop()
        ctx.close()
        clearTimeout(timeout)

        // Sum the first 3000 non-(-Infinity) values
        let sum = 0
        let count = 0
        for (let i = 0; i < Math.min(buffer.length, 3000); i++) {
          if (isFinite(buffer[i])) {
            sum += Math.abs(buffer[i])
            count++
          }
        }

        result.supported  = true
        result.sampleSum  = count > 0 ? sum / count : 0
        result.hash       = _floatHash(result.sampleSum)
        resolve(result)
      }, 500)
    } catch (e) {
      clearTimeout(timeout)
      result.error = String(e)
      resolve(result)
    }
  })
}

function _floatHash(val) {
  // Encode float as hex string for stable comparison
  const buf = new ArrayBuffer(8)
  new Float64Array(buf)[0] = val
  const bytes = new Uint8Array(buf)
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("")
}
