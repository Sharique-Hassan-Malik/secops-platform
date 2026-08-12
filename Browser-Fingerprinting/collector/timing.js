/**
 * Timing and performance fingerprinting.
 *
 * Hardware differences (CPU speed, memory bandwidth, GPU) produce measurable
 * variance in JavaScript execution timing. We capture:
 *
 *  - performance.now() resolution (do values increment in steps > 1 µs?)
 *  - Math operation timing (reflects CPU microarchitecture)
 *  - DOM operation timing
 *  - Date.getTimezoneOffset() — the local UTC offset
 *  - navigator properties
 *
 * Note: browsers intentionally add jitter to performance.now() to mitigate
 * timing attacks. The resolution itself (step size) remains a fingerprinting
 * signal because it is set based on browser security level (cross-origin
 * isolation state), not randomised per call.
 */

export function collectTiming() {
  return {
    timezoneOffset:   new Date().getTimezoneOffset(),
    timezone:         _timezone(),
    clockResolution:  _clockResolution(),
    mathTimingHash:   _mathTiming(),
    domTimingMs:      _domTiming(),
    hardwareConcurrency: navigator.hardwareConcurrency ?? null,
    deviceMemoryGB:   navigator.deviceMemory ?? null,
    platform:         navigator.platform ?? null,
    userAgent:        navigator.userAgent ?? null,
    language:         navigator.language ?? null,
    languages:        Array.from(navigator.languages ?? []),
    cookieEnabled:    navigator.cookieEnabled,
    doNotTrack:       navigator.doNotTrack ?? null,
    maxTouchPoints:   navigator.maxTouchPoints ?? 0,
    screenWidth:      screen.width,
    screenHeight:     screen.height,
    screenDepth:      screen.colorDepth,
    screenPixelRatio: window.devicePixelRatio ?? 1,
    availWidth:       screen.availWidth,
    availHeight:      screen.availHeight,
    innerWidth:       window.innerWidth,
    innerHeight:      window.innerHeight,
  }
}

function _timezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone
  } catch {
    return null
  }
}

function _clockResolution() {
  // Measure the smallest observable increment of performance.now()
  const samples = []
  for (let i = 0; i < 50; i++) {
    let t0 = performance.now()
    let t1 = t0
    while (t1 === t0) t1 = performance.now()
    samples.push(t1 - t0)
  }
  samples.sort((a, b) => a - b)
  return samples[Math.floor(samples.length / 2)]   // median
}

function _mathTiming() {
  // Run a mixed-precision computation and time it.
  // The result encodes both the timing bucket and a checksum of the output
  // (which can differ by CPU due to fused multiply-add differences).
  const t0  = performance.now()
  let acc   = 0
  const N   = 50_000
  for (let i = 0; i < N; i++) {
    acc += Math.sin(i) * Math.cos(i) + Math.sqrt(i + 1)
  }
  const elapsed = performance.now() - t0

  // Combine timing bucket and output hash into one number
  const timingBucket = Math.floor(elapsed / 5)       // 5 ms buckets
  const outputHash   = Math.abs(Math.floor(acc)) % 1000
  return timingBucket * 10000 + outputHash
}

function _domTiming() {
  const t0  = performance.now()
  const div = document.createElement("div")
  for (let i = 0; i < 200; i++) {
    const el = document.createElement("span")
    el.textContent = "x"
    div.appendChild(el)
  }
  document.body.appendChild(div)
  const _h = div.offsetHeight  // force reflow
  document.body.removeChild(div)
  return parseFloat((performance.now() - t0).toFixed(3))
}
