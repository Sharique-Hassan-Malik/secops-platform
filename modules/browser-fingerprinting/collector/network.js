/**
 * Network and media device fingerprinting.
 *
 * - navigator.connection exposes network type and bandwidth estimate
 * - MediaDevices.enumerateDevices() lists audio/video hardware labels
 *   (labels are blank without camera/mic permission, but device counts
 *   and groupId structure still vary by hardware)
 * - RTCPeerConnection ice candidate gathering reveals local network
 *   interface types (Ethernet, WiFi, VPN, loopback)
 * - Battery API — capacity and charging state vary by device
 */

export async function collectNetwork() {
  const result = {
    connectionType:        null,
    effectiveType:         null,
    downlink:              null,
    rtt:                   null,
    mediaDeviceCounts:     null,
    mediaDeviceGroupIds:   [],
    iceCandidateTypes:     [],
    batteryCharging:       null,
    batteryLevel:          null,
    error:                 null,
  }

  try {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection
    if (conn) {
      result.connectionType = conn.type        ?? null
      result.effectiveType  = conn.effectiveType ?? null
      result.downlink       = conn.downlink      ?? null
      result.rtt            = conn.rtt           ?? null
    }
  } catch { /* ignored */ }

  // Media device enumeration
  try {
    if (navigator.mediaDevices?.enumerateDevices) {
      const devices = await navigator.mediaDevices.enumerateDevices()
      const counts  = { audioinput: 0, audiooutput: 0, videoinput: 0 }
      const groupIds = new Set()
      for (const d of devices) {
        if (d.kind in counts) counts[d.kind]++
        if (d.groupId) groupIds.add(d.groupId)
      }
      result.mediaDeviceCounts   = counts
      result.mediaDeviceGroupIds = Array.from(groupIds).sort()
    }
  } catch { /* ignored */ }

  // ICE candidate types — reveals which network interfaces exist
  try {
    const types = await _gatherIceCandidateTypes()
    result.iceCandidateTypes = types
  } catch { /* ignored */ }

  // Battery API (deprecated but still present in Chrome/Firefox)
  try {
    if (navigator.getBattery) {
      const battery = await navigator.getBattery()
      result.batteryCharging = battery.charging
      result.batteryLevel    = battery.level
    }
  } catch { /* ignored */ }

  return result
}

async function _gatherIceCandidateTypes() {
  return new Promise(resolve => {
    const types = new Set()
    const timeout = setTimeout(() => resolve(Array.from(types)), 2000)

    try {
      const pc = new RTCPeerConnection({ iceServers: [] })
      pc.createDataChannel("")

      pc.onicecandidate = e => {
        if (!e.candidate) {
          clearTimeout(timeout)
          pc.close()
          resolve(Array.from(types).sort())
          return
        }
        // candidate type: host, srflx (server reflexive), relay
        const m = e.candidate.candidate.match(/typ (\w+)/)
        if (m) types.add(m[1])
      }

      pc.createOffer().then(o => pc.setLocalDescription(o)).catch(() => {
        clearTimeout(timeout)
        resolve(Array.from(types))
      })
    } catch {
      clearTimeout(timeout)
      resolve([])
    }
  })
}
