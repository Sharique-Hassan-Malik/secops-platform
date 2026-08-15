/**
 * background.js  —  Service worker
 *
 * Two responsibilities:
 *   1. Listen for completed ZIP downloads → auto-scan via offscreen document
 *   2. Receive THREAT_DETECTED messages from popup → show notification
 */

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type !== 'THREAT_DETECTED') return;

  const topFlag = msg.flags?.[0] ?? 'Unknown';
  chrome.notifications.create({
    type:    'basic',
    iconUrl: 'icons/icon128.png',
    title:   `⚠ ZIP Bomb Detected — ${msg.threatLevel}`,
    message: `File: ${msg.filename}\nFlag: ${topFlag}`,
    priority: 2,
  });
});

// Watch for completed ZIP/archive downloads and badge the icon
chrome.downloads.onChanged.addListener((delta) => {
  if (!delta.state || delta.state.current !== 'complete') return;

  chrome.downloads.search({ id: delta.id }, ([item]) => {
    if (!item) return;
    const url = item.finalUrl || item.url || '';
    const isArchive = /\.(zip|gz|bz2)(\?.*)?$/i.test(url);
    if (!isArchive) return;

    // Badge the icon to prompt user to scan
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeBackgroundColor({ color: '#f97316' });
    chrome.action.setTitle({ title: 'ZIP Bomb Detector — ZIP download detected, click to scan' });

    // Clear badge after 30s
    setTimeout(() => {
      chrome.action.setBadgeText({ text: '' });
      chrome.action.setTitle({ title: 'ZIP Bomb Detector' });
    }, 30_000);
  });
});
