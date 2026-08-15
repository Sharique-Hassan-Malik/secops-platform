/**
 * content.js — Page content script
 * Finds all archive download links and adds a shield badge next to them.
 */

const ARCHIVE_RE = /\.(zip|gz|bz2|tar|7z|xz|rar|zst|zstd|tgz|tbz2|jar|apk|pt|pth)(\?[^"]*)?$/i;

function addBadge(link) {
  if (link.dataset.zbdTagged) return;
  link.dataset.zbdTagged = '1';

  const badge = document.createElement('span');
  badge.textContent = '🛡';
  badge.title = 'ZIP Bomb Detector: Scan this archive before opening.';
  badge.style.cssText = [
    'display:inline-block',
    'margin-left:4px',
    'cursor:pointer',
    'font-size:0.85em',
    'opacity:0.7',
    'transition:opacity 0.15s',
    'vertical-align:middle',
  ].join(';');

  badge.addEventListener('mouseenter', () => badge.style.opacity = '1');
  badge.addEventListener('mouseleave', () => badge.style.opacity = '0.7');
  badge.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    chrome.runtime.sendMessage({ type: 'ARCHIVE_LINK_CLICKED', url: link.href });
    badge.textContent = '🛡✓';
    setTimeout(() => { badge.textContent = '🛡'; }, 2000);
  });

  link.insertAdjacentElement('afterend', badge);
}

function scanLinks() {
  document.querySelectorAll('a[href]').forEach(link => {
    if (ARCHIVE_RE.test(link.getAttribute('href') ?? '')) addBadge(link);
  });
}

scanLinks();
const observer = new MutationObserver(scanLinks);
observer.observe(document.body, { childList: true, subtree: true });
