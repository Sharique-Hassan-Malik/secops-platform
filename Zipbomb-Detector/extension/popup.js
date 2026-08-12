import { scanArchive, fmtBytes, ThreatLevel, POLICIES } from './scanner.js';

const dropZone    = document.getElementById('drop-zone');
const fileInput   = document.getElementById('file-input');
const resultEl    = document.getElementById('result');
const spinner     = document.getElementById('spinner');
const rescanBtn   = document.getElementById('rescan-btn');
const policySelect= document.getElementById('policy-select');

// Restore last used policy
chrome.storage.local.get(['policy'], ({ policy }) => {
  if (policy) policySelect.value = policy;
});
policySelect.addEventListener('change', () => {
  chrome.storage.local.set({ policy: policySelect.value });
});

// Drop zone interactions
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', ()  => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) processFile(file);
});
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) processFile(fileInput.files[0]);
});
rescanBtn.addEventListener('click', reset);

function reset() {
  resultEl.style.display = 'none';
  resultEl.innerHTML     = '';
  dropZone.style.display = 'block';
  rescanBtn.style.display= 'none';
  fileInput.value        = '';
}

async function processFile(file) {
  dropZone.style.display  = 'none';
  spinner.style.display   = 'block';
  rescanBtn.style.display = 'none';

  await new Promise(r => setTimeout(r, 30)); // let spinner paint

  try {

    const policy = POLICIES[policySelect.value] ?? POLICIES.default;
    const result = await scanArchive(file, policy);
    spinner.style.display = 'none';
    renderResult(file.name, file.size, result);
  } catch (err) {
    spinner.style.display = 'none';
    renderError(err.message);
  }
}

function renderResult(filename, fileSize, r) {
  const lvl     = ThreatLevel.name(r.threatLevel);
  const topFlags= r.flags.slice(0, 6);
  const showEntries = r.entries.slice(0, 8);

  resultEl.innerHTML = `
    <div class="result-header">
      <div class="threat-dot dot-${lvl}"></div>
      <span class="level-${lvl}">${lvl}</span>
      <span style="color:var(--muted);font-weight:400;font-size:12px;margin-left:4px">— ${escHtml(filename)}</span>
      <span style="margin-left:auto;background:var(--border);color:var(--muted);font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;text-transform:uppercase">${(r.fmt||'zip').replace('.','·')}</span>
    </div>

    <div class="result-grid">
      <div class="stat">
        <div class="label">File size</div>
        <div class="value">${fmtBytes(fileSize)}</div>
      </div>
      <div class="stat">
        <div class="label">Entries</div>
        <div class="value">${r.entryCount.toLocaleString()}</div>
      </div>
      <div class="stat">
        <div class="label">Compressed</div>
        <div class="value">${fmtBytes(r.totalCompressed)}</div>
      </div>
      <div class="stat">
        <div class="label">Declared expanded</div>
        <div class="value">${fmtBytes(r.totalUncompressed)}</div>
      </div>
      <div class="stat">
        <div class="label">Compression ratio</div>
        <div class="value ${r.overallRatio > 50 ? 'level-CRITICAL' : r.overallRatio > 10 ? 'level-HIGH' : ''}">${r.overallRatio >= 1 ? r.overallRatio.toFixed(1) + ' : 1' : '—'}</div>
      </div>
      <div class="stat">
        <div class="label">Overlapping regions</div>
        <div class="value ${r.hasOverlaps ? 'level-CRITICAL' : ''}">${r.hasOverlaps ? 'YES ⚠' : 'No'}</div>
      </div>
      <div class="stat">
        <div class="label">Scan time</div>
        <div class="value">${r.scanMs} ms</div>
      </div>
      <div class="stat">
        <div class="label">Policy</div>
        <div class="value">${policySelect.options[policySelect.selectedIndex].text.split(' ')[0]}</div>
      </div>
    </div>

    ${topFlags.length ? `
    <div class="flags-section">
      <div class="flags-title">Detection flags</div>
      ${topFlags.map(f => `
        <div class="flag-item">
          <span class="flag-badge badge-${f.levelName}">${f.levelName}</span>
          <span>${escHtml(f.description)}</span>
        </div>
      `).join('')}
    </div>` : ''}

    ${showEntries.length ? `
    <div class="entries-section" id="entries-section">
      <div class="entries-title">
        <span>Entries (${r.entryCount})</span>
        <button id="toggle-entries">Hide</button>
      </div>
      <table class="entry-table">
        <tr>
          <th>Name</th><th>Ratio</th><th>Expanded</th>
        </tr>
        ${showEntries.map(e => `
          <tr class="${e.ratio > 100 ? 'flagged' : ''}">
            <td title="${escHtml(e.name)}">${escHtml(truncate(e.name, 28))}</td>
            <td>${e.ratio > 0 ? e.ratio.toFixed(1) + 'x' : '—'}</td>
            <td>${fmtBytes(e.uncompSz)}</td>
          </tr>
        `).join('')}
        ${r.entryCount > 8 ? `<tr><td colspan="3" style="color:var(--muted);padding:4px 14px">…and ${r.entryCount - 8} more</td></tr>` : ''}
      </table>
    </div>` : ''}
  `;

  document.getElementById('toggle-entries')?.addEventListener('click', function() {
    const sec = document.getElementById('entries-section');
    const collapsed = sec.classList.toggle('entries-collapsed');
    this.textContent = collapsed ? 'Show' : 'Hide';
  });

  resultEl.style.display  = 'block';
  rescanBtn.style.display = 'block';

  // Notify background if critical
  if (r.threatLevel >= ThreatLevel.CRITICAL) {
    chrome.runtime.sendMessage({
      type: 'THREAT_DETECTED',
      filename,
      threatLevel: lvl,
      flags: r.flags.map(f => f.code),
    });
  }
}

function renderError(msg) {
  resultEl.innerHTML = `
    <div class="result-header">
      <div class="threat-dot dot-MEDIUM"></div>
      <span class="level-MEDIUM">SCAN ERROR</span>
    </div>
    <div class="stat" style="grid-column:1/-1;padding:12px 14px">
      <div class="label">Error</div>
      <div class="value" style="color:var(--muted);font-size:12px">${escHtml(msg)}</div>
    </div>
  `;
  resultEl.style.display  = 'block';
  rescanBtn.style.display = 'block';
}

const escHtml = s => s.replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const truncate = (s, n) => s.length > n ? '…' + s.slice(-(n-1)) : s;
