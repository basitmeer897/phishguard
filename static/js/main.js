/* ============================================================
   PhishGuard — Frontend Logic
   ============================================================ */

'use strict';

// ----------------------------------------------------------------
// DOM refs
// ----------------------------------------------------------------
const urlInput        = document.getElementById('urlInput');
const analyzeBtn      = document.getElementById('analyzeBtn');
const btnText         = analyzeBtn.querySelector('.btn-text');
const btnSpinner      = document.getElementById('btnSpinner');
const clearBtn        = document.getElementById('clearBtn');
const resultsArea     = document.getElementById('resultsArea');
const loadingOverlay  = document.getElementById('loadingOverlay');
const modelBadge      = document.getElementById('modelBadge');

// Verdict
const verdictBanner   = document.getElementById('verdictBanner');
const verdictLabel    = document.getElementById('verdictLabel');
const verdictUrl      = document.getElementById('verdictUrl');
const verdictTime     = document.getElementById('verdictTime');
const verdictIcon     = document.getElementById('verdictIcon');

// ML
const mlVerdict       = document.getElementById('mlVerdict');
const mlModelName     = document.getElementById('mlModelName');
const gaugeFill       = document.getElementById('gaugeFill');
const gaugePct        = document.getElementById('gaugePct');
const probLegit       = document.getElementById('probLegit');
const probPhish       = document.getElementById('probPhish');

// Security
const riskDot         = document.getElementById('riskDot');
const riskScore       = document.getElementById('riskScore');
const riskLabel       = document.getElementById('riskLabel');
const flagsWrap       = document.getElementById('flagsWrap');
const flagsList       = document.getElementById('flagsList');
const checkDNSVal     = document.getElementById('checkDNSVal');
const checkSSLVal     = document.getElementById('checkSSLVal');
const checkHTTPSVal   = document.getElementById('checkHTTPSVal');
const checkRedirectVal= document.getElementById('checkRedirectVal');
const checkPhishtankVal=document.getElementById('checkPhishtankVal');
const checkDomainVal  = document.getElementById('checkDomainVal');

// Features
const featuresBody    = document.getElementById('featuresBody');

// Recommendation
const recBody         = document.getElementById('recBody');

// Loading steps
const lsteps = [1,2,3,4,5].map(i => document.getElementById(`lstep${i}`));

// ----------------------------------------------------------------
// Fetch model info on load
// ----------------------------------------------------------------
async function fetchModelInfo() {
  try {
    const res = await fetch('/api/model-info');
    if (!res.ok) throw new Error();
    const data = await res.json();
    modelBadge.textContent = `Model: ${data.model || 'Loaded'}`;
  } catch {
    modelBadge.textContent = 'Model: Not trained';
  }
}
fetchModelInfo();

// ----------------------------------------------------------------
// Loading step animation
// ----------------------------------------------------------------
let stepTimer = null;
function startLoadingSteps() {
  let idx = 0;
  lsteps.forEach(s => s.classList.remove('active'));
  lsteps[0].classList.add('active');

  stepTimer = setInterval(() => {
    idx++;
    if (idx < lsteps.length) {
      lsteps[idx - 1].classList.remove('active');
      lsteps[idx].classList.add('active');
    }
  }, 1800);
}
function stopLoadingSteps() {
  clearInterval(stepTimer);
  lsteps.forEach(s => s.classList.remove('active'));
}

// ----------------------------------------------------------------
// Icon paths
// ----------------------------------------------------------------
const ICONS = {
  phishing: `<circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2.5" fill="none"/>
             <line x1="15" y1="9" x2="9" y2="15" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
             <line x1="9" y1="9" x2="15" y2="15" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>`,
  legitimate: `<circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2.5" fill="none"/>
               <polyline points="7 12 10.5 15.5 17 9" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>`,
  suspicious: `<circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2.5" fill="none"/>
               <line x1="12" y1="8" x2="12" y2="13" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
               <circle cx="12" cy="16" r="1" fill="currentColor"/>`
};

const VERDICT_COLORS = {
  PHISHING:   'var(--danger)',
  LEGITIMATE: 'var(--safe)',
  SUSPICIOUS: 'var(--warn)',
};

// ----------------------------------------------------------------
// Feature metadata for the table
// ----------------------------------------------------------------
const FEATURE_META = {
  URLLength:             { label: 'URL Length',              risk: v => v > 100 ? 'danger' : v > 60 ? 'warn' : 'safe', unit: 'chars' },
  DomainLength:          { label: 'Domain Length',           risk: v => v > 30 ? 'warn' : 'safe' },
  IsDomainIP:            { label: 'Domain is IP',            risk: v => v ? 'danger' : 'safe', fmt: v => v ? 'Yes' : 'No' },
  NoOfSubDomain:         { label: 'Subdomains',              risk: v => v >= 3 ? 'danger' : v >= 2 ? 'warn' : 'safe' },
  IsHTTPS:               { label: 'Uses HTTPS',              risk: v => v ? 'safe' : 'danger', fmt: v => v ? 'Yes' : 'No' },
  HasAtSign:             { label: 'Contains @ Sign',         risk: v => v ? 'danger' : 'safe', fmt: v => v ? 'Yes' : 'No' },
  HyphenInDomain:        { label: 'Hyphen in Domain',        risk: v => v ? 'warn' : 'safe', fmt: v => v ? 'Yes' : 'No' },
  IsSuspiciousTLD:       { label: 'Suspicious TLD',          risk: v => v ? 'danger' : 'safe', fmt: v => v ? 'Yes' : 'No' },
  IsShorteningService:   { label: 'URL Shortener',           risk: v => v ? 'danger' : 'safe', fmt: v => v ? 'Yes' : 'No' },
  HasPhishingKeyword:    { label: 'Phishing Keywords',       risk: v => v ? 'danger' : 'safe', fmt: v => v ? 'Yes' : 'No' },
  NoOfPhishingKeywords:  { label: '# Phishing Keywords',     risk: v => v >= 3 ? 'danger' : v >= 1 ? 'warn' : 'safe' },
  HasBrandInSubdomain:   { label: 'Brand in Subdomain',      risk: v => v ? 'danger' : 'safe', fmt: v => v ? 'Yes' : 'No' },
  HasObfuscation:        { label: 'URL Obfuscation',         risk: v => v ? 'danger' : 'safe', fmt: v => v ? 'Yes' : 'No' },
  NoOfObfuscatedChar:    { label: 'Obfuscated Chars',        risk: v => v > 0 ? 'warn' : 'safe' },
  URLEntropy:            { label: 'URL Entropy',             risk: v => v > 4.5 ? 'warn' : 'safe', fmt: v => v.toFixed(3) },
  DegitRatioInURL:       { label: 'Digit Ratio',             risk: v => v > 0.3 ? 'warn' : 'safe', fmt: v => (v*100).toFixed(1)+'%' },
  SpacialCharRatioInURL: { label: 'Special Char Ratio',      risk: v => v > 0.1 ? 'warn' : 'safe', fmt: v => (v*100).toFixed(1)+'%' },
  NoOfDots:              { label: 'Dots in URL',             risk: v => v > 5 ? 'warn' : 'safe' },
  HasPort:               { label: 'Non-standard Port',       risk: v => v ? 'warn' : 'safe', fmt: v => v ? 'Yes' : 'No' },
  PathDepth:             { label: 'URL Path Depth',          risk: v => v > 6 ? 'warn' : 'safe' },
  HasSuspiciousExtension:{ label: 'Suspicious Extension',    risk: v => v ? 'danger' : 'safe', fmt: v => v ? 'Yes' : 'No' },
};

function formatFeatureVal(key, val) {
  const meta = FEATURE_META[key];
  if (meta && meta.fmt) return meta.fmt(val);
  if (typeof val === 'number') return Number.isInteger(val) ? val : val.toFixed(4);
  return String(val);
}

function getRisk(key, val) {
  const meta = FEATURE_META[key];
  if (meta && meta.risk) return meta.risk(val);
  return 'neutral';
}

// ----------------------------------------------------------------
// Render helpers
// ----------------------------------------------------------------
function checkSpan(cls, text) {
  return `<span class="check-${cls}">${text}</span>`;
}

function renderFeatureTable(features) {
  featuresBody.innerHTML = '';
  const keys = Object.keys(features);
  keys.forEach(key => {
    const val = features[key];
    const risk = getRisk(key, val);
    const label = (FEATURE_META[key] && FEATURE_META[key].label) || key;
    const display = formatFeatureVal(key, val);
    const badge = risk === 'neutral'
      ? `<span class="badge badge-neutral">—</span>`
      : `<span class="badge badge-${risk}">${risk === 'danger' ? 'High Risk' : risk === 'warn' ? 'Suspicious' : 'OK'}</span>`;
    featuresBody.innerHTML += `
      <tr>
        <td>${label}</td>
        <td>${display}</td>
        <td>${badge}</td>
      </tr>`;
  });
}

function renderRecommendation(verdict, secAssessment) {
  const recs = {
    PHISHING: {
      emoji: '🚨',
      title: 'Do NOT visit this URL — it is likely a phishing site',
      text: 'This URL shows strong indicators of a phishing attack. Do not enter any credentials, personal information, or payment details. Close any tabs that opened this link. If you received it via email or message, report it as phishing.',
      actions: ['Copy URL for reporting', 'Report to PhishTank', 'Share warning']
    },
    SUSPICIOUS: {
      emoji: '⚠️',
      title: 'Proceed with extreme caution',
      text: 'This URL has suspicious characteristics. While it may not be confirmed phishing, we recommend not entering sensitive information. Verify the URL carefully before proceeding.',
      actions: ['Verify domain', 'Check URL manually', 'Report if phishing']
    },
    LEGITIMATE: {
      emoji: '✅',
      title: 'URL appears to be legitimate',
      text: 'No significant phishing indicators were detected. The URL structure and security checks look normal. Always double-check the domain before entering sensitive information.',
      actions: ['Visit safely', 'Bookmark for later']
    }
  };
  const r = recs[verdict] || recs['SUSPICIOUS'];
  recBody.innerHTML = `
    <div class="rec-emoji">${r.emoji}</div>
    <div class="rec-text">
      <h3>${r.title}</h3>
      <p>${r.text}</p>
      <div class="rec-actions">
        ${r.actions.map(a => `<button class="rec-btn">${a}</button>`).join('')}
      </div>
    </div>
  `;
}

// ----------------------------------------------------------------
// Main render function
// ----------------------------------------------------------------
function renderResults(data) {
  const verdict = data.overall_verdict;
  const ml      = data.ml_analysis    || {};
  const sec     = data.security_assessment || {};

  // --- Verdict banner ---
  verdictBanner.className = 'verdict-banner ' + verdict.toLowerCase();
  verdictLabel.textContent = verdict;
  verdictLabel.style.color = VERDICT_COLORS[verdict] || 'var(--text)';
  verdictUrl.textContent = data.url;
  verdictTime.textContent = `Analyzed in ${data.analysis_time_seconds}s`;
  verdictIcon.innerHTML = ICONS[verdict.toLowerCase()] || ICONS.suspicious;
  verdictIcon.style.color = VERDICT_COLORS[verdict] || 'var(--text)';

  // --- ML ---
  const mlV = ml.verdict || '—';
  mlVerdict.textContent = mlV;
  mlVerdict.style.color = VERDICT_COLORS[mlV] || 'var(--text)';
  mlModelName.textContent = ml.model_name || '';

  const phishPct = ml.phishing_probability ?? 0;
  const legitPct = ml.legitimate_probability ?? 0;
  gaugeFill.style.width = phishPct + '%';
  gaugePct.textContent  = phishPct.toFixed(1) + '%';
  probPhish.textContent = phishPct.toFixed(1) + '%';
  probLegit.textContent = legitPct.toFixed(1) + '%';

  // --- Security ---
  const score = sec.risk_score || 0;
  const flags = sec.risk_flags || [];

  // Risk dot color
  let dotColor = 'var(--safe)';
  if (score >= 5)      dotColor = 'var(--danger)';
  else if (score >= 2) dotColor = 'var(--warn)';
  riskDot.style.background = dotColor;
  riskScore.textContent = `${score} risk flag${score !== 1 ? 's' : ''}`;
  riskLabel.textContent = score >= 5 ? 'High Risk' : score >= 2 ? 'Medium Risk' : 'Low Risk';
  riskLabel.style.color = dotColor;

  // DNS
  const dns = sec.dns || {};
  checkDNSVal.innerHTML = dns.has_dns
    ? checkSpan('safe', '✓ Found')
    : checkSpan('danger', '✗ No records');

  // SSL
  const ssl = sec.ssl || {};
  if (ssl.error && !ssl.has_ssl) {
    checkSSLVal.innerHTML = checkSpan('neutral', 'N/A');
  } else if (ssl.is_valid) {
    const daysLeft = ssl.days_to_expiry;
    const cls = daysLeft < 30 ? 'warn' : 'safe';
    checkSSLVal.innerHTML = checkSpan(cls, `✓ Valid (${daysLeft}d left)`);
  } else {
    checkSSLVal.innerHTML = checkSpan('danger', '✗ Invalid/None');
  }

  // HTTPS
  const hasHTTPS = data.url.startsWith('https');
  checkHTTPSVal.innerHTML = hasHTTPS
    ? checkSpan('safe', '✓ Yes')
    : checkSpan('danger', '✗ No');

  // Redirects
  const redir = sec.redirects || {};
  if (redir.error) {
    checkRedirectVal.innerHTML = checkSpan('neutral', 'Could not check');
  } else {
    const n = redir.num_redirects || 0;
    const cls = n > 3 ? 'danger' : n > 1 ? 'warn' : 'safe';
    checkRedirectVal.innerHTML = checkSpan(cls, `${n} redirect${n !== 1 ? 's' : ''}`);
  }

  // PhishTank
  const pt = sec.phishtank || {};
  if (pt.in_phishtank) {
    checkPhishtankVal.innerHTML = checkSpan('danger', '✗ Reported');
  } else if (pt.error) {
    checkPhishtankVal.innerHTML = checkSpan('neutral', 'Could not check');
  } else {
    checkPhishtankVal.innerHTML = checkSpan('safe', '✓ Not listed');
  }

  // Domain
  checkDomainVal.innerHTML = `<span style="color:var(--text)">${sec.domain || '—'}</span>`;

  // Flags
  if (flags.length > 0) {
    flagsWrap.style.display = '';
    flagsList.innerHTML = flags.map(f => `<li>${f}</li>`).join('');
  } else {
    flagsWrap.style.display = 'none';
  }

  // Features table
  renderFeatureTable(ml.features_used || {});

  // Recommendation
  renderRecommendation(verdict, sec);

  // Show results
  resultsArea.classList.remove('hidden');
  resultsArea.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ----------------------------------------------------------------
// Analyze
// ----------------------------------------------------------------
async function analyze() {
  const url = urlInput.value.trim();
  if (!url) {
    urlInput.focus();
    return;
  }

  // Show loading
  loadingOverlay.classList.remove('hidden');
  startLoadingSteps();
  analyzeBtn.disabled = true;
  btnText.classList.add('hidden');
  btnSpinner.classList.remove('hidden');

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || `Server error: ${res.status}`);
    }

    renderResults(data);

  } catch (err) {
    alert(`Analysis failed: ${err.message}\n\nMake sure the Flask server is running.`);
  } finally {
    loadingOverlay.classList.add('hidden');
    stopLoadingSteps();
    analyzeBtn.disabled = false;
    btnText.classList.remove('hidden');
    btnSpinner.classList.add('hidden');
  }
}

// ----------------------------------------------------------------
// Event listeners
// ----------------------------------------------------------------
analyzeBtn.addEventListener('click', analyze);

urlInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') analyze();
});

clearBtn.addEventListener('click', () => {
  urlInput.value = '';
  urlInput.focus();
  resultsArea.classList.add('hidden');
});

document.querySelectorAll('.ex-pill').forEach(pill => {
  pill.addEventListener('click', () => {
    urlInput.value = pill.dataset.url;
    analyze();
  });
});

