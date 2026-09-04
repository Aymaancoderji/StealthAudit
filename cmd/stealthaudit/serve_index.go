package main

// indexHTML is the single-page live fingerprint demo served by `stealthaudit
// serve`. Everything renders client-side from the JSON the /api/collect and
// /api/report endpoints return, styled after fingerprint.com's public demo:
// a visitor-recognition headline, a score gauge, and per-signal cards.
const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>StealthAudit — Live Fingerprint Test</title>
<style>
  :root {
    --bg: #f5f7fb; --card: #ffffff; --border: #e6e9f0;
    --text: #1a2133; --muted: #6b7280; --accent: #2f6fed; --accent-soft: #eaf0fe;
    --green: #16a34a; --green-soft: #e9f9ee;
    --amber: #d97706; --amber-soft: #fdf3e3;
    --red: #dc2626; --red-soft: #fdecec;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  }
  nav {
    display: flex; align-items: center; justify-content: space-between;
    padding: 1.1rem 2rem; background: var(--card); border-bottom: 1px solid var(--border);
  }
  nav .brand { font-weight: 700; font-size: 1.05rem; display: flex; align-items: center; gap: .5rem; }
  nav .brand .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); display: inline-block; }
  nav .tag { color: var(--muted); font-size: .85rem; }
  main { max-width: 980px; margin: 0 auto; padding: 2.5rem 1.5rem 5rem; }

  #loading { text-align: center; padding: 5rem 1rem; color: var(--muted); }
  .spinner {
    width: 34px; height: 34px; margin: 0 auto 1.2rem; border-radius: 50%;
    border: 3px solid var(--border); border-top-color: var(--accent);
    animation: spin .8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  #app { display: none; }
  #app.ready { display: block; animation: fadein .35s ease; }
  @keyframes fadein { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }

  .hero {
    background: var(--card); border: 1px solid var(--border); border-radius: 16px;
    padding: 2rem; display: flex; gap: 2.25rem; align-items: center; flex-wrap: wrap;
    box-shadow: 0 1px 2px rgba(20,25,40,.03), 0 10px 30px rgba(20,25,40,.04);
  }
  .gauge-wrap { flex: 0 0 auto; text-align: center; }
  .gauge-num { font-size: 1.9rem; font-weight: 800; }
  .gauge-label { font-size: .72rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-top: .1rem; }
  .hero-main { flex: 1 1 320px; min-width: 280px; }
  .visitor-line { font-size: 1.4rem; font-weight: 700; margin: 0 0 .35rem; }
  .visitor-sub { color: var(--muted); font-size: .92rem; margin-bottom: 1rem; }
  .pills { display: flex; gap: .5rem; flex-wrap: wrap; }
  .pill {
    display: inline-flex; align-items: center; gap: .4rem; padding: .35rem .75rem;
    border-radius: 999px; font-size: .82rem; font-weight: 600;
  }
  .pill.green { background: var(--green-soft); color: var(--green); }
  .pill.amber { background: var(--amber-soft); color: var(--amber); }
  .pill.red { background: var(--red-soft); color: var(--red); }
  .pill.neutral { background: var(--accent-soft); color: var(--accent); }
  .pill code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }

  .section-title { font-size: 1.05rem; font-weight: 700; margin: 2.25rem 0 1rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 1rem; }
  .card {
    background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 1.25rem;
  }
  .card-head { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: .85rem; }
  .card-head h3 { margin: 0; font-size: .95rem; }
  .card-score { font-weight: 800; font-size: 1.05rem; }
  .bar-track { background: #eef1f6; border-radius: 6px; height: 6px; overflow: hidden; margin-bottom: 1rem; }
  .bar-fill { height: 100%; border-radius: 6px; }
  .check-list { list-style: none; margin: 0; padding: 0; display: grid; gap: .55rem; }
  .check-list li { display: flex; gap: .55rem; align-items: flex-start; font-size: .86rem; }
  .check-list .ic { flex: 0 0 auto; width: 1.1rem; text-align: center; }
  .check-list .ok { color: var(--green); }
  .check-list .bad { color: var(--red); }
  .check-list .neutral-ic { color: var(--muted); }
  .check-list .kv { color: var(--muted); }
  .check-list .kv b { color: var(--text); font-weight: 600; }
  .muted-card { color: var(--muted); font-size: .88rem; }
  .muted-card a { color: var(--accent); font-weight: 600; text-decoration: none; }

  .cta {
    display: flex; align-items: center; justify-content: space-between; gap: 1rem;
    background: var(--accent-soft); border: 1px solid #d8e4fd; border-radius: 14px;
    padding: 1rem 1.25rem; margin-top: 1rem; flex-wrap: wrap;
  }
  .cta p { margin: 0; font-size: .88rem; color: #1e3a8a; }
  .btn {
    display: inline-block; background: var(--accent); color: #fff; font-weight: 600;
    font-size: .85rem; padding: .55rem 1rem; border-radius: 8px; text-decoration: none;
    border: none; cursor: pointer; white-space: nowrap;
  }
  .btn.secondary { background: #fff; color: var(--accent); border: 1px solid #c9d8fb; }

  .flags-card { margin-top: 1rem; }
  .flag-row { display: flex; gap: .75rem; padding: .6rem 0; border-top: 1px solid var(--border); font-size: .86rem; }
  .flag-row:first-child { border-top: none; }
  .sev-badge {
    flex: 0 0 auto; width: 1.6rem; height: 1.6rem; border-radius: 50%;
    display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: .75rem;
  }
  .flag-body .code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .78rem; color: var(--muted); }

  details.raw { margin-top: 2rem; }
  details.raw summary { cursor: pointer; color: var(--accent); font-weight: 600; font-size: .9rem; }
  details.raw pre {
    margin-top: 1rem; background: #0d1117; color: #c9d1d9; padding: 1rem; border-radius: 10px;
    overflow: auto; font-size: .78rem; max-height: 420px;
  }
  #errorBox { display: none; background: var(--red-soft); color: var(--red); border-radius: 10px; padding: 1rem; margin-bottom: 1rem; }

  .ml-flag {
    display: flex; align-items: center; gap: 1.1rem; border-radius: 14px;
    padding: 1.1rem 1.4rem; margin-bottom: 1.5rem; animation: flagpop .3s ease;
    border: 1px solid transparent;
  }
  .ml-flag.automated { background: var(--red-soft); border-color: #f8b4b4; }
  .ml-flag.genuine { background: var(--green-soft); border-color: #a7e3bb; }
  .ml-flag.uncertain { background: var(--amber-soft); border-color: #f3d49a; }
  .ml-flag .ml-icon { font-size: 1.8rem; line-height: 1; }
  .ml-flag .ml-prob { font-size: 1.7rem; font-weight: 800; }
  .ml-flag.automated .ml-prob, .ml-flag.automated .ml-title { color: var(--red); }
  .ml-flag.genuine .ml-prob, .ml-flag.genuine .ml-title { color: var(--green); }
  .ml-flag.uncertain .ml-prob, .ml-flag.uncertain .ml-title { color: var(--amber); }
  .ml-flag .ml-title { font-weight: 700; font-size: 1rem; }
  .ml-flag .ml-sub { color: var(--muted); font-size: .82rem; margin-top: .15rem; }
  .ml-flag .ml-badge {
    margin-left: auto; font-size: .72rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: .04em; background: rgba(0,0,0,.06); padding: .3rem .6rem; border-radius: 999px;
  }
  @keyframes flagpop { from { opacity: 0; transform: scale(.97); } to { opacity: 1; transform: none; } }

  .history-wrap { margin-top: 1.1rem; padding-top: 1rem; border-top: 1px solid var(--border); }
  .history-label { font-size: .72rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: .5rem; }
  .history-bars { display: flex; align-items: flex-end; gap: 3px; height: 34px; }
  .history-bars .bar { flex: 1 1 auto; max-width: 10px; height: 26px; border-radius: 2px 2px 0 0; background: var(--accent); opacity: .35; }
  .history-bars .bar.latest { opacity: 1; }
  .history-bars .bar:hover { opacity: .8; }
</style>
</head>
<body>
<nav>
  <div class="brand"><span class="dot"></span> StealthAudit</div>
  <div class="tag">Live fingerprint test &middot; nothing leaves this machine</div>
</nav>
<main>
  <div id="errorBox"></div>
  <div id="loading">
    <div class="spinner"></div>
    Collecting your browser's fingerprint&hellip;
  </div>
  <div id="app"></div>
</main>
<script>
const PROBE_URL = {{.ProbeURL}};
const scoreColor = (s) => s >= 80 ? 'var(--green)' : s >= 50 ? 'var(--amber)' : 'var(--red)';
const scoreSoft  = (s) => s >= 80 ? 'var(--green-soft)' : s >= 50 ? 'var(--amber-soft)' : 'var(--red-soft)';
const sevColor   = (n) => n >= 4 ? 'var(--red)' : n >= 2 ? 'var(--amber)' : 'var(--green)';
const sevSoft    = (n) => n >= 4 ? 'var(--red-soft)' : n >= 2 ? 'var(--amber-soft)' : 'var(--green-soft)';
const esc = (s) => (s ?? '').toString().replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtDate = (iso) => { try { return new Date(iso).toLocaleString(); } catch { return iso; } };

function gauge(score) {
  const C = 2 * Math.PI * 52;
  const frac = Math.max(0, Math.min(100, score)) / 100;
  return '<div class="gauge-wrap">' +
    '<svg viewBox="0 0 120 120" width="128" height="128">' +
      '<circle cx="60" cy="60" r="52" fill="none" stroke="#eef1f6" stroke-width="12"/>' +
      '<circle cx="60" cy="60" r="52" fill="none" stroke="' + scoreColor(score) + '" stroke-width="12" ' +
        'stroke-linecap="round" transform="rotate(-90 60 60)" ' +
        'stroke-dasharray="' + (frac * C).toFixed(1) + ' ' + C.toFixed(1) + '"/>' +
      '<text x="60" y="56" text-anchor="middle" font-size="26" font-weight="800" fill="' + scoreColor(score) + '">' + Math.round(score) + '</text>' +
      '<text x="60" y="76" text-anchor="middle" font-size="10" fill="#6b7280">/ 100</text>' +
    '</svg>' +
    '<div class="gauge-label">Stealth Score</div>' +
  '</div>';
}

function check(ok, label, extra) {
  const icClass = ok === null ? 'neutral-ic' : (ok ? 'ok' : 'bad');
  const icon = ok === null ? '&middot;' : (ok ? '&#10003;' : '&#10007;');
  return '<li><span class="ic ' + icClass + '">' + icon + '</span><span class="kv">' + label + (extra ? ' &mdash; <b>' + esc(extra) + '</b>' : '') + '</span></li>';
}

function categoryCard(title, score, itemsHTML) {
  return '<div class="card">' +
    '<div class="card-head"><h3>' + title + '</h3><span class="card-score" style="color:' + scoreColor(score) + '">' + Math.round(score) + '</span></div>' +
    '<div class="bar-track"><div class="bar-fill" style="width:' + Math.max(0,Math.min(100,score)) + '%; background:' + scoreColor(score) + '"></div></div>' +
    '<ul class="check-list">' + itemsHTML + '</ul>' +
  '</div>';
}

function mlFlagBanner(ml) {
  if (!ml) return '';
  const pct = Math.round(ml.probability * 100);
  const cls = ml.verdict === 'likely_automated' ? 'automated' : (ml.verdict === 'likely_genuine' ? 'genuine' : 'uncertain');
  const icon = cls === 'automated' ? '&#128680;' : (cls === 'genuine' ? '&#9989;' : '&#8265;');
  const title = cls === 'automated'
    ? 'ML model flagged this fingerprint as suspicious'
    : (cls === 'genuine' ? 'ML model reads this as a genuine browser' : 'ML model is uncertain about this fingerprint');
  const top = (ml.contributions || []).slice(0, 3)
    .filter(c => Math.abs(c.impact) > 0.01)
    .map(c => c.feature.replace(/_/g, ' '))
    .join(', ');
  return '<div class="ml-flag ' + cls + '">' +
    '<span class="ml-icon">' + icon + '</span>' +
    '<div><div class="ml-title">' + title + '</div>' +
    '<div class="ml-sub">' + (top ? 'Driven mainly by: ' + esc(top) : 'No strong signals either way') + '</div></div>' +
    '<span class="ml-prob">' + pct + '%</span>' +
    '<span class="ml-badge">' + cls.replace('_', ' ') + '</span>' +
  '</div>';
}

function visitHistory(visits) {
  if (!visits || visits.length < 2) return '';
  const bars = visits.map((iso, i) => {
    const isLatest = i === visits.length - 1;
    const title = fmtDate(iso);
    return '<div class="bar' + (isLatest ? ' latest' : '') + '" title="' + esc(title) + '"></div>';
  }).join('');
  return '<div class="history-wrap">' +
    '<div class="history-label">Visit history (' + visits.length + (visits.length >= 25 ? '+' : '') + ' most recent)</div>' +
    '<div class="history-bars">' + bars + '</div>' +
  '</div>';
}

function render(data) {
  const r = data.report, v = data.visitor, a = r.analysis || {};
  const cat = a.categoryScores || {};
  const fp = r; // Fingerprint fields are promoted to the top level of report.Run

  const statusPill = (fp.runtime && fp.runtime.webdriverFlag) || a.stealthScore < 50
    ? '<span class="pill red">&#129302; Automation signals detected</span>'
    : (a.stealthScore < 80
      ? '<span class="pill amber">&#9888; Some anomalies found</span>'
      : '<span class="pill green">&#9989; Looks like a genuine browser</span>');

  const visitorLine = v.isNew
    ? "First time here &mdash; nice to meet you."
    : "Welcome back! Recognized from " + v.count + " previous visit" + (v.count === 1 ? '' : 's') +
      " &mdash; no cookies involved. Last time was " + fmtDate(v.lastSeen) + ".";

  let html = mlFlagBanner(r.ml);

  html += '<div class="hero">' +
    gauge(a.stealthScore || 0) +
    '<div class="hero-main">' +
      '<p class="visitor-line">You\'ve visited ' + v.count + ' time' + (v.count === 1 ? '' : 's') + '</p>' +
      '<p class="visitor-sub">' + visitorLine + '</p>' +
      '<div class="pills">' +
        statusPill +
        '<span class="pill neutral">Visitor ID <code>' + v.shortId + '</code></span>' +
        '<span class="pill neutral">First seen ' + fmtDate(v.firstSeen) + '</span>' +
      '</div>' +
      visitHistory(v.visits) +
    '</div>' +
  '</div>';

  html += '<div class="section-title">Signal Breakdown</div><div class="grid">';

  const rt = fp.runtime || {};
  html += categoryCard('Runtime Integrity', cat.js_runtime_integrity ?? 0,
    check(!rt.webdriverFlag, 'navigator.webdriver') +
    check(rt.functionToStringOk, 'Function.toString() unmodified') +
    check(!rt.permissionsAnomaly, 'Permissions API consistent') +
    check(rt.workerSupport, 'Web Worker support') +
    check(!rt.workerWebdriverLeak, 'Web Worker webdriver isolated') +
    check(!rt.errorStackAutomationLeak, 'No automation frames in Error.stack') +
    check(rt.toStringOfToStringOk !== false, 'Function.toString deep integrity') +
    check(rt.hasChromeRuntime, 'window.chrome.runtime present') +
    check(!(rt.automationArtifacts && rt.automationArtifacts.length), 'No WebDriver/automation artifacts', (rt.automationArtifacts || []).join(', ') || null) +
    check(!rt.webdriverDescriptorAnomaly, 'navigator.webdriver descriptor native') +
    check(!rt.cdpRuntimeDomainSuspected, 'No CDP Runtime-domain preview signal') +
    check(!rt.hasChromeRuntime || (rt.chromeLoadTimesPresent && rt.chromeCsiPresent), 'window.chrome shape complete'));

  const gl = fp.webgl || {}, dev = fp.device || {};
  const isSoftware = /swiftshader|llvmpipe|software rasterizer|mesa.*(softpipe|llvmpipe)/i.test(gl.unmaskedRenderer || '');
  html += categoryCard('Hardware Consistency', cat.hardware_consistency ?? 0,
    check(!isSoftware, 'GPU renderer', gl.unmaskedRenderer || 'unknown') +
    check(gl.webgl2Supported !== false, 'WebGL2 supported') +
    check(!!(fp.canvas && fp.canvas.hash), 'Canvas fingerprint produced') +
    check(!!(fp.audio && fp.audio.hash), 'Audio fingerprint produced') +
    check(dev.hardwareConcurrency > 1, 'CPU cores', String(dev.hardwareConcurrency ?? '?')) +
    check((dev.fonts || []).length >= 3, 'System fonts detected', String((dev.fonts || []).length)) +
    check(dev.screenWidth > 0 && dev.screenHeight > 0, 'Screen resolution', (dev.screenWidth ?? '?') + '&times;' + (dev.screenHeight ?? '?')) +
    check(!(dev.outerWidth === 0 && dev.outerHeight === 0), 'Window geometry valid', (dev.outerWidth && dev.outerHeight) ? (dev.outerWidth + '&times;' + dev.outerHeight) : null) +
    check(dev.colorDepth >= 24, 'Color depth', dev.colorDepth ? dev.colorDepth + '-bit' : null) +
    check(dev.deviceMemory > 0, 'Device memory', dev.deviceMemory ? dev.deviceMemory + ' GB' : 'unavailable') +
    (dev.userAgentData && dev.userAgentData.platform ? check(true, 'Client hints platform', dev.userAgentData.platform) : ''));

  if (r.network) {
    const tls = r.network.tls || {}, h2 = r.network.http2 || {};
    html += categoryCard('TLS / Network Alignment', cat.tls_network_alignment ?? 0,
      check(!!tls.ja3, 'JA3 captured', tls.ja3 ? tls.ja3.slice(0, 16) + '&hellip;' : null) +
      check(!!tls.ja4, 'JA4 captured', tls.ja4 ? tls.ja4.slice(0, 16) + '&hellip;' : null) +
      check(!!h2.pseudoHeaders, 'HTTP/2 negotiated', h2.pseudoHeaders ? h2.pseudoHeaders.join(' ') : null));
  } else {
    html += '<div class="card">' +
      '<div class="card-head"><h3>TLS / Network Alignment</h3></div>' +
      '<p class="muted-card">Not captured yet &mdash; this needs a real TLS handshake, so it can\'t run silently in the background.</p>' +
      '<div class="cta"><p>Open the local TLS probe (your browser will warn about a self-signed cert &mdash; that\'s expected, accept it) then come back and refresh.</p>' +
      '<div style="display:flex; gap:.5rem"><a class="btn" href="' + PROBE_URL + '" target="_blank" rel="noopener">Run TLS test</a>' +
      '<button class="btn secondary" onclick="loadReport()">Refresh</button></div></div>' +
    '</div>';
  }

  html += '<div class="card">' +
    '<div class="card-head"><h3>Session Isolation</h3></div>' +
    '<p class="muted-card">Not part of a single-session test. Run <code>stealthaudit leaktest</code> to check whether two automated sessions leak state into each other.</p>' +
  '</div>';

  html += '</div>';

  const flags = a.flags || [];
  html += '<div class="section-title">Flags (' + flags.length + ')</div>';
  if (flags.length === 0) {
    html += '<div class="card muted-card">No flags raised &mdash; nothing in this fingerprint looked anomalous.</div>';
  } else {
    html += '<div class="card flags-card">' + flags.map(f =>
      '<div class="flag-row">' +
        '<span class="sev-badge" style="background:' + sevSoft(f.severity) + '; color:' + sevColor(f.severity) + '">' + f.severity + '</span>' +
        '<div class="flag-body"><div>' + esc(f.description) + '</div><div class="code">' + esc(f.category) + ' &middot; ' + esc(f.code) + '</div></div>' +
      '</div>').join('') + '</div>';
  }

  html += '<details class="raw"><summary>View raw fingerprint JSON</summary><pre>' + esc(JSON.stringify(r, null, 2)) + '</pre></details>';

  document.getElementById('app').innerHTML = html;
  document.getElementById('app').classList.add('ready');
  document.getElementById('loading').style.display = 'none';
}

function showError(msg) {
  const box = document.getElementById('errorBox');
  box.textContent = msg;
  box.style.display = 'block';
  document.getElementById('loading').style.display = 'none';
}

async function loadReport() {
  try {
    const resp = await fetch('/api/report');
    if (!resp.ok) throw new Error(await resp.text());
    render(await resp.json());
  } catch (e) {
    showError('Could not load report: ' + e);
  }
}

async function main() {
  try {
    const fp = await {{.AuditScript}};
    const resp = await fetch('/api/collect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(fp),
    });
    if (!resp.ok) throw new Error(await resp.text());
    render(await resp.json());
  } catch (e) {
    showError('Fingerprint collection failed: ' + e);
  }
}
main();
</script>
</body>
</html>
`
