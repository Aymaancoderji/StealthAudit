// Puppeteer runner: a long-lived Node process controlled over stdin/stdout
// via newline-delimited JSON messages. Spawned and owned by the Go
// orchestrator (pkg/orchestrator/puppeteer.go) — one process per session.
//
// Protocol is identical to runners/playwright/session.js:
//   in:  {"id": <int>, "method": "launch"|"navigate"|"evaluate"|"close", "params": {...}}
//   out: {"id": <int>, "result": <any>}  or  {"id": <int>, "error": "<message>"}

const readline = require('readline');
const puppeteerExtra = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

let browser = null;
let page = null;

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

async function handleLaunch(params) {
  if ((params.browser || 'chromium') !== 'chromium') {
    // puppeteer-core also supports "firefox" product, but the stealth
    // plugin only targets Chromium; keep scope to Chromium for now.
    throw new Error(`puppeteer adapter only supports chromium (got ${params.browser})`);
  }

  if (params.stealthPlugin) {
    puppeteerExtra.use(StealthPlugin());
  }

  const launchArgs = params.extraArgs && params.extraArgs.length ? [...params.extraArgs] : [];
  if (params.proxyURL) {
    launchArgs.push(`--proxy-server=${params.proxyURL}`);
  }
  // Unprivileged user namespaces are commonly restricted in containers;
  // without this Chrome's zygote sandbox init aborts on launch. This
  // disables the OS-level process sandbox around the browser itself, not
  // any security check performed against pages under audit. Opt out with
  // STEALTHAUDIT_NO_SANDBOX=0 on hosts where the real sandbox is available.
  if (process.env.STEALTHAUDIT_NO_SANDBOX !== '0') {
    launchArgs.push('--no-sandbox', '--disable-setuid-sandbox');
  }
  if (params.ignoreHTTPSErrors) {
    // Chromium CLI switch rather than a Puppeteer-API option: it's stable
    // across Puppeteer versions, unlike the API surface for this setting.
    launchArgs.push('--ignore-certificate-errors');
  }

  browser = await puppeteerExtra.launch({
    headless: params.headless !== false,
    args: launchArgs,
  });

  page = await browser.newPage();
  if (params.userAgent) {
    await page.setUserAgent(params.userAgent);
  }

  return { ok: true };
}

async function handleNavigate(params) {
  if (!page) throw new Error('no active page; call launch first');
  await page.goto(params.url, { waitUntil: 'load' });
  return { ok: true };
}

async function handleEvaluate(params) {
  if (!page) throw new Error('no active page; call launch first');
  const result = await page.evaluate(params.script);
  return result;
}

async function handleClose() {
  if (browser) await browser.close();
  return { ok: true };
}

const handlers = {
  launch: handleLaunch,
  navigate: handleNavigate,
  evaluate: handleEvaluate,
  close: handleClose,
};

const rl = readline.createInterface({ input: process.stdin, terminal: false });

rl.on('line', async (line) => {
  line = line.trim();
  if (!line) return;

  let msg;
  try {
    msg = JSON.parse(line);
  } catch (e) {
    send({ id: null, error: `invalid JSON: ${e.message}` });
    return;
  }

  const handler = handlers[msg.method];
  if (!handler) {
    send({ id: msg.id, error: `unknown method: ${msg.method}` });
    return;
  }

  try {
    const result = await handler(msg.params || {});
    send({ id: msg.id, result });
  } catch (e) {
    send({ id: msg.id, error: e.message });
  }

  if (msg.method === 'close') {
    process.exit(0);
  }
});

process.on('SIGTERM', () => process.exit(0));
