// Playwright runner: a long-lived Node process controlled over stdin/stdout
// via newline-delimited JSON messages. Spawned and owned by the Go
// orchestrator (pkg/orchestrator/playwright.go) — one process per session.
//
// Protocol (one JSON object per line):
//   in:  {"id": <int>, "method": "launch"|"navigate"|"evaluate"|"close", "params": {...}}
//   out: {"id": <int>, "result": <any>}  or  {"id": <int>, "error": "<message>"}

const readline = require('readline');
const { chromium, firefox, webkit } = require('playwright');

const engines = { chromium, firefox, webkit };

let browser = null;
let context = null;
let page = null;

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

async function handleLaunch(params) {
  const engine = engines[params.browser || 'chromium'];
  if (!engine) {
    throw new Error(`unsupported browser: ${params.browser}`);
  }

  const launchOpts = { headless: params.headless !== false };
  if (params.proxyURL) {
    launchOpts.proxy = { server: params.proxyURL };
  }
  if (params.extraArgs && params.extraArgs.length) {
    launchOpts.args = params.extraArgs;
  }

  browser = await engine.launch(launchOpts);

  const contextOpts = {};
  if (params.userAgent) {
    contextOpts.userAgent = params.userAgent;
  }
  if (params.ignoreHTTPSErrors) {
    contextOpts.ignoreHTTPSErrors = true;
  }
  context = await browser.newContext(contextOpts);

  if (params.stealthPlugin) {
    // Minimal stealth-style patch: hide the webdriver flag. A dedicated
    // stealth module can replace this in a later phase.
    await context.addInitScript(() => {
      Object.defineProperty(Navigator.prototype, 'webdriver', { get: () => undefined });
    });
  }

  page = await context.newPage();
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
  if (context) await context.close();
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
