// Explicit browser login; cookies travel only through a private pipe to the keychain.
// Usage: node scripts/probes/edupage_browser_login.cjs SCHOOL
const {spawn} = require('node:child_process');
const path = require('node:path');
const {chromium} = require('playwright');
const school = process.argv[2];
if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(school || '') || school === 'login1') {
  process.stderr.write('SCHOOL_REQUIRED\n'); process.exit(1);
}
const root = path.resolve(__dirname, '../..');
const python = process.env.EDUPAGE_MCP_PYTHON || path.join(root, '.venv/bin/python');
const base = `https://${school}.edupage.org`;
const endpoints = new Map();
let browser;
const report = value => process.stdout.write(JSON.stringify(value) + '\n');
async function storeSession(cookies) {
  return new Promise((resolve, reject) => {
    const child = spawn(python, ['-m', 'src.edupage_mcp', '--school', school, '--import-browser-session'],
      {cwd: root, stdio: ['pipe', 'pipe', 'pipe']});
    let result = '', failure = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('IMPORT_TIMEOUT')); }, 300000);
    child.stdout.on('data', chunk => { if(result.length < 4096) result += chunk; });
    child.stderr.on('data', chunk => {
      if (failure.length < 4096) failure += chunk;
    });
    child.on('error', () => { clearTimeout(timer); reject(new Error('IMPORT_FAILED')); });
    child.stdin.on('error', () => {});
    child.on('close', code => {
      clearTimeout(timer);
      try {if(code === 0 && JSON.parse(result).status === 'READY') return resolve();}catch{}
      const known = ['AUTH_REQUIRED', 'INVALID_SESSION', 'KEYCHAIN_UNAVAILABLE',
        'SCHEMA_CHANGED', 'USERNAME_MISSING', 'SECRET_IN_FILE', 'TEMPORARY_ERROR', 'LOCAL_ERROR'];
      const fixedCode = failure.trim().split('\n').find(line => known.includes(line));
      reject(new Error(fixedCode || 'IMPORT_FAILED'));
    });
    child.stdin.end(JSON.stringify({school, cookies}));
  });
}
(async () => {
  browser = await chromium.launch({channel: 'chrome', headless: false});
  // Incognito context: no storageState, screenshots, tracing, HAR or saved profile.
  const context = await browser.newContext({locale: 'de-DE', serviceWorkers: 'block'});
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('Network.enable');
  cdp.on('Network.requestWillBeSent', event => {
    try {
      const url = new URL(event.request.url);
      if (!['Document', 'XHR', 'Fetch'].includes(event.type) || url.protocol !== 'https:'
          || ![`${school}.edupage.org`, 'login1.edupage.org'].includes(url.hostname)) return;
      // Record known protocol paths only, never values, headers or request bodies.
      if (!['/login/', '/login/twofactor', '/login/edubarLogin.php', '/user/', '/timeline/'].includes(url.pathname)) return;
      const item = {method: event.request.method, host: url.hostname, path: url.pathname};
      for (const key of ['cmd', 'akcia', 'module']) {
        const value = url.searchParams.get(key);
        if (value && /^[A-Za-z]{1,30}$/.test(value)) item[key] = value;
      }
      endpoints.set(JSON.stringify(item), item);
    } catch {}
  });
  await page.goto(base + '/login/?cmd=MainLogin', {waitUntil: 'domcontentloaded', timeout: 30000});
  report({status: 'WAITING_FOR_BROWSER_LOGIN', timeout_seconds: 600});
  const deadline = Date.now() + 600000;
  while (Date.now() < deadline) {
    if (page.isClosed()) throw new Error('BROWSER_CLOSED');
    const url = new URL(page.url());
    if (url.origin === base && /^\/(user|timeline)\/?$/.test(url.pathname)) {
      const cookies = await context.cookies(base + '/user/', base + '/timeline/');
      await storeSession(cookies);
      cookies.length = 0;
      report({status: 'SESSION_SAVED_IN_KEYCHAIN', endpoints: [...endpoints.values()]});
      return;
    }
    await page.waitForTimeout(2000);
  }
  throw new Error('LOGIN_TIMEOUT');
})().catch(error => {
  const safe = ['IMPORT_TIMEOUT', 'IMPORT_FAILED', 'BROWSER_CLOSED', 'LOGIN_TIMEOUT',
    'AUTH_REQUIRED', 'INVALID_SESSION', 'KEYCHAIN_UNAVAILABLE', 'SCHEMA_CHANGED',
    'USERNAME_MISSING', 'SECRET_IN_FILE', 'TEMPORARY_ERROR', 'LOCAL_ERROR'];
  report({status: safe.includes(error.message) ? error.message : 'BROWSER_FAILED'});
  process.exitCode = 1;
}).finally(async () => { if (browser) await browser.close().catch(() => {}); });
