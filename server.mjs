import { createServer } from 'node:http';
import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';

const usernames = ['dkrajca', 'ltkaczyk', 'pplonski', 'gtomaszek', 'test'];
const accountRole = username => username === 'dkrajca' ? 'admin' : 'sales';
const stretch = promisify(scrypt);
const lifetime = 8 * 60 * 60 * 1000;
const cookieName = '__Host-gx_session';
const loginPage = (invalid = false) => '<!doctype html><html lang="cs"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Přihlášení | GX</title><style>body{font:16px system-ui;background:#f3f6fa;color:#112740;margin:0;padding:24px}main{background:white;border:1px solid #d5deea;border-radius:12px;max-width:360px;margin:10vh auto;padding:24px}label,input{display:block}label{margin:12px 0}input{box-sizing:border-box;width:100%;padding:8px}button{background:#064795;color:white;border:0;border-radius:6px;padding:9px 14px;font:inherit}p{color:#9b3425}</style><main><h1>Přihlášení do GX</h1>' +
  (invalid ? '<p role="alert">Přihlášení se nezdařilo.</p>' : '') +
  '<form method="post" action="/login"><label>Uživatelské jméno<input name="username" required maxlength="32" autocomplete="username"></label><label>Heslo<input name="password" type="password" required maxlength="256" autocomplete="current-password"></label><button>Přihlásit se</button></form></main></html>';

function send(response, status, body = '', headers = {}) {
  response.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    ...headers,
  });
  response.end(body);
}

export function createQuoteServer({ publicOrigin, accounts, appHtml }) {
  const origin = new URL(publicOrigin);
  if (origin.protocol !== 'https:' || publicOrigin !== origin.origin) throw Error('GX_PUBLIC_ORIGIN must be a canonical HTTPS origin');
  const hashes = new Map(usernames.map(username => {
    const encoded = accounts[username];
    if (!/^[a-f0-9]{32}:[a-f0-9]{64}$/.test(encoded ?? '')) throw Error('Missing password hash for ' + username);
    const [salt, digest] = encoded.split(':');
    return [username, { salt: Buffer.from(salt, 'hex'), digest: Buffer.from(digest, 'hex') }];
  }));
  const unknown = hashes.get('test');
  const sessions = new Map();
  let attempts = 0;
  let until = 0;
  let concurrent = 0;
  const cookie = (value, age) => cookieName + '=' + value + '; Path=/; Max-Age=' + age + '; HttpOnly; Secure; SameSite=Strict';
  function redirect(response, path, value, age) {
    send(response, 303, '', {Location:path,'Set-Cookie':cookie(value, age)});
  }
  return createServer(async (request, response) => {
    try {
      const path = new URL(request.url, origin).pathname;
      const id = request.headers.cookie?.match(/(?:^|;\s*)__Host-gx_session=([a-f0-9]{64})(?:;|$)/)?.[1];
      const now = Date.now();
      const session = sessions.get(id);
      const user = session?.expires > now ? session.username : null;
      if (request.method === 'GET' && path === '/login') {
        return user ? send(response, 303, '', {Location:'/'}) : send(response, 200, loginPage());
      }
      if (request.method === 'POST' && ['/login','/logout'].includes(path)) {
        if (request.headers.origin !== origin.origin) return send(response, 403);
        if (path === '/logout') {
          sessions.delete(id);
          return redirect(response, '/login', '', 0);
        }
        if (user) return send(response, 303, '', {Location:'/'});
        if (now >= until) {
          attempts = 0;
          until = now + 60_000;
        }
        if (attempts >= 25 || concurrent >= 4) return send(response, 429, 'Zkus to za chvíli.', {'Retry-After':'60'});
        let body = '';
        for await (const chunk of request) {
          body += chunk;
          if (body.length > 4096) return send(response, 413);
        }
        if (attempts >= 25 || concurrent >= 4) return send(response, 429, 'Zkus to za chvíli.', {'Retry-After':'60'});
        const fields = new URLSearchParams(body);
        const username = fields.get('username')?.trim().toLowerCase();
        const password = fields.get('password') ?? '';
        if (password.length > 256) return send(response, 401, loginPage(true));
        const account = hashes.get(username);
        const { salt, digest } = account ?? unknown;
        attempts++;
        concurrent++;
        let matches;
        try { matches = timingSafeEqual(await stretch(password, salt, 32), digest); }
        finally { concurrent--; }
        if (!account || !matches) return send(response, 401, loginPage(true));
        for (const [token, item] of sessions) if (item.expires <= now) sessions.delete(token);
        if (sessions.size >= 1000) return send(response, 503);
        const token = randomBytes(32).toString('hex');
        sessions.set(token, {username,expires:now+lifetime});
        return redirect(response, '/', token, lifetime/1000);
      }
      if (request.method === 'GET' && ['/', '/index.html'].includes(path)) {
        if (!user) return send(response, 303, '', {Location:'/login'});
        const role = accountRole(user);
        const accountControls = '<form method="post" action="/logout" class="actions gx-account"><span>' + user + '</span><button class="secondary">Odhlásit / Wyloguj</button></form>';
        const html = appHtml.replace('</header>', accountControls + '</header>')
          .replace('<body>', '<body data-account="' + user + '" data-role="' + role + '">')
          .replace("const storageKey = 'gx-quotes-demo-v2';", "const storageKey = 'gx-quotes-demo-v2:' + document.body.dataset.account;")
          .replace("const clientsKey = 'gx-clients-demo-v1';", "const clientsKey = 'gx-clients-demo-v1:' + document.body.dataset.account;")
          .replace('<option>Demo Sales 1</option><option>Demo Sales 2</option>', '<option>' + user + '</option>');
        return send(response, 200, html);
      }
      return send(response, 404);
    } catch {
      if (!response.headersSent) send(response, 500);
    }
  });
}

if (process.argv[2] === '--create-credentials') {
  const passwords = {};
  const hashes = {};
  for (const username of usernames) {
    const password = randomBytes(18).toString('base64url');
    const salt = randomBytes(16);
    const digest = await stretch(password, salt, 32);
    passwords[username] = password;
    hashes[username] = salt.toString('hex') + ':' + digest.toString('hex');
  }
  console.log(JSON.stringify({passwords, hashes}, null, 2));
} else if (process.env.GX_PUBLIC_ORIGIN) {
  const accounts = JSON.parse(process.env.GX_ACCOUNT_HASHES ?? '{}');
  const appHtml = readFileSync(process.env.GX_APP_FILE ?? new URL('./index.html', import.meta.url), 'utf8');
  createQuoteServer({ publicOrigin:process.env.GX_PUBLIC_ORIGIN, accounts, appHtml })
    .listen(Number(process.env.PORT ?? 3000), process.env.GX_LISTEN_HOST ?? '127.0.0.1');
}
