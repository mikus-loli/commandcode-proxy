// 多账号池 + 智能路由 + 管理后台 端到端测试。
// 全部走 loopback mock 上游，不需要真 key、不访问 Command Code / npm registry。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { setup } from './helpers.mjs';

const ADMIN_TOKEN = 'adm_test_123';
const ADMIN = { 'x-admin-token': ADMIN_TOKEN };
const MAIN = { env: { CC_ADMIN_TOKEN: ADMIN_TOKEN } };
const CHAT = { model: 'm', messages: [{ role: 'user', content: 'hi' }] };

async function withSetup(opts, fn) {
  const s = await setup(opts);
  try { return await fn(s); } finally { await s.close(); }
}

function admin(proxy, method, path, body, headers = ADMIN) {
  return fetch(proxy.base + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
const addAccount = (proxy, body) =>
  admin(proxy, 'POST', '/admin/api/accounts', body).then(r => r.json()).then(j => j.account);
const addClient = (proxy, body) =>
  admin(proxy, 'POST', '/admin/api/clients', body).then(r => r.json()).then(j => j.client);
const metrics = (proxy) => admin(proxy, 'GET', '/admin/api/metrics').then(r => r.json());
const routeAuth = (mock) => String(mock.lastGenerate()?.headers.authorization || '');
const countAuth = (mock, needle) =>
  mock.seen.filter(s => s.url === '/alpha/generate' && String(s.headers.authorization || '').includes(needle)).length;

// 只让指定的「坏」key 在 /alpha/generate 上 429（初始化请求仍放行，避免干扰）。
function badKeyMock(opts = {}) {
  return {
    env: { CC_ADMIN_TOKEN: ADMIN_TOKEN },
    ...opts,
    onRequest(req, res) {
      const auth = String(req.headers.authorization || '');
      if (req.url === '/alpha/generate' && auth.includes('bad_')) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'rate limited' } }));
      }
    },
  };
}

// ── 1. 未配置令牌 → admin 404，不泄露 ──────────────────────
test('未配置 CC_ADMIN_TOKEN：/admin 与 /admin/api/* 均 404，且不含上游 key', async () => {
  await withSetup({ env: { CC_ADMIN_TOKEN: '' } }, async ({ proxy }) => {
    for (const p of ['/admin', '/admin/api/accounts', '/admin/api/clients']) {
      const r = await proxy.get(p);
      assert.equal(r.status, 404, p + ' should be 404');
      const t = await r.text();
      assert.ok(!t.includes('user_'), p + ' must not leak upstream keys');
    }
  });
});

// ── 2. 鉴权 + 预检不应答 ACAO ──────────────────────────────
test('鉴权：错误令牌 401、x-admin-token/Bearer 正确 200、OPTIONS 不发 ACAO', async () => {
  await withSetup(MAIN, async ({ proxy }) => {
    const bad = await admin(proxy, 'GET', '/admin/api/accounts', undefined, { 'x-admin-token': 'wrong' });
    assert.equal(bad.status, 401);
    const none = await admin(proxy, 'GET', '/admin/api/accounts', undefined, {});
    assert.equal(none.status, 401);
    assert.equal((await admin(proxy, 'GET', '/admin/api/accounts')).status, 200);
    const bearer = await fetch(proxy.base + '/admin/api/accounts', { headers: { Authorization: 'Bearer ' + ADMIN_TOKEN } });
    assert.equal(bearer.status, 200);
    const pre = await fetch(proxy.base + '/admin/api/accounts', { method: 'OPTIONS' });
    assert.equal(pre.status, 204);
    assert.equal(pre.headers.get('access-control-allow-origin'), null);
    // 数据面仍保留 CORS
    const dataPre = await fetch(proxy.base + '/v1/chat/completions', { method: 'OPTIONS' });
    assert.equal(dataPre.headers.get('access-control-allow-origin'), '*');
  });
});

// ── 3 & 4. 新增账号脱敏、列表脱敏 ──────────────────────────
test('新增账号 201 且 apiKey 掩码；原始 key 不出现在任何响应文本里', async () => {
  await withSetup(MAIN, async ({ proxy }) => {
    const raw = 'user_secret_ABC123XYZ';
    const r = await admin(proxy, 'POST', '/admin/api/accounts', { name: 'A', apiKey: raw });
    assert.equal(r.status, 201);
    const txt = await r.text();
    assert.ok(!txt.includes(raw), 'create response must not echo the raw key');
    const j = JSON.parse(txt);
    assert.equal(j.account.apiKey, raw.slice(0, 8) + '…' + raw.slice(-4));
    const listTxt = await (await admin(proxy, 'GET', '/admin/api/accounts')).text();
    assert.ok(!listTxt.includes(raw), 'list response must not echo the raw key');
    assert.ok(listTxt.includes('…'), 'list response should be masked');
  });
});

// ── 5. client 明文令牌仅一次 ───────────────────────────────
test('新建 client 仅此一次返回明文 ccp_*，随后 GET 只回掩码', async () => {
  await withSetup(MAIN, async ({ proxy }) => {
    const r = await admin(proxy, 'POST', '/admin/api/clients', { name: 'c1' });
    assert.equal(r.status, 201);
    const created = (await r.json()).client;
    assert.match(created.token, /^ccp_[0-9a-f]+$/);
    const listTxt = await (await admin(proxy, 'GET', '/admin/api/clients')).text();
    assert.ok(!listTxt.includes(created.token), 'plaintext token must not be listed again');
    assert.ok(listTxt.includes('…'));
  });
});

// ── 6. 池路由：上游收到池账号 key（≠ 客户端令牌）───────────
test('池路由：client 令牌请求 → 上游收到池账号 key，且不等于客户端令牌', async () => {
  await withSetup(MAIN, async ({ proxy, mock }) => {
    await addAccount(proxy, { name: 'A', apiKey: 'user_pool_AAA' });
    const cli = await addClient(proxy, { name: 'c' });
    const r = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    assert.equal(r.status, 200);
    assert.equal(routeAuth(mock), 'Bearer user_pool_AAA');
    assert.notEqual(routeAuth(mock), 'Bearer ' + cli.token);
  });
});

// ── 7. 加权偏好健康账号 + 坏账号进冷却 ─────────────────────
test('加权偏好健康账号：A 恒 429、B 正常，12 次后 B 占绝大多数且 A 进冷却', async () => {
  await withSetup(badKeyMock(), async ({ proxy, mock }) => {
    await addAccount(proxy, { name: 'A', apiKey: 'user_bad_A' });
    await addAccount(proxy, { name: 'B', apiKey: 'user_good_B' });
    const cli = await addClient(proxy, { name: 'c' });
    for (let i = 0; i < 12; i++) {
      await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    }
    const a = countAuth(mock, 'bad_');
    const b = countAuth(mock, 'good_');
    assert.ok(a <= 3, 'failing account should drop out after ≤3 failures, got ' + a);
    assert.ok(b >= 9, 'healthy account should carry the rest, got ' + b);
    const m = await metrics(proxy);
    const accA = m.accounts.find(x => x.name === 'A');
    assert.equal(accA.cooling, true);
    assert.ok(accA.cooldownUntil > Date.now());
  });
});

// ── 8. reset-metrics 后坏账号重新获流 ──────────────────────
test('reset-metrics 后冷却清除，账号重新获流', async () => {
  await withSetup(badKeyMock(), async ({ proxy, mock }) => {
    const A = await addAccount(proxy, { name: 'A', apiKey: 'user_bad_A' });
    await addAccount(proxy, { name: 'B', apiKey: 'user_good_B' });
    const cli = await addClient(proxy, { name: 'c' });
    for (let i = 0; i < 12; i++) await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    assert.equal((await metrics(proxy)).accounts.find(x => x.name === 'A').cooling, true);

    const before = countAuth(mock, 'bad_');
    const rr = await admin(proxy, 'POST', '/admin/api/accounts/' + A.id + '/reset-metrics');
    assert.equal(rr.status, 200);
    assert.equal((await metrics(proxy)).accounts.find(x => x.name === 'A').cooling, false);

    for (let i = 0; i < 12; i++) await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    assert.ok(countAuth(mock, 'bad_') > before, 'reset account should receive traffic again');
  });
});

// ── 9. PUT routing 热生效（进程未重启）─────────────────────
test('PUT /admin/api/routing 热改权重：200 且无需重启', async () => {
  await withSetup(MAIN, async ({ proxy, mock }) => {
    const pid = proxy.child.pid;
    const r = await admin(proxy, 'PUT', '/admin/api/routing', { weights: { successRate: 0.9, latency: 0.05, load: 0.05 } });
    assert.equal(r.status, 200);
    const got = await (await admin(proxy, 'GET', '/admin/api/routing')).json();
    assert.equal(got.routing.weights.successRate, 0.9);
    // 进程仍是同一个、仍在服务
    assert.equal(proxy.child.pid, pid);
    assert.equal(proxy.child.exitCode, null);
    const live = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer user_test' });
    assert.equal(live.status, 200);
    assert.equal(String(mock.lastGenerate().headers.authorization), 'Bearer user_test');
    // 非法权重和 → 400
    const bad = await admin(proxy, 'PUT', '/admin/api/routing', { weights: { successRate: 0, latency: 0, load: 0 } });
    assert.equal(bad.status, 400);
  });
});

// ── 10 & 11. legacy 直通 / 未知凭据 401 ────────────────────
test('legacy 回归：user_xxx 原样透传，未知凭据 401 文案一致', async () => {
  await withSetup(MAIN, async ({ proxy, mock }) => {
    const ok = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer user_test' });
    assert.equal(ok.status, 200);
    assert.equal(routeAuth(mock), 'Bearer user_test');
    assert.equal((await metrics(proxy)).totals.accounts, 0);
    assert.equal((await metrics(proxy)).inflight, 0);

    const bad = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer invalid_token' });
    assert.equal(bad.status, 401);
    const j = await bad.json();
    assert.equal(j.error.message, 'Missing API key. Send in Authorization: Bearer <key> or x-api-key header');
  });
});

// ── 12. 白名单只指向禁用账号 → 503 no_available_account ────
test('client 白名单仅指向禁用账号 → 503 no_available_account，且不含 key', async () => {
  await withSetup(MAIN, async ({ proxy }) => {
    const A = await addAccount(proxy, { name: 'A', apiKey: 'user_disabled_A', enabled: false });
    const cli = await addClient(proxy, { name: 'c', accountIds: [A.id] });
    const r = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    assert.equal(r.status, 503);
    const txt = await r.text();
    assert.ok(txt.includes('no_available_account'));
    assert.ok(!txt.includes('user_'));
  });
});

// ── 13. /v1/messages 与 /v1/responses 同样发池 key ─────────
test('/v1/messages（x-api-key）与 /v1/responses 同样发池 key', async () => {
  await withSetup(MAIN, async ({ proxy, mock }) => {
    await addAccount(proxy, { name: 'A', apiKey: 'user_msgs_KEY' });
    const cli = await addClient(proxy, { name: 'c' });

    const msgs = await proxy.post('/v1/messages',
      { model: 'm', max_tokens: 50, messages: [{ role: 'user', content: 'hi' }] },
      { 'x-api-key': cli.token });
    assert.equal(msgs.status, 200);
    assert.equal(routeAuth(mock), 'Bearer user_msgs_KEY');

    const resp = await proxy.post('/v1/responses', { model: 'm', input: 'hi' }, { Authorization: 'Bearer ' + cli.token });
    assert.equal(resp.status, 200);
    assert.equal(routeAuth(mock), 'Bearer user_msgs_KEY');
  });
});

// ── 14. 持久化：新增后落盘 ─────────────────────────────────
test('持久化：新增账号写入 workdir/accounts.json', async () => {
  await withSetup(MAIN, async ({ proxy }) => {
    const A = await addAccount(proxy, { name: 'persist-A', apiKey: 'user_persist_KEY' });
    const cli = await addClient(proxy, { name: 'persist-c' });
    const file = join(proxy.workdir, 'accounts.json');
    const data = JSON.parse(readFileSync(file, 'utf8'));
    assert.ok(data.accounts.some(a => a.id === A.id && a.apiKey === 'user_persist_KEY'));
    assert.ok(data.clients.some(c => c.id === cli.id && c.token === cli.token));
    assert.ok(data.routing && data.routing.weights);
  });
});

// ── 15. 并发在途：期间 >0，结束归零（finally 无泄漏）───────
test('并发负载：metrics.inFlight 期间 >0，结束后归零', async () => {
  const slow = {
    env: { CC_ADMIN_TOKEN: ADMIN_TOKEN },
    onRequest: async (req) => { if (req.url === '/alpha/generate') await sleep(320); },
  };
  await withSetup(slow, async ({ proxy }) => {
    await addAccount(proxy, { name: 'A', apiKey: 'user_slow_KEY' });
    const cli = await addClient(proxy, { name: 'c' });
    const auth = { Authorization: 'Bearer ' + cli.token };
    const reqs = Array.from({ length: 4 }, () => proxy.post('/v1/chat/completions', CHAT, auth));
    await sleep(140);
    const mid = await metrics(proxy);
    assert.ok(mid.inflight > 0, 'in-flight should be > 0 during load, got ' + mid.inflight);
    await Promise.all(reqs);
    await sleep(80);
    const end = await metrics(proxy);
    assert.equal(end.inflight, 0);
    assert.equal(end.accounts.find(x => x.name === 'A').components.inFlight, 0);
  });
});

// ── 16. UI 静态自测：零机密外壳 ────────────────────────────
test('GET /admin 200 含 <html>，无未转义模板残迹，不含账号 key', async () => {
  await withSetup(MAIN, async ({ proxy }) => {
    const raw = 'user_ui_SECRET_KEY_9';
    await addAccount(proxy, { name: 'ui-A', apiKey: raw });
    const r = await proxy.get('/admin');
    assert.equal(r.status, 200);
    const t = await r.text();
    assert.ok(t.includes('<html'), 'should be an HTML shell');
    assert.ok(!t.includes('${'), 'no un-interpolated template residue');
    assert.ok(!t.includes(raw), 'shell must not contain any account key');
    assert.ok(!t.includes('innerHTML'), 'shell must not use innerHTML for data');
    assert.match(r.headers.get('content-security-policy') || '', /default-src 'none'/);
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
  });
});