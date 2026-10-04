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

test('旧 creditCooldownMs 配置被丢弃，不保留原始值', async () => {
  await withSetup(MAIN, async ({ proxy }) => {
    for (const value of [3600000, 'invalid', -1, { value: 999999999 }]) {
      const response = await admin(proxy, 'PUT', '/admin/api/routing', {
        creditCooldownMs: value,
      });
      assert.equal(response.status, 200);
      const saved = await response.json();
      assert.equal(Object.hasOwn(saved.routing, 'creditCooldownMs'), false);
      const got = await (await admin(proxy, 'GET', '/admin/api/routing')).json();
      assert.equal(Object.hasOwn(got.routing, 'creditCooldownMs'), false);
      const stored = JSON.parse(readFileSync(join(proxy.workdir, 'accounts.json'), 'utf8'));
      assert.equal(Object.hasOwn(stored.routing, 'creditCooldownMs'), false);
    }
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

// 额度 mock：模拟 CC 官方 4 个只读额度端点
function usageMock(opts = {}) {
  const json = (res, o) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  return {
    env: { CC_ADMIN_TOKEN: ADMIN_TOKEN },
    ...opts,
    onRequest(req, res) {
      const u = req.url;
      if (opts.failWhoami && u.startsWith('/alpha/whoami')) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'boom' } }));
        return;
      }
      if (u.startsWith('/alpha/whoami')) {
        return json(res, { org: { id: 'org_1', login: 'acme' }, user: { userName: 'u1' }, orgLimits: [] });
      }
      if (u.startsWith('/alpha/billing/credits')) {
        return json(res, { credits: { planId: 'individual-goat', monthlyCredits: 12.5, purchasedCredits: 3, freeCredits: 0 } });
      }
      if (u.startsWith('/alpha/billing/subscriptions')) {
        return json(res, { data: { planId: 'individual-goat', status: 'active', currentPeriodStart: new Date(Date.now() - 86400000).toISOString(), currentPeriodEnd: new Date(Date.now() + 86400000).toISOString() } });
      }
      if (u.startsWith('/alpha/usage/summary')) return json(res, { totalCost: 20 });
    },
  };
}
const whoamiHits = (mock) => mock.seen.filter(s => s.url.startsWith('/alpha/whoami')).length;

// ── 17. 额度归一化 + 掩码 + 缓存 ────────────────────────────
test('额度查看：/admin/api/usage 归一化套餐/余额、不回显 key、命中缓存', async () => {
  await withSetup(usageMock(), async ({ proxy, mock }) => {
    const raw = 'user_quota_KEY_42';
    const acc = await addAccount(proxy, { name: 'quota-A', apiKey: raw });
    const r = await admin(proxy, 'GET', '/admin/api/usage');
    assert.equal(r.status, 200);
    const txt = await r.text();
    assert.ok(!txt.includes(raw), 'usage response must not echo the upstream key');
    const body = JSON.parse(txt);
    const u = body.usage[0];
    assert.equal(u.id, acc.id);
    assert.equal(u.ok, true);
    assert.equal(u.plan.name, 'GOAT');
    assert.equal(u.credits.monthlyRemaining, 12.5);
    assert.equal(u.credits.purchasedRemaining, 3);
    assert.equal(u.credits.totalRemaining, 15.5);
    assert.equal(u.whoami.orgLogin, 'acme');
    assert.equal(u.subscription.status, 'active');
    assert.ok(u.daysLeft > 0);

    // 二次 GET 命中 5 分钟缓存：不再打上游
    const before = whoamiHits(mock);
    await admin(proxy, 'GET', '/admin/api/usage');
    assert.equal(whoamiHits(mock), before, 'cached call should not hit upstream again');
    // ?refresh=1 强制绕过缓存
    await admin(proxy, 'GET', '/admin/api/usage?refresh=1');
    assert.ok(whoamiHits(mock) > before, 'refresh=1 must refetch from upstream');
  });
});

// ── 18. 单账号额度 + 上游异常降级 + 404 ────────────────────
test('额度查看：/admin/api/accounts/:id/usage 单账号；上游异常降级为 ok:false', async () => {
  await withSetup(usageMock({ failWhoami: true }), async ({ proxy }) => {
    const acc = await addAccount(proxy, { name: 'quota-B', apiKey: 'user_quota_B' });
    const one = await admin(proxy, 'GET', '/admin/api/accounts/' + acc.id + '/usage');
    assert.equal(one.status, 200);
    const view = (await one.json()).usage;
    assert.equal(view.id, acc.id);
    assert.equal(view.ok, false);
    assert.equal(view.error, 'upstream_500');

    const all = await admin(proxy, 'GET', '/admin/api/usage');
    assert.equal(all.status, 200);
    assert.equal((await all.json()).usage[0].ok, false);

    const missing = await admin(proxy, 'GET', '/admin/api/accounts/acc_nope/usage');
    assert.equal(missing.status, 404);
  });
});

// 额度耗尽 mock：/alpha/generate 上「穷」key 返回 400 insufficient credits，其余放行
function creditMock(opts = {}) {
  return {
    env: { CC_ADMIN_TOKEN: ADMIN_TOKEN },
    ...opts,
    onRequest(req, res) {
      if (req.url !== '/alpha/generate') return creditUsageMock(opts).onRequest(req, res);
      const auth = String(req.headers.authorization || '');
      if (opts.rejectAll || auth.includes('poor_')) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: false,
          error: { code: 'USAGE_EXCEEDED', message: 'You have insufficient credits to make this request. Please purchase more credits to continue using the service.' },
        }));
      }
    },
  };
}
const putRouting = (proxy, body) =>
  admin(proxy, 'PUT', '/admin/api/routing', body).then(r => r.json());
const accountOf = (m, id) => m.accounts.find(a => a.id === id);

// ── 19. 额度耗尽 → 同请求自动换号（客户端无感）+ 长冷却 ──────
test('额度耗尽：同请求自动换号成功，耗尽账号进入长冷却', async () => {
  await withSetup(creditMock(), async ({ proxy, mock }) => {
    const poor = await addAccount(proxy, { name: 'poor', apiKey: 'user_poor_AAA', weight: 10 });
    const rich = await addAccount(proxy, { name: 'rich', apiKey: 'user_rich_BBB', weight: 1 });
    await putRouting(proxy, { selection: 'best' });
    const cli = await addClient(proxy, { name: 'c' });

    const r = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    assert.equal(r.status, 200, await r.text());
    assert.equal(countAuth(mock, 'user_poor_AAA'), 1, 'poor account must be tried exactly once');
    assert.equal(routeAuth(mock), 'Bearer user_rich_BBB', 'final attempt must use the rich account');

    const m = await metrics(proxy);
    const mp = accountOf(m, poor.id), mr = accountOf(m, rich.id);
    assert.equal(mp.creditExhausted, true);
    assert.equal(mp.cooling, true);
    assert.ok(mp.creditResetAt > Date.now());
    assert.equal(mp.cooldownUntil, mp.creditResetAt);
    assert.equal(whoamiHits(mock), 1, '明确错误也查询套餐时间');
    assert.equal(mr.creditExhausted, false);
  });
});

// ── 20. 全部账号额度耗尽 → 返回错误，且都被长冷却 ────────────
test('额度耗尽：全部账号耗尽时透出上游 400，且账号都在长冷却', async () => {
  await withSetup(creditMock({ rejectAll: true }), async ({ proxy }) => {
    const a1 = await addAccount(proxy, { name: 'a1', apiKey: 'user_poor_A1', weight: 10 });
    const a2 = await addAccount(proxy, { name: 'a2', apiKey: 'user_poor_A2', weight: 1 });
    await putRouting(proxy, { selection: 'best' });
    const cli = await addClient(proxy, { name: 'c' });

    const r = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    assert.equal(r.status, 400);
    const m = await metrics(proxy);
    for (const id of [a1.id, a2.id]) {
      assert.equal(accountOf(m, id).creditExhausted, true);
      assert.equal(accountOf(m, id).cooling, true);
    }
    const blocked = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    assert.equal(blocked.status, 503, '全部耗尽不得 fail-open');
    assert.ok((await blocked.text()).includes('no_available_account'));
  });
});

// ── 21. creditFailoverMax=0 → 不换号但仍长冷却 ──────────────
test('额度耗尽：creditFailoverMax=0 时不换号，但仍立即长冷却', async () => {
  await withSetup(creditMock({ rejectAll: true }), async ({ proxy, mock }) => {
    const a1 = await addAccount(proxy, { name: 'a1', apiKey: 'user_poor_A1', weight: 10 });
    await putRouting(proxy, { selection: 'best', creditFailoverMax: 0 });
    const cli = await addClient(proxy, { name: 'c' });

    const r = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    assert.equal(r.status, 400);
    assert.equal(countAuth(mock, 'user_poor_A1'), 1, 'no failover attempt expected');
    const mm = accountOf(await metrics(proxy), a1.id);
    assert.equal(mm.creditExhausted, true);
    assert.equal(mm.cooling, true);
  });
});

// ── 22. /v1/messages 走同一套换号逻辑 ───────────────────────
test('额度耗尽：/v1/messages 同样自动换号', async () => {
  await withSetup(creditMock(), async ({ proxy, mock }) => {
    const poor = await addAccount(proxy, { name: 'poor', apiKey: 'user_poor_M', weight: 10 });
    await addAccount(proxy, { name: 'rich', apiKey: 'user_rich_M', weight: 1 });
    await putRouting(proxy, { selection: 'best' });
    const cli = await addClient(proxy, { name: 'c' });

    const r = await proxy.post('/v1/messages',
      { model: 'm', max_tokens: 50, messages: [{ role: 'user', content: 'hi' }] },
      { Authorization: 'Bearer ' + cli.token });
    assert.equal(r.status, 200, await r.text());
    assert.equal(countAuth(mock, 'user_poor_M'), 1);
    assert.equal(routeAuth(mock), 'Bearer user_rich_M');
    assert.equal(accountOf(await metrics(proxy), poor.id).creditExhausted, true);
  });
});

// 额度查询 mock：可切换「已充值」；穷号余额 0.10/套餐 10 → 已用 99%
function creditUsageMock(opts = {}) {
  const state = opts.state || { topUp: false };
  if (!Object.hasOwn(state, 'resetAt')) state.resetAt = new Date(Date.now() + 86400000).toISOString();
  const json = (res, o) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  return {
    state,
    env: { CC_ADMIN_TOKEN: ADMIN_TOKEN },
    ...opts,
    async onRequest(req, res) {
      const u = req.url;
      const auth = String(req.headers.authorization || '');
      const poor = auth.includes('poor_');
      // 上游 400 用「不认识」的文案，逼出额度兜底判定（而非文案匹配）
      if (u === '/alpha/generate' && poor) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { code: 'INVALID_ARGUMENT', message: 'request rejected by upstream' } }));
        return;
      }
      if (u.startsWith('/alpha/whoami')) {
        if (opts.usageDelay) await sleep(opts.usageDelay);
        if (state.failUsage) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'usage unavailable' } }));
          return;
        }
        return json(res, { org: { id: 'org_1', login: 'acme' }, user: { userName: 'u1' }, orgLimits: [] });
      }
      if (u.startsWith('/alpha/billing/credits')) {
        const remain = (state.topUp || !poor) ? 10 : 0.10;
        return json(res, { credits: { planId: 'individual-go', monthlyCredits: remain, purchasedCredits: 0, freeCredits: 0 } });
      }
      if (u.startsWith('/alpha/billing/subscriptions')) {
        return json(res, { data: { planId: 'individual-go', status: state.subscriptionStatus || 'active', currentPeriodStart: new Date(Date.now() - 86400000).toISOString(), currentPeriodEnd: state.resetAt } });
      }
      if (u.startsWith('/alpha/usage/summary')) return json(res, { totalCost: 0 });
    },
  };
}

// ── 23. 额度兜底：已用≥95% + 非标准 400 → 判为额度耗尽并换号 ──
test('额度兜底：已用≥95% 且上游 400（文案不认识）时也换号并长冷却', async () => {
  await withSetup(creditUsageMock(), async ({ proxy, mock }) => {
    const poor = await addAccount(proxy, { name: 'poor', apiKey: 'user_poor_U', weight: 10 });
    const rich = await addAccount(proxy, { name: 'rich', apiKey: 'user_rich_U', weight: 1 });
    await putRouting(proxy, { selection: 'best' });
    const cli = await addClient(proxy, { name: 'c' });

    assert.equal(whoamiHits(mock), 0, 'no preloaded usage cache');

    const r = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    assert.equal(r.status, 200, await r.text());
    assert.equal(countAuth(mock, 'user_poor_U'), 1);
    assert.equal(routeAuth(mock), 'Bearer user_rich_U', 'should fail over despite unknown error text');
    assert.equal(whoamiHits(mock), 1, 'one fresh query for the failed attempt only');
    const mm = accountOf(await metrics(proxy), poor.id);
    assert.equal(mm.creditExhausted, true);
    assert.equal(mm.cooling, true);
  });
});

// ── 24. 充值后刷新额度 / 重置指标不能提前解除阻断 ────────────
test('额度兜底：充值查询及重置指标均不能提前解除额度阻断', async () => {
  const state = { topUp: false };
  await withSetup(creditUsageMock({ state }), async ({ proxy }) => {
    const poor = await addAccount(proxy, { name: 'poor', apiKey: 'user_poor_U', weight: 10 });
    await addAccount(proxy, { name: 'rich', apiKey: 'user_rich_U', weight: 1 });
    await putRouting(proxy, { selection: 'best' });
    const cli = await addClient(proxy, { name: 'c' });
    await admin(proxy, 'GET', '/admin/api/usage');   // 播种 99% 已用

    const r = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    assert.equal(r.status, 200);
    assert.equal(accountOf(await metrics(proxy), poor.id).cooling, true, 'should be cooling before top-up');

    // 充值后刷新不能解除套餐时间阻断
    state.topUp = true;
    await admin(proxy, 'GET', '/admin/api/usage?refresh=1');
    const after = accountOf(await metrics(proxy), poor.id);
    assert.equal(after.creditExhausted, true);
    assert.equal(after.cooling, true);
    assert.equal(after.creditResetAt, Date.parse(state.resetAt));
    await admin(proxy, 'POST', '/admin/api/accounts/' + poor.id + '/reset-metrics');
    const reset = accountOf(await metrics(proxy), poor.id);
    assert.equal(reset.creditExhausted, true, '重置指标不能解除额度阻断');
    assert.equal(reset.creditResetAt, after.creditResetAt);
  });
});

for (const [path, body] of [
  ['/v1/chat/completions', CHAT],
  ['/v1/messages', { ...CHAT, max_tokens: 50 }],
  ['/v1/responses', { model: 'm', input: 'hi' }],
]) {
  test('主动额度查询：creditFailoverMax=0 仍查询并长冷却 ' + path, async () => {
    await withSetup(creditUsageMock(), async ({ proxy, mock }) => {
      const poor = await addAccount(proxy, { name: 'poor', apiKey: 'user_poor_zero' });
      await putRouting(proxy, { creditFailoverMax: 0 });
      const cli = await addClient(proxy, { name: 'c' });
      const r = await proxy.post(path, body, { Authorization: 'Bearer ' + cli.token });
      assert.equal(r.status, 400);
      assert.equal(countAuth(mock, 'user_poor_zero'), 1);
      assert.equal(whoamiHits(mock), 1, 'handler must not query again');
      const m = await metrics(proxy);
      assert.equal(accountOf(m, poor.id).creditExhausted, true);
      assert.equal(accountOf(m, poor.id).cooling, true);
      assert.equal(m.inflight, 0);
      assert.equal(accountOf(m, poor.id).totals.requests, 1);
      assert.equal(accountOf(m, poor.id).creditResetAt, Date.parse((await (await admin(proxy, 'GET', '/admin/api/accounts/' + poor.id + '/usage')).json()).usage.subscription.currentPeriodEnd));
      assert.ok(accountOf(m, poor.id).lastError.at <= Date.now());
      assert.equal(accountOf(m, poor.id).lastError.status, 400);
    });
  });
}

for (const refreshState of ['failUsage', 'topUp']) {
  test('主动额度查询：新结果推翻旧耗尽缓存 ' + refreshState, async () => {
    const state = { topUp: false };
    await withSetup(creditUsageMock({ state }), async ({ proxy, mock }) => {
      const poor = await addAccount(proxy, { name: 'poor', apiKey: 'user_poor_stale', weight: 10 });
      await addAccount(proxy, { name: 'rich', apiKey: 'user_rich_stale', weight: 1 });
      await putRouting(proxy, { selection: 'best' });
      const cli = await addClient(proxy, { name: 'c' });
      const seeded = await admin(proxy, 'GET', '/admin/api/accounts/' + poor.id + '/usage');
      assert.ok((await seeded.json()).usage.credits.usagePercent >= 0.95);
      state[refreshState] = true;
      const r = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
      assert.equal(r.status, 400);
      assert.equal((await r.json()).error.message, 'request rejected by upstream');
      assert.equal(whoamiHits(mock), 2, 'failure must refresh even with a cached result');
      assert.equal(countAuth(mock, 'user_rich_stale'), 0);
      const m = await metrics(proxy);
      assert.equal(accountOf(m, poor.id).creditExhausted, false);
      assert.equal(accountOf(m, poor.id).cooling, false);
      assert.equal(m.inflight, 0);
    });
  });
}

test('主动额度查询：达到换号上限的最后失败账号也查询一次', async () => {
  await withSetup(creditUsageMock(), async ({ proxy, mock }) => {
    const a = await addAccount(proxy, { name: 'a', apiKey: 'user_poor_limit_A', weight: 10 });
    const b = await addAccount(proxy, { name: 'b', apiKey: 'user_poor_limit_B', weight: 1 });
    await putRouting(proxy, { selection: 'best', creditFailoverMax: 1 });
    const cli = await addClient(proxy, { name: 'c' });
    const r = await proxy.post('/v1/chat/completions', CHAT, { Authorization: 'Bearer ' + cli.token });
    assert.equal(r.status, 400);
    assert.equal(whoamiHits(mock), 2);
    const m = await metrics(proxy);
    for (const id of [a.id, b.id]) {
      assert.equal(accountOf(m, id).creditExhausted, true);
      assert.equal(accountOf(m, id).cooling, true);
      assert.equal(accountOf(m, id).totals.requests, 1);
      assert.ok(Number.isFinite(accountOf(m, id).creditResetAt));
      assert.equal(accountOf(m, id).cooldownUntil, accountOf(m, id).creditResetAt);
      assert.ok(accountOf(m, id).lastError.at <= Date.now());
    }
    assert.equal(m.inflight, 0);
  });
});

test('主动额度查询：同账号并发失败合并查询，完成后新失败重新查询', async () => {
  await withSetup(creditUsageMock({ state: { topUp: true }, usageDelay: 300 }), async ({ proxy, mock }) => {
    await addAccount(proxy, { name: 'poor', apiKey: 'user_poor_concurrent' });
    const cli = await addClient(proxy, { name: 'c' });
    const auth = { Authorization: 'Bearer ' + cli.token };
    const results = await Promise.all(Array.from({ length: 4 }, () => proxy.post('/v1/chat/completions', CHAT, auth)));
    for (const r of results) assert.equal(r.status, 400);
    assert.equal(whoamiHits(mock), 1);
    const r = await proxy.post('/v1/chat/completions', CHAT, auth);
    assert.equal(r.status, 400);
    assert.equal(whoamiHits(mock), 2, 'in-flight entry must be removed after completion');
    assert.equal((await metrics(proxy)).inflight, 0);
  });
});

for (const [name, fields] of [
  ['未知', { resetAt: null }],
  ['无效', { resetAt: 'not-a-date' }],
  ['过去', { resetAt: new Date(Date.now() - 86400000).toISOString() }],
  ['inactive', { subscriptionStatus: 'inactive' }],
  ['查询失败', { failUsage: true }],
]) {
  test('明确耗尽：' + name + '套餐时间保持硬阻断，后续可登记有效时间', async () => {
    const state = { topUp: false, ...fields };
    await withSetup(creditMock({ state }), async ({ proxy, mock }) => {
      const a = await addAccount(proxy, { name: 'poor', apiKey: 'user_poor_unknown' });
      await putRouting(proxy, { creditFailoverMax: 0 });
      const cli = await addClient(proxy, { name: 'c' });
      const auth = { Authorization: 'Bearer ' + cli.token };
      assert.equal((await proxy.post('/v1/chat/completions', CHAT, auth)).status, 400);
      const m = accountOf(await metrics(proxy), a.id);
      assert.equal(m.creditResetAt, null);
      assert.equal(m.creditResetUnknown, true);
      assert.equal(m.creditBlocked, true);
      assert.equal(m.cooling, true);
      assert.equal(m.score, 0);
      assert.equal((await proxy.post('/v1/chat/completions', CHAT, auth)).status, 503);
      assert.equal(countAuth(mock, 'poor_'), 1);
      state.failUsage = false;
      state.topUp = true;
      state.subscriptionStatus = 'active';
      state.resetAt = new Date(Date.now() + 60000).toISOString();
      await admin(proxy, 'GET', '/admin/api/accounts/' + a.id + '/usage?refresh=1');
      const updated = accountOf(await metrics(proxy), a.id);
      assert.equal(updated.creditResetAt, Date.parse(state.resetAt));
      assert.equal(updated.cooldownUntil, updated.creditResetAt);
      assert.equal(updated.creditBlocked, true);
      assert.equal((await proxy.post('/v1/chat/completions', CHAT, auth)).status, 503);
    });
  });
}

test('套餐重置到期前阻断，到期后选路恢复尝试', async () => {
  const state = { topUp: false };
  const opts = creditUsageMock({ state });
  const baseRequest = opts.onRequest;
  opts.onRequest = (req, res) => {
    if (req.url === '/alpha/generate' && state.topUp) return;
    return baseRequest(req, res);
  };
  await withSetup(opts, async ({ proxy }) => {
    const a = await addAccount(proxy, { name: 'poor', apiKey: 'user_poor_expiry' });
    const cli = await addClient(proxy, { name: 'c' });
    await putRouting(proxy, { creditFailoverMax: 0 });
    const auth = { Authorization: 'Bearer ' + cli.token };
    state.resetAt = new Date(Date.now() + 1500).toISOString();
    assert.equal((await proxy.post('/v1/chat/completions', CHAT, auth)).status, 400);
    assert.equal(accountOf(await metrics(proxy), a.id).cooldownUntil, Date.parse(state.resetAt));
    state.topUp = true;
    assert.equal((await proxy.post('/v1/chat/completions', CHAT, auth)).status, 503);
    await sleep(Math.max(0, Date.parse(state.resetAt) - Date.now()) + 150);
    assert.equal((await proxy.post('/v1/chat/completions', CHAT, auth)).status, 200);
    const m = accountOf(await metrics(proxy), a.id);
    assert.equal(m.creditBlocked, false);
    assert.equal(m.creditResetAt, null);
  });
});

test('旧在途成功不能提前清除额度阻断，成功仍正常记账', async () => {
  const state = { topUp: false };
  const opts = creditMock({ state });
  const baseRequest = opts.onRequest;
  let finish;
  let started;
  const ready = new Promise(resolve => { started = resolve; });
  const gate = new Promise(resolve => { finish = resolve; });
  let generates = 0;
  opts.onRequest = async (req, res) => {
    if (req.url === '/alpha/generate' && ++generates === 1) {
      started();
      await gate;
      return;
    }
    return baseRequest(req, res);
  };
  await withSetup(opts, async ({ proxy }) => {
    const a = await addAccount(proxy, { name: 'poor', apiKey: 'user_poor_inflight' });
    const cli = await addClient(proxy, { name: 'c' });
    await putRouting(proxy, { creditFailoverMax: 0 });
    const auth = { Authorization: 'Bearer ' + cli.token };
    const success = proxy.post('/v1/chat/completions', CHAT, auth);
    await ready;
    try {
      assert.equal((await proxy.post('/v1/chat/completions', CHAT, auth)).status, 400);
    } finally { finish(); }
    assert.equal((await success).status, 200);
    const m = accountOf(await metrics(proxy), a.id);
    assert.equal(m.creditBlocked, true);
    assert.equal(m.creditResetAt, Date.parse(state.resetAt));
    assert.equal(m.cooldownUntil, m.creditResetAt);
    assert.equal(m.totals.ok, 1);
    assert.equal(m.totals.fail, 1);
    assert.equal(m.inFlight, 0);
    assert.equal((await proxy.post('/v1/chat/completions', CHAT, auth)).status, 503);
  });
});