import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import vm from 'node:vm';
import { setup } from './helpers.mjs';

const ADMIN_TOKEN = 'expiring_boost_test';
const ADMIN = { 'x-admin-token': ADMIN_TOKEN };
const DAY_MS = 86400000;
const NOW = Date.UTC(2030, 0, 1);
const period = days => new Date(NOW + days * DAY_MS).toISOString();

async function admin(proxy, method, path, body) {
  const response = await fetch(proxy.base + '/admin/api/' + path, {
    method,
    headers: { ...ADMIN, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  assert.ok(response.ok, await response.clone().text());
  return response.json();
}

function json(response, body, status = 200) {
  response.writeHead(status, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(body));
  return true;
}

async function withPool(fixtures, run) {
  const directory = mkdtempSync(join(tmpdir(), 'ccp-expiring-clock-'));
  const clock = join(directory, 'clock.cjs');
  writeFileSync(clock, 'Date.now = () => ' + NOW + ';\n');
  const snapshots = fixtures.map((fixture, index) => ({
    remaining: 8, known: true, ...fixture, apiKey: 'user_expiring_' + index,
  }));
  const state = new Map(snapshots.map(snapshot => [snapshot.apiKey, snapshot]));
  let harness;
  try {
    harness = await setup({
      env: {
        CC_ADMIN_TOKEN: ADMIN_TOKEN,
        CC_USAGE_REFRESH_MS: '60000',
        NODE_OPTIONS: [process.env.NODE_OPTIONS, '--require=' + clock].filter(Boolean).join(' '),
      },
      onRequest(request, response) {
        const snapshot = state.get(request.headers.authorization?.replace('Bearer ', ''));
        if (!snapshot) return false;
        if (request.url.startsWith('/alpha/whoami')) return json(response, { org: { id: snapshot.apiKey } });
        if (request.url.startsWith('/alpha/billing/credits')) return json(response, {
          credits: snapshot.known ? { planId: 'individual-go', monthlyCredits: snapshot.remaining } : {},
          windowLimits: snapshot.windowLimits,
        });
        if (request.url.startsWith('/alpha/billing/subscriptions')) return json(response, { data: {
          planId: snapshot.known ? 'individual-go' : undefined,
          status: 'active', currentPeriodEnd: snapshot.currentPeriodEnd,
        } });
        if (request.url === '/alpha/generate' && snapshot.rejectCredit) return json(response, {
          message: 'You have insufficient credits to make this request',
        }, 400);
        return false;
      },
    });
    const { proxy } = harness;
    const { routing: defaults } = await admin(proxy, 'GET', 'routing');
    const routing = async patch => {
      const { routing: current } = await admin(proxy, 'GET', 'routing');
      return (await admin(proxy, 'PUT', 'routing', { ...current, ...patch })).routing;
    };
    await routing({ expiringBoostEnabled: true, selection: 'best', creditFailoverMax: 0 });
    const accounts = [];
    const usage = account => admin(proxy, 'GET', 'accounts/' + account.id + '/usage?refresh=1');
    for (const snapshot of snapshots) {
      const { account } = await admin(proxy, 'POST', 'accounts', {
        name: snapshot.apiKey, apiKey: snapshot.apiKey, weight: 1,
      });
      accounts.push(account);
      assert.equal((await usage(account)).usage.ok, true);
    }
    const metrics = async () => (await admin(proxy, 'GET', 'metrics')).accounts;
    const chat = async () => {
      const { client } = await admin(proxy, 'POST', 'clients', { name: 'expiring-client' });
      const response = await proxy.post('/v1/chat/completions', {
        model: 'm', messages: [{ role: 'user', content: 'hi' }], max_tokens: 32,
      }, { Authorization: 'Bearer ' + client.token });
      await response.text();
      return response.status;
    };
    await run({ ...harness, snapshots, accounts, defaults, routing, metrics, usage, chat });
  } finally {
    if (harness) await harness.close();
    rmSync(directory, { recursive: true, force: true });
  }
}

function report(context, label, accounts) {
  context.diagnostic(label + ': ' + JSON.stringify(accounts.map(account => ({
    score: account.score,
    remaining: account.components.remaining,
    periodEndAt: account.components.periodEndAt,
    expiringBoostApplied: account.components.expiringBoostApplied,
    creditExhausted: account.creditExhausted,
    windowExhausted: account.windowExhausted,
  }))));
}

test('expiring 1: six-day account scores 100x the identical thirty-day control', async context => {
  await withPool([{ currentPeriodEnd: period(6) }, { currentPeriodEnd: period(30) }], async ({ metrics }) => {
    const [soon, control] = await metrics();
    assert.equal(soon.components.expiringBoostApplied, true);
    assert.equal(control.components.expiringBoostApplied, false);
    assert.equal(soon.components.periodEndAt, NOW + 6 * DAY_MS);
    assert.equal(soon.components.base, control.components.base);
    assert.equal(soon.components.weightFactor, control.components.weightFactor);
    assert.ok(soon.score > control.score * 50);
    assert.equal(soon.score, control.score * 100);
    report(context, 'six days / thirty days', [soon, control]);
  });
});

test('expiring 2: eight days and seven days plus 1ms do not boost; exactly seven days does', async context => {
  await withPool([
    { currentPeriodEnd: period(8) },
    { currentPeriodEnd: period(7) },
    { currentPeriodEnd: new Date(NOW + 7 * DAY_MS + 1).toISOString() },
  ], async ({ proxy, metrics }) => {
    const [outside, boundary, beyond] = await metrics();
    assert.equal(outside.components.expiringBoostApplied, false);
    assert.equal(beyond.components.expiringBoostApplied, false);
    const snapshot = await admin(proxy, 'GET', 'metrics');
    assert.equal(Date.parse(snapshot.startedAt) + snapshot.uptimeMs, NOW);
    assert.equal(boundary.components.periodEndAt - NOW, 7 * DAY_MS);
    assert.equal(boundary.components.expiringBoostApplied, true, 'exactly seven days must be included');
    assert.equal(boundary.score, outside.score * 100);
    report(context, 'eight days / exactly seven days / seven days plus 1ms', [outside, boundary, beyond]);
  });
});

test('expiring 3: disabling the switch removes the boost from a six-day account', async context => {
  await withPool([{ currentPeriodEnd: period(6) }], async ({ routing, metrics }) => {
    const [enabled] = await metrics();
    assert.equal(enabled.components.expiringBoostApplied, true);
    await routing({ expiringBoostEnabled: false });
    const [disabled] = await metrics();
    assert.equal(disabled.components.expiringBoostApplied, false);
    assert.equal(enabled.score, disabled.score * 100);
    report(context, 'switch enabled / disabled', [enabled, disabled]);
  });
});

for (const [label, currentPeriodEnd] of [['missing', undefined], ['invalid', 'not-a-date']]) {
  test('expiring 4: ' + label + ' currentPeriodEnd stays null and does not boost or throw', async context => {
    await withPool([{ currentPeriodEnd }], async ({ metrics }) => {
      const [account] = await metrics();
      assert.equal(account.components.periodEndAt, null);
      assert.equal(account.components.expiringBoostApplied, false);
      assert.ok(Number.isFinite(account.score));
      assert.ok(account.score > 0);
      report(context, label + ' period', [account]);
    });
  });
}

test('expiring 5: zero balance never boosts; credit exhaustion keeps score zero and prevents selection', async context => {
  await withPool([{ currentPeriodEnd: period(6), remaining: 0, rejectCredit: true }], async ({ metrics, chat, mock }) => {
    const [empty] = await metrics();
    assert.equal(empty.components.remaining, 0);
    assert.equal(empty.components.expiringBoostApplied, false, 'zero balance must not boost even before a rejection');
    assert.equal(await chat(), 400);
    const [blocked] = await metrics();
    assert.equal(blocked.creditExhausted, true);
    assert.equal(blocked.components.remaining, 0);
    assert.equal(blocked.components.expiringBoostApplied, false);
    assert.equal(blocked.score, 0);
    const generated = mock.generateCount();
    assert.equal(generated, 1);
    assert.equal(await chat(), 503);
    assert.equal(mock.generateCount(), generated);
    report(context, 'empty before rejection / credit exhausted', [empty, blocked]);
  });
});

test('expiring 6 credit: a blocked account with positive balance cannot be marked boosted', async context => {
  await withPool([{ currentPeriodEnd: period(6), remaining: 0.1, rejectCredit: true }], async ({ metrics, chat }) => {
    assert.equal((await metrics())[0].components.expiringBoostApplied, true);
    assert.equal(await chat(), 400);
    const [blocked] = await metrics();
    assert.equal(blocked.creditExhausted, true);
    assert.ok(blocked.components.remaining > 0);
    assert.equal(blocked.components.periodEndAt, NOW + 6 * DAY_MS);
    assert.equal(blocked.score, 0);
    assert.equal(blocked.components.expiringBoostApplied, false, 'credit block must override the boost');
    report(context, 'credit block with positive balance', [blocked]);
  });
});

test('expiring 6 window: an exhausted window overrides an otherwise eligible boost', async context => {
  await withPool([{
    currentPeriodEnd: period(6),
    windowLimits: {
      limited: true,
      fiveHour: { used: 3, cap: 3, exceeded: true, resetAt: NOW + 3600000 },
      weekly: { used: 3, cap: 6, exceeded: false, resetAt: NOW + DAY_MS },
    },
  }], async ({ metrics, chat, mock }) => {
    const [blocked] = await metrics();
    assert.equal(blocked.creditExhausted, false);
    assert.equal(blocked.windowExhausted, true);
    assert.ok(blocked.components.remaining > 0);
    assert.equal(blocked.components.periodEndAt, NOW + 6 * DAY_MS);
    assert.equal(blocked.score, 0);
    assert.equal(blocked.components.expiringBoostApplied, false, 'window block must override the boost');
    assert.equal(await chat(), 503);
    assert.equal(mock.generateCount(), 0);
    report(context, 'window block with positive balance', [blocked]);
  });
});

test('expiring 7: expired periods and a period ending exactly now do not boost', async context => {
  await withPool([
    { currentPeriodEnd: new Date(NOW - 1).toISOString() },
    { currentPeriodEnd: period(0) },
  ], async ({ metrics }) => {
    const accounts = await metrics();
    assert.equal(accounts[0].components.periodEndAt, NOW - 1);
    assert.equal(accounts[1].components.periodEndAt, NOW);
    for (const account of accounts) {
      assert.equal(account.components.expiringBoostApplied, false);
      assert.ok(account.score > 0);
    }
    report(context, 'expired by 1ms / exactly now', accounts);
  });
});

test('expiring: unknown remaining balance does not boost despite a valid six-day period', async context => {
  await withPool([{ currentPeriodEnd: period(6), known: false }], async ({ metrics }) => {
    const [account] = await metrics();
    assert.equal(account.components.remaining, null);
    assert.equal(account.components.periodEndAt, NOW + 6 * DAY_MS);
    assert.equal(account.components.expiringBoostApplied, false);
    report(context, 'unknown remaining balance', [account]);
  });
});

test('expiring: missing or invalid refresh and reset-metrics preserve a known period', async () => {
  await withPool([{ currentPeriodEnd: period(6) }], async ({ proxy, snapshots, accounts, usage, metrics }) => {
    for (const currentPeriodEnd of [undefined, 'not-a-date']) {
      snapshots[0].currentPeriodEnd = currentPeriodEnd;
      assert.equal((await usage(accounts[0])).usage.ok, true);
      const [account] = await metrics();
      assert.equal(account.components.periodEndAt, NOW + 6 * DAY_MS);
      assert.equal(account.components.expiringBoostApplied, true);
    }
    await admin(proxy, 'POST', 'accounts/' + accounts[0].id + '/reset-metrics');
    const [reset] = await metrics();
    assert.equal(reset.components.periodEndAt, NOW + 6 * DAY_MS);
    assert.equal(reset.components.expiringBoostApplied, true);
  });
});

test('expiring: routing defaults, clamps, strict boolean and full-replacement semantics', async () => {
  await withPool([], async ({ proxy, defaults, routing }) => {
    assert.equal(defaults.expiringBoostEnabled, false);
    assert.equal(defaults.expiringWindowDays, 7);
    assert.equal(defaults.expiringBoost, 100);
    for (const [days, boost, expectedDays, expectedBoost] of [[0, 0, 1, 1], [91, 10001, 90, 10000]]) {
      const applied = await routing({ expiringWindowDays: days, expiringBoost: boost });
      assert.equal(applied.expiringWindowDays, expectedDays);
      assert.equal(applied.expiringBoost, expectedBoost);
    }
    const strict = await routing({ expiringBoostEnabled: 1 });
    assert.equal(strict.expiringBoostEnabled, false);
    const { routing: replaced } = await admin(proxy, 'PUT', 'routing', {});
    assert.equal(replaced.expiringBoostEnabled, false);
    assert.equal(replaced.expiringWindowDays, 7);
    assert.equal(replaced.expiringBoost, 100);
  });
});

class PanelElement {
  constructor(tagName) {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.textContent = '';
    this.classList = { add() {}, remove() {} };
  }
  appendChild(child) { this.children.push(child); child.parentNode = this; return child; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); child.parentNode = null; }
  get firstChild() { return this.children[0]; }
  addEventListener() {}
  getAttribute(name) { return this[name]; }
}

function nodesOf(root) {
  return [root, ...root.children.flatMap(nodesOf)];
}

async function panel(proxy) {
  const data = {};
  for (const path of ['accounts', 'clients', 'routing', 'metrics', 'config']) data[path] = await admin(proxy, 'GET', path);
  const response = await proxy.get('/admin');
  assert.equal(response.status, 200);
  const html = await response.text();
  const elements = Object.fromEntries(['view', 'stats', 'tabs', 'logout', 'app', 'toasts']
    .map(id => [id, new PanelElement('div')]));
  const tab = new PanelElement('button');
  tab['data-tab'] = 'routing';
  elements.tabs.appendChild(tab);
  const requests = [];
  const context = vm.createContext({
    document: {
      getElementById: id => elements[id], createElement: tag => new PanelElement(tag),
      querySelector: () => null, addEventListener() {}, body: new PanelElement('body'),
    },
    sessionStorage: { getItem: () => ADMIN_TOKEN },
    setInterval() {}, clearInterval() {}, setTimeout() {},
    MutationObserver: class { observe() {} },
    fetch: async (path, options) => {
      requests.push({ path, options });
      return { ok: true, status: 200, text: async () => JSON.stringify(data[path.split('/').pop()] || {}) };
    },
  });
  for (const script of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) vm.runInContext(script[1], context);
  await new Promise(resolve => setImmediate(resolve));
  return { root: elements.view, tab, requests };
}

test('expiring 8: actual account cards render the badge only when applied, never undefined', async context => {
  await withPool([{ currentPeriodEnd: period(6) }, { currentPeriodEnd: period(30) }], async ({ proxy, routing }) => {
    const { root } = await panel(proxy);
    const cards = nodesOf(root).filter(node => node.className?.startsWith('card '));
    assert.equal(cards.length, 2);
    const badges = cards.map(card => nodesOf(card).filter(node => node.textContent.startsWith('快重置')));
    assert.deepEqual(badges.map(items => items.map(item => item.textContent)), [['快重置 ×100'], []]);
    assert.ok(badges[0][0].className.includes('badge'));
    assert.ok(nodesOf(root).every(node => !node.textContent.includes('×undefined')));
    await routing({ expiringBoostEnabled: false });
    const disabled = await panel(proxy);
    assert.ok(nodesOf(disabled.root).every(node => !node.textContent.includes('快重置')));
    context.diagnostic('rendered badges: ' + JSON.stringify(badges.map(items => items.map(item => item.textContent)))
      + '; switch off: []');
  });
});

test('expiring: panel controls initialize correctly and save all three settings via PUT', async () => {
  await withPool([], async ({ proxy }) => {
    const { root, tab, requests } = await panel(proxy);
    tab.onclick();
    const nodes = nodesOf(root);
    const input = label => {
      const field = nodes.find(node => node.children.some(child => child.textContent === label));
      assert.ok(field, label);
      return field.children.find(child => child.tagName === 'INPUT');
    };
    const enabled = input('启用快重置优先 expiringBoostEnabled');
    const days = input('快重置界限（天） expiringWindowDays');
    const boost = input('快重置倍数 expiringBoost');
    assert.equal(enabled.type, 'checkbox');
    assert.equal(enabled.checked, true);
    assert.equal(Number(days.value), 7);
    assert.equal(Number(days.min), 1);
    assert.equal(Number(days.max), 90);
    assert.equal(Number(boost.value), 100);
    assert.equal(Number(boost.min), 1);
    assert.equal(Number(boost.max), 10000);
    enabled.checked = false;
    days.value = '3.5';
    boost.value = '250';
    nodes.find(node => node.textContent === '保存路由配置').onclick();
    const saved = requests.find(request => request.options.method === 'PUT');
    assert.ok(saved);
    assert.equal(saved.path, '/admin/api/routing');
    const payload = JSON.parse(saved.options.body);
    assert.equal(payload.expiringBoostEnabled, false);
    assert.equal(payload.expiringWindowDays, 3.5);
    assert.equal(payload.expiringBoost, 250);
    const { routing: applied } = await admin(proxy, 'PUT', 'routing', payload);
    assert.equal(applied.expiringBoostEnabled, false);
    assert.equal(applied.expiringWindowDays, 3.5);
    assert.equal(applied.expiringBoost, 250);
  });
});
