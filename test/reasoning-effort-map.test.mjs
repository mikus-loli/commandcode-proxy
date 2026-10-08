// Hermes 客户端用 OpenAI 风格的档位词（none/minimal）与自家档位 ultra，
// 但 CC 的 params.reasoning_effort 只接受 off|low|medium|high|xhigh|max。
// 透传非法值会被上游 400 拒绝：
//   Invalid request error. Often missing required parameters or typo.
//   HINT: Validation error: Invalid option: expected one of
//     "off"|"low"|"medium"|"high"|"xhigh"|"max" at "params.reasoning_effort"
// 归一化必须在唯一出口 buildCcRequest 里做，/v1/chat/completions 与 /v1/messages 才会一起生效。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setup } from './helpers.mjs';

const AUTH = { Authorization: 'Bearer user_test' };
const CHAT = { model: 'm', messages: [{ role: 'user', content: 'hi' }] };

// 未传第二个参数 = 请求里完全不带 reasoning_effort 字段
const ABSENT = Symbol('absent');
/** 发一条 chat/completions 请求，返回到达上游 mock 的请求体。 */
async function upstreamBody(s, reasoning_effort = ABSENT) {
  const body = { ...CHAT };
  if (reasoning_effort !== ABSENT) body.reasoning_effort = reasoning_effort;
  await s.proxy.post('/v1/chat/completions', body, AUTH);
  return s.mock.lastGenerate().body;
}

// ── 词表归一化 ────────────────────────────────────────────

test('none → off（关闭思考）', async () => {
  const s = await setup();
  try {
    assert.equal((await upstreamBody(s, 'none')).params.reasoning_effort, 'off');
  } finally { await s.close(); }
});

test('minimal → low（绝不能静默关闭思考）', async () => {
  const s = await setup();
  try {
    assert.equal((await upstreamBody(s, 'minimal')).params.reasoning_effort, 'low',
      'CC 没有比 low 更弱的"开启"档，minimal 只能降到 low');
  } finally { await s.close(); }
});

test('ultra → max（Hermes 内部档位）', async () => {
  const s = await setup();
  try {
    assert.equal((await upstreamBody(s, 'ultra')).params.reasoning_effort, 'max');
  } finally { await s.close(); }
});

test('大小写与首尾空白被忽略：HIGH / " high " → high', async () => {
  const s = await setup();
  try {
    assert.equal((await upstreamBody(s, 'HIGH')).params.reasoning_effort, 'high');
    assert.equal((await upstreamBody(s, ' high ')).params.reasoning_effort, 'high');
  } finally { await s.close(); }
});

// ── 无法识别 / 非字符串 → 一律不发该字段 ──────────────────

test('未知值 garbage → 不发送 reasoning_effort（宁可用上游默认）', async () => {
  const s = await setup();
  try {
    assert.ok(!('reasoning_effort' in (await upstreamBody(s, 'garbage')).params));
  } finally { await s.close(); }
});

test('非字符串（数字 / 对象 / null）→ 不发送 reasoning_effort', async () => {
  const s = await setup();
  try {
    assert.ok(!('reasoning_effort' in (await upstreamBody(s, 5)).params));
    assert.ok(!('reasoning_effort' in (await upstreamBody(s, { effort: 'low' })).params));
    assert.ok(!('reasoning_effort' in (await upstreamBody(s, null)).params));
  } finally { await s.close(); }
});

test('空字符串 / 纯空白 → 不发送 reasoning_effort', async () => {
  const s = await setup();
  try {
    assert.ok(!('reasoning_effort' in (await upstreamBody(s, '')).params));
    assert.ok(!('reasoning_effort' in (await upstreamBody(s, '   ')).params));
  } finally { await s.close(); }
});

test('请求完全没带该字段 → 上游请求体里仍然没有（不要凭空加上）', async () => {
  const s = await setup();
  try {
    const body = await upstreamBody(s);
    assert.ok(!('reasoning_effort' in body.params));
  } finally { await s.close(); }
});

// ── 端到端回归：Hermes 的 none 不再把 400 透传给下游 ────────

test('端到端：带 reasoning_effort=none 的 chat 请求到达上游时是 off', async () => {
  const s = await setup();
  try {
    const r = await s.proxy.post('/v1/chat/completions',
      { ...CHAT, reasoning_effort: 'none' }, AUTH);
    assert.equal(r.status, 200);
    const wire = s.mock.lastGenerate().body;
    assert.equal(wire.params.reasoning_effort, 'off');
    assert.ok(!JSON.stringify(wire).includes('"none"'),
      '非法词 none 绝不能出现在发往 CC 的请求体里');
  } finally { await s.close(); }
});
