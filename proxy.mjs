/**
 * Command Code → OpenAI 兼容代理
 * 基于真实 CLI 流量抓包数据构建
 */
import http from 'http';
import https from 'https';
import tls from 'tls';
import { Readable } from 'stream';
import crypto from 'crypto';
import { randomUUID } from 'crypto';
import { readFileSync, existsSync, appendFileSync, writeFileSync, renameSync, chmodSync, unlinkSync, mkdirSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

// ── 配置加载 ──────────────────────────────────────
const __dirname = dirname(fileURLToPath(import.meta.url));

function loadConfig() {
  const defaults = {
    port: 3000,
    host: '0.0.0.0',
    apiBase: 'https://api.commandcode.ai',
    projectSlug: 'cc-proxy',
    logFile: '',
    logLevel: 'info',
    useProviderModels: true,
    modelRefreshIntervalMs: 5 * 60 * 1000,  // 5 minutes
    zdr: false,
    cliMode: 'agent', // 信封 mode。服务端枚举（真机 400 报出来的）：agent|learning|custom-agent|custom-agent-create|title-gen|tool-desc|compact|vision
    cliSessionMode: 'interactive', // lifecycle metadata 的 mode —— 注意这是另一个枚举：interactive | non-interactive
    fingerprintSalt: '',
    deviceProjectDir: '', // 伪造的项目目录（留空则用内置的 C:\Users\dev\projects\app） // 改这个值 = 让所有账号换一台设备（见设备指纹注释）
    emptySystemPlaceholder: true, // 无 system prompt 时发空格占位，阻止 CC 上游注入 ~7.5K token 默认提示词（issue #17）
    upstreamProxy: '',            // 上游 HTTP 代理，如 http://127.0.0.1:7890（issue #18）
    adminToken: '',               // 管理后台令牌（空 = 后台关闭）。强烈建议用 CC_ADMIN_TOKEN 环境变量传入
    accountsFile: 'accounts.json',// 账号池数据文件（相对 __dirname 或绝对路径）
  };

  const configPath = resolve(__dirname, 'config.json');
  if (existsSync(configPath)) {
    try {
      const user = JSON.parse(readFileSync(configPath, 'utf-8'));
      Object.assign(defaults, user);
    } catch (e) {
      console.error('[config] Failed to parse config.json:', e.message);
    }
  }

  // 环境变量覆写
  if (process.env.PORT) defaults.port = parseInt(process.env.PORT);
  if (process.env.HOST) defaults.host = process.env.HOST;
  if (process.env.CC_API_BASE) defaults.apiBase = process.env.CC_API_BASE;
  if (process.env.PROJECT_SLUG) defaults.projectSlug = process.env.PROJECT_SLUG;
  if (process.env.LOG_FILE) defaults.logFile = process.env.LOG_FILE;
  if (process.env.CC_USE_PROVIDER_MODELS) defaults.useProviderModels = process.env.CC_USE_PROVIDER_MODELS !== 'false';
  if (process.env.CMD_ZDR !== undefined) defaults.zdr = process.env.CMD_ZDR === '1';
  if (process.env.CC_FINGERPRINT_SALT !== undefined) defaults.fingerprintSalt = process.env.CC_FINGERPRINT_SALT;
  if (process.env.CC_DEVICE_PROJECT_DIR) defaults.deviceProjectDir = process.env.CC_DEVICE_PROJECT_DIR;
  if (process.env.CC_CLI_MODE) defaults.cliMode = process.env.CC_CLI_MODE;
  if (process.env.CC_CLI_SESSION_MODE) defaults.cliSessionMode = process.env.CC_CLI_SESSION_MODE;
  if (process.env.CC_EMPTY_SYSTEM_PLACEHOLDER) defaults.emptySystemPlaceholder = process.env.CC_EMPTY_SYSTEM_PLACEHOLDER !== 'false';
  if (process.env.CC_UPSTREAM_PROXY) defaults.upstreamProxy = process.env.CC_UPSTREAM_PROXY;
  if (process.env.CC_ADMIN_TOKEN !== undefined) defaults.adminToken = process.env.CC_ADMIN_TOKEN;
  if (process.env.CC_ACCOUNTS_FILE) defaults.accountsFile = process.env.CC_ACCOUNTS_FILE;

  return defaults;
}

const CFG = loadConfig();

// ══════════════════════════════════════════════════════════════
// 多账号池 + 智能路由（详见 README「多账号与智能路由」）
// ══════════════════════════════════════════════════════════════
const ACCOUNTS_PATH = resolve(__dirname, CFG.accountsFile);
const CLIENT_TOKEN_PREFIX = 'ccp_';
const MAX_ACCOUNTS = 100;
const MAX_CLIENTS = 500;
// 客户端令牌禁止匹配 legacy 的 user_ 正则，否则会与直通路径冲突（见 resolveRoute）。
const USER_KEY_RE = /user_[a-zA-Z0-9_-]+/;

function defaultRouting() {
  return {
    strategy: 'weighted',
    selection: 'weighted_random',           // weighted_random | best
    weights: { successRate: 0.5, latency: 0.3, load: 0.2 },
    windowSizeMs: 300000,                   // 成功率滚动窗口 5min
    bucketMs: 30000,                        // 窗口分桶粒度（内存 O(1)）
    priorAlpha: 5,                          // Beta 先验强度（冷启动）
    priorSuccessRate: 0.8,                  // 冷启动先验成功率
    latencyEwmaAlpha: 0.3,                  // 成功样本 TTFT 的 EWMA 系数
    latencyFloorMs: 400,
    latencyCeilMs: 60000,
    unknownLatencyScore: 0.5,               // 无延迟样本时的中性分
    loadReference: 4,                       // 无 maxInflight 时 load=1/(1+inFlight/ref)
    cooldownBaseMs: 30000,
    cooldownMaxMs: 300000,
    failureCooldownThreshold: 3,            // 连续失败 N 次进入冷却
    countTimeoutsAsFailure: true,
    countRateLimitAsFailure: true,
    penalizeAuthErrors: false,              // 401/403 是否计入失败
    creditFailoverMax: 3,                   // 单请求内最多换几个号重试（0 = 关闭换号）
    creditUsageThreshold: 0.95,             // 额度查询已用比例 ≥ 此值 + 上游报错 → 兜底判为额度耗尽
  };
}

function newStore() {
  return { version: 1, accounts: [], clients: [], routing: defaultRouting() };
}

let STORE = newStore();
let PERSISTENCE_OK = true;

// ── 工具：ID / 令牌 / 掩码 / 定时安全比较 ──────────────
function newId(prefix) { return prefix + crypto.randomBytes(6).toString('hex'); }
function newClientToken() { return CLIENT_TOKEN_PREFIX + crypto.randomBytes(24).toString('hex'); }

// 长度不等时也执行一次比较，避免长度侧信道。
function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a ?? ''), 'utf8');
  const bb = Buffer.from(String(b ?? ''), 'utf8');
  if (ba.length !== bb.length) { crypto.timingSafeEqual(ba, ba); return false; }
  return crypto.timingSafeEqual(ba, bb);
}

// 密钥掩码：任何对外响应都必须经过它（账号 key 永不提供明文出口）。
function maskKey(k) {
  const s = String(k ?? '');
  if (!s) return '';
  if (s.length <= 12) return s.slice(0, 3) + '…';
  return s.slice(0, 8) + '…' + s.slice(-4);
}

function clampNum(v, dflt, min, max) {
  const n = typeof v === 'number' ? v : Number(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, n));
}
function sanitizeName(v, fallback) {
  const s = String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 64);
  return s || fallback;
}

// ── 校验与归一化 ────────────────────────────────────────
function normalizeRouting(raw) {
  const d = defaultRouting();
  const r = { ...d, weights: { ...d.weights } };
  if (!raw || typeof raw !== 'object') return r;
  if (raw.selection === 'best' || raw.selection === 'weighted_random') r.selection = raw.selection;
  if (raw.weights && typeof raw.weights === 'object') {
    r.weights.successRate = clampNum(raw.weights.successRate, d.weights.successRate, 0, 1000);
    r.weights.latency = clampNum(raw.weights.latency, d.weights.latency, 0, 1000);
    r.weights.load = clampNum(raw.weights.load, d.weights.load, 0, 1000);
  }
  r.windowSizeMs = clampNum(raw.windowSizeMs, d.windowSizeMs, 10000, 86400000);
  r.bucketMs = clampNum(raw.bucketMs, d.bucketMs, 1000, r.windowSizeMs);
  r.priorAlpha = clampNum(raw.priorAlpha, d.priorAlpha, 0, 1000);
  r.priorSuccessRate = clampNum(raw.priorSuccessRate, d.priorSuccessRate, 0, 1);
  r.latencyEwmaAlpha = clampNum(raw.latencyEwmaAlpha, d.latencyEwmaAlpha, 0.01, 1);
  r.latencyFloorMs = clampNum(raw.latencyFloorMs, d.latencyFloorMs, 1, 3600000);
  r.latencyCeilMs = clampNum(raw.latencyCeilMs, d.latencyCeilMs, r.latencyFloorMs + 1, 3600000);
  r.unknownLatencyScore = clampNum(raw.unknownLatencyScore, d.unknownLatencyScore, 0, 1);
  r.loadReference = clampNum(raw.loadReference, d.loadReference, 0.1, 10000);
  r.cooldownBaseMs = clampNum(raw.cooldownBaseMs, d.cooldownBaseMs, 1000, 3600000);
  r.cooldownMaxMs = clampNum(raw.cooldownMaxMs, d.cooldownMaxMs, r.cooldownBaseMs, 86400000);
  r.failureCooldownThreshold = clampNum(raw.failureCooldownThreshold, d.failureCooldownThreshold, 1, 1000);
  r.countTimeoutsAsFailure = raw.countTimeoutsAsFailure !== false;
  r.countRateLimitAsFailure = raw.countRateLimitAsFailure !== false;
  r.penalizeAuthErrors = raw.penalizeAuthErrors === true;
  r.creditFailoverMax = Math.floor(clampNum(raw.creditFailoverMax, d.creditFailoverMax, 0, 20));
  r.creditUsageThreshold = clampNum(raw.creditUsageThreshold, d.creditUsageThreshold, 0, 1);
  return r;
}

// 字段级 merge 后**原地赋值**，避免在途请求读到半初始化对象。
function applyRouting(raw) {
  const next = normalizeRouting(raw);
  for (const k of Object.keys(next)) {
    if (k === 'weights') Object.assign(STORE.routing.weights, next.weights);
    else STORE.routing[k] = next[k];
  }
  return STORE.routing;
}

function normalizeAccount(a) {
  const nowIso = new Date().toISOString();
  return {
    id: typeof a.id === 'string' && a.id ? a.id : newId('acc_'),
    name: sanitizeName(a.name, 'account'),
    apiKey: String(a.apiKey),
    enabled: a.enabled !== false,
    weight: clampNum(a.weight, 1, 0.01, 1000),
    priority: Number.isFinite(a.priority) ? a.priority : 0,
    maxInflight: Number.isFinite(a.maxInflight) && a.maxInflight > 0 ? Math.floor(a.maxInflight) : 0,
    tags: Array.isArray(a.tags) ? a.tags.filter(t => typeof t === 'string').slice(0, 20) : [],
    notes: typeof a.notes === 'string' ? a.notes.slice(0, 2000) : '',
    createdAt: a.createdAt || nowIso,
    updatedAt: a.updatedAt || a.createdAt || nowIso,
  };
}

function normalizeClient(c) {
  const nowIso = new Date().toISOString();
  return {
    id: typeof c.id === 'string' && c.id ? c.id : newId('cli_'),
    name: sanitizeName(c.name, 'client'),
    token: typeof c.token === 'string' && c.token ? c.token : newClientToken(),
    enabled: c.enabled !== false,
    accountIds: Array.isArray(c.accountIds) ? c.accountIds.filter(x => typeof x === 'string') : null,
    notes: typeof c.notes === 'string' ? c.notes.slice(0, 2000) : '',
    createdAt: c.createdAt || nowIso,
    updatedAt: c.updatedAt || c.createdAt || nowIso,
    lastUsedAt: c.lastUsedAt || null,
  };
}

function normalizeStore(raw) {
  const base = newStore();
  if (!raw || typeof raw !== 'object') return base;
  if (Array.isArray(raw.accounts)) {
    base.accounts = raw.accounts
      .filter(a => a && typeof a === 'object' && typeof a.apiKey === 'string' && a.apiKey)
      .slice(0, MAX_ACCOUNTS).map(normalizeAccount);
  }
  if (Array.isArray(raw.clients)) {
    base.clients = raw.clients
      .filter(c => c && typeof c === 'object' && typeof c.token === 'string' && c.token)
      .slice(0, MAX_CLIENTS).map(normalizeClient);
  }
  if (raw.routing && typeof raw.routing === 'object') base.routing = normalizeRouting(raw.routing);
  return base;
}

// ── 持久化：原子写 + 0600 ───────────────────────────────
function persistAccounts() {
  const tmp = ACCOUNTS_PATH + '.tmp-' + crypto.randomBytes(4).toString('hex');
  try {
    const dir = dirname(ACCOUNTS_PATH);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(tmp, JSON.stringify(STORE, null, 2), { mode: 0o600 });
    renameSync(tmp, ACCOUNTS_PATH);
    try { chmodSync(ACCOUNTS_PATH, 0o600); } catch {}
    PERSISTENCE_OK = true;
    return true;
  } catch (e) {
    try { if (existsSync(tmp)) unlinkSync(tmp); } catch {}
    if (PERSISTENCE_OK) log('error', 'Failed to persist accounts file (memory-only mode)', { error: e.message, file: CFG.accountsFile });
    PERSISTENCE_OK = false;
    return false;
  }
}

function loadAccountsFile() {
  if (!existsSync(ACCOUNTS_PATH)) {
    STORE = newStore();
    persistAccounts();   // 首次生成；失败仅告警（内存态仍可用）
    return;
  }
  try {
    STORE = normalizeStore(JSON.parse(readFileSync(ACCOUNTS_PATH, 'utf-8')));
    log('info', 'Accounts loaded', { accounts: STORE.accounts.length, clients: STORE.clients.length, file: CFG.accountsFile });
  } catch (e) {
    STORE = newStore();
    log('error', 'Failed to parse accounts file, starting with empty pool', { error: e.message, file: CFG.accountsFile });
  }
}
loadAccountsFile();

// ── 运行时指标（不落盘） ────────────────────────────────
const runtime = new Map(); // accountId → metrics

function newRuntime() {
  return {
    inFlight: 0,
    totals: { requests: 0, ok: 0, fail: 0, neutral: 0, retried: 0 },
    buckets: [],
    consecutiveFailures: 0,
    cooldownUntil: 0,
    cooldownLevel: 0,
    creditExhausted: false,
    creditResetAt: null,
    lastError: null,
    ewmaTtftMs: 0,
    lastLatencyMs: 0,
    lastUsedAt: 0,
  };
}
function getRuntime(id) {
  let r = runtime.get(id);
  if (!r) { r = newRuntime(); runtime.set(id, r); }
  return r;
}
function pruneRuntime() {
  const ids = new Set(STORE.accounts.map(a => a.id));
  for (const id of runtime.keys()) if (!ids.has(id)) runtime.delete(id);
}
function resetRuntime(id) {
  const old = getRuntime(id);
  const next = newRuntime();
  next.inFlight = old.inFlight;
  next.creditExhausted = old.creditExhausted;
  next.creditResetAt = old.creditResetAt;
  if (old.creditExhausted) next.cooldownUntil = old.creditResetAt || 0;
  runtime.set(id, next);
}

function creditResetAtOf(usage) {
  const sub = usage && usage.subscription;
  if (!usage?.ok || sub?.status !== 'active' || typeof sub.currentPeriodEnd !== 'string') return null;
  const at = Date.parse(sub.currentPeriodEnd);
  return Number.isFinite(at) && at > Date.now() ? at : null;
}

function expireCreditBlock(r, now) {
  if (r.creditExhausted && Number.isFinite(r.creditResetAt) && r.creditResetAt <= now) {
    r.creditExhausted = false;
    r.creditResetAt = null;
    r.cooldownUntil = 0;
    r.cooldownLevel = 0;
    r.consecutiveFailures = 0;
  }
}

function pruneBuckets(r, now, routing) {
  const cutoff = now - routing.windowSizeMs;
  while (r.buckets.length && r.buckets[0].t < cutoff) r.buckets.shift();
  // 极端情况下（长时间无请求）窗口内可能堆积很多桶，硬性封顶
  const maxBuckets = Math.ceil(routing.windowSizeMs / routing.bucketMs) + 2;
  while (r.buckets.length > maxBuckets) r.buckets.shift();
}
function addSample(r, now, routing, kind, ttftMs) {
  const t = Math.floor(now / routing.bucketMs) * routing.bucketMs;
  let b = r.buckets.length ? r.buckets[r.buckets.length - 1] : null;
  if (!b || b.t !== t) { b = { t, ok: 0, fail: 0, ttftSum: 0, ttftCount: 0 }; r.buckets.push(b); }
  if (kind === 'ok') {
    b.ok++;
    if (Number.isFinite(ttftMs)) { b.ttftSum += ttftMs; b.ttftCount++; }
  } else {
    b.fail++;
  }
  pruneBuckets(r, now, routing);
}
function windowStats(r, now, routing) {
  pruneBuckets(r, now, routing);
  let ok = 0, fail = 0, ttftSum = 0, ttftCount = 0;
  for (const b of r.buckets) { ok += b.ok; fail += b.fail; ttftSum += b.ttftSum; ttftCount += b.ttftCount; }
  return { ok, fail, n: ok + fail, ttftSum, ttftCount };
}

// ── 评分与选择 ──────────────────────────────────────────
function scoreAccount(account, r, now, routing, maxWeight) {
  const st = windowStats(r, now, routing);
  const S = routing.priorAlpha > 0
    ? (st.ok + routing.priorAlpha * routing.priorSuccessRate) / (st.n + routing.priorAlpha)
    : (st.n > 0 ? st.ok / st.n : routing.priorSuccessRate);
  let L;
  if (r.ewmaTtftMs > 0) {
    L = Math.min(1, Math.max(0, (routing.latencyCeilMs - r.ewmaTtftMs) / (routing.latencyCeilMs - routing.latencyFloorMs)));
  } else {
    L = routing.unknownLatencyScore;
  }
  const C = account.maxInflight > 0
    ? Math.min(1, Math.max(0, 1 - r.inFlight / account.maxInflight))
    : 1 / (1 + r.inFlight / routing.loadReference);

  const wsum = routing.weights.successRate + routing.weights.latency + routing.weights.load;
  const wS = wsum > 0 ? routing.weights.successRate / wsum : 1 / 3;
  const wL = wsum > 0 ? routing.weights.latency / wsum : 1 / 3;
  const wC = wsum > 0 ? routing.weights.load / wsum : 1 / 3;
  const base = wS * S + wL * L + wC * C;
  const weightFactor = maxWeight > 0 ? account.weight / maxWeight : 1;
  const score = r.creditExhausted || r.cooldownUntil > now ? 0 : base * weightFactor;
  return {
    score,
    components: {
      success: S, latency: L, load: C, weightFactor, base,
      samples: st.n, ok: st.ok, fail: st.fail,
      cooldownUntil: r.cooldownUntil, ewmaTtftMs: r.ewmaTtftMs, inFlight: r.inFlight,
    },
  };
}

function compareCandidates(a, b) {
  if (b.score !== a.score) return b.score - a.score;
  if (a.runtime.inFlight !== b.runtime.inFlight) return a.runtime.inFlight - b.runtime.inFlight;
  const la = a.runtime.ewmaTtftMs || Infinity, lb = b.runtime.ewmaTtftMs || Infinity;
  if (la !== lb) return la - lb;
  if (a.runtime.lastUsedAt !== b.runtime.lastUsedAt) return a.runtime.lastUsedAt - b.runtime.lastUsedAt;
  return a.account.id < b.account.id ? -1 : 1;
}

function selectAccount(client) {
  const now = Date.now();
  const routing = STORE.routing;
  let list = STORE.accounts.filter(a => a.enabled);
  if (client && Array.isArray(client.accountIds)) {
    const allow = new Set(client.accountIds);
    list = list.filter(a => allow.has(a.id));
  }
  const notSaturated = list.filter(a => {
    const r = getRuntime(a.id);
    expireCreditBlock(r, now);
    return !r.creditExhausted && !(a.maxInflight > 0 && r.inFlight >= a.maxInflight);
  });
  const healthy = notSaturated.filter(a => getRuntime(a.id).cooldownUntil <= now);
  const cooling = notSaturated.filter(a => getRuntime(a.id).cooldownUntil > now);

  let pool = healthy;
  let fallback = false;
  if (pool.length === 0) {
    if (cooling.length === 0) return null;   // 无可用账号
    // fail-open：全在冷却时选冷却最早到期的那个，绝不因此 503
    pool = cooling.slice().sort((a, b) => getRuntime(a.id).cooldownUntil - getRuntime(b.id).cooldownUntil);
    fallback = true;
  }

  const maxWeight = pool.reduce((m, a) => Math.max(m, a.weight), 0);
  const candidates = pool.map(a => {
    const r = getRuntime(a.id);
    const { score, components } = scoreAccount(a, r, now, routing, maxWeight);
    const eff = fallback ? components.base * components.weightFactor : score;
    return { account: a, score: eff, components, runtime: r };
  });

  if (routing.selection === 'best' || fallback) {
    candidates.sort(compareCandidates);
    return candidates[0].account;
  }
  const total = candidates.reduce((s, x) => s + x.score, 0);
  if (!(total > 0)) { candidates.sort(compareCandidates); return candidates[0].account; }
  let pick = Math.random() * total;
  for (const x of candidates) { pick -= x.score; if (pick <= 0) return x.account; }
  return candidates[candidates.length - 1].account;
}

function reserveAccount(accountId) {
  const r = getRuntime(accountId);
  r.inFlight++;
  r.lastUsedAt = Date.now();
}
function releaseInflight(accountId) {
  const r = getRuntime(accountId);
  if (r.inFlight > 0) r.inFlight--;
}

// 上游状态码 → 记账口径：'fail' | 'neutral'
function classifyUpstreamStatus(status) {
  if (status === 400 || status === 404 || status === 422) return 'neutral'; // 客户端请求错，换账号一样
  if (status === 401 || status === 403) return STORE.routing.penalizeAuthErrors ? 'fail' : 'neutral';
  return 'fail';
}

// 「额度耗尽」是**账号级**错误：上游用 400/402 表示，但换账号就能成功。
// 必须与「客户端请求错」的 400 区分开，否则账号不会被惩罚，路由会一直选中它（见 releaseAccount）。
function isCreditExhaustedError(status, code, text) {
  if (code && /USAGE_EXCEEDED|INSUFFICIENT_?CREDITS?|QUOTA_EXCEEDED|CREDIT_?EXHAUSTED/i.test(String(code))) return true;
  if (status !== 400 && status !== 402 && status !== 403) return false;
  if (!text) return false;
  return /insufficient[_ ]credits?|purchase more credits|out of credits|credit balance|quota[_ ]exceeded|usage[_ ]exceeded|余额不足|额度不足/i.test(text);
}

function releaseAccount(accountId, outcome, latencyMs) {
  const r = getRuntime(accountId);
  if (r.inFlight > 0) r.inFlight--;
  // 请求总数与结果计数在同一处递增：保证 requests >= ok+fail+neutral 恒成立、无漂移窗口
  r.totals.requests++;
  const now = Date.now();
  const routing = STORE.routing;
  const state = outcome && outcome.state;
  if (outcome && outcome.status != null) {
    r.lastError = { at: now, status: outcome.status, code: outcome.code || null, message: outcome.message || null };
  }
  if (latencyMs != null) r.lastLatencyMs = latencyMs;

  if (state === 'ok') {
    addSample(r, now, routing, 'ok', outcome.ttftMs);
    if (Number.isFinite(outcome.ttftMs)) {
      r.ewmaTtftMs = r.ewmaTtftMs > 0
        ? routing.latencyEwmaAlpha * outcome.ttftMs + (1 - routing.latencyEwmaAlpha) * r.ewmaTtftMs
        : outcome.ttftMs;
    }
    r.totals.ok++;
    if (outcome.retried) r.totals.retried++;
    r.consecutiveFailures = 0;
    r.cooldownLevel = 0;
    if (!r.creditExhausted) r.cooldownUntil = 0;
  } else if (state === 'fail') {
    addSample(r, now, routing, 'fail', null);
    r.totals.fail++;
    r.consecutiveFailures++;
    if (r.consecutiveFailures >= routing.failureCooldownThreshold) {
      const backoff = Math.min(routing.cooldownBaseMs * Math.pow(2, r.cooldownLevel), routing.cooldownMaxMs);
      if (!r.creditExhausted) r.cooldownUntil = now + backoff;
      r.cooldownLevel++;
    }
  } else if (state === 'credit_exhausted') {
    // 仅套餐周期到期可恢复；未知重置时间保持硬阻断。
    addSample(r, now, routing, 'fail', null);
    r.totals.fail++;
    r.consecutiveFailures++;
    r.cooldownLevel = 0;                       // 与普通指数退避解耦，避免下次叠加翻倍
    // 旧在途结果不能覆盖已登记的较新套餐时间，也不能以未知时间清除它。
    const resetAt = Number.isFinite(outcome.creditResetAt) ? outcome.creditResetAt : null;
    r.creditResetAt = r.creditResetAt === null ? resetAt
      : resetAt === null ? r.creditResetAt : Math.max(r.creditResetAt, resetAt);
    r.cooldownUntil = r.creditResetAt || 0;
    r.creditExhausted = true;
  } else if (state === 'neutral') {
    r.totals.neutral++;
  }
  // aborted / pending：仅释放 inFlight，不记成败
}

/**
 * 额度耗尽换号：上游对「本账号没钱了」用 400/402 + insufficient credits 表达。
 * 这是账号级错误 —— 换账号就能成功，因此在这里释放当前账号（长冷却），并立即用下一个
 * 可用账号重放同一个请求，客户端无感。
 *
 * 返回 { route, apiKey, ccResponse, errorText, mapped, creditExhausted, switched, stop }。
 * 调用方必须把 route/apiKey/ccResponse/errorText/mapped 回写到自己的局部变量；
 * 若最终响应仍非 2xx，由调用方按原有错误分支返回（此时最后那个账号由外层 finally 记账）。
 *
 * forward: async (apiKey) => Response  —— 负责 ensureInitialized + forwardToCC 的重放闭包。
 */
async function creditFailover({ route, apiKey, ccResponse, errorText, mapped, outcome, req, forward }) {
  const routing = STORE.routing;
  const cur = { route, apiKey, ccResponse, errorText, mapped, creditExhausted: false };
  const tried = new Set(route && route.accountId ? [route.accountId] : []);
  let switches = 0;
  while (cur.ccResponse && !cur.ccResponse.ok && cur.route.mode === 'pool') {
    const status = cur.ccResponse.status;
    cur.creditExhausted = isCreditExhaustedError(status, cur.mapped && cur.mapped.code, cur.errorText);
    outcome.creditResetAt = null;
    if (cur.creditExhausted || status === 400 || status === 402 || status === 403) {
      const account = STORE.accounts.find(a => a.id === cur.route.accountId);
      if (account) {
        const usage = await getAccountUsage(account, true);
        const p = usage.credits && usage.credits.usagePercent;
        cur.creditExhausted = cur.creditExhausted || (usage.ok === true && typeof p === 'number'
          && Number.isFinite(p) && p >= routing.creditUsageThreshold);
        if (cur.creditExhausted) outcome.creditResetAt = creditResetAtOf(usage);
      }
    }
    if (!cur.creditExhausted || switches >= routing.creditFailoverMax) break;
    // 1) 记账：当前账号额度耗尽 → 立即长冷却（不等连续失败阈值）
    outcome.state = 'credit_exhausted';
    outcome.status = cur.ccResponse.status;
    outcome.code = (cur.mapped && cur.mapped.code) || null;
    outcome.message = (cur.mapped && cur.mapped.body && cur.mapped.body.error && cur.mapped.body.error.message) || null;
    cur.route.release(outcome, null);
    // 2) 换下一个账号（刚冷却的账号已被 selectAccount 排除）
    const next = resolveRoute(req.headers);
    if (!next || next.error) {
      log('warn', 'Credit failover stopped: no other account available', { used: switches });
      return { ...cur, switched: switches, stop: true };
    }
    if (next.accountId && tried.has(next.accountId)) {
      next.release({ state: 'pending' }, null);   // 只剩同一个账号可选，再试也无意义
      log('warn', 'Credit failover stopped: only the exhausted account is available', { used: switches });
      return { ...cur, switched: switches, stop: true };
    }
    if (next.accountId) tried.add(next.accountId);
    switches++;
    log('warn', 'Upstream account out of credits - retrying with another account', {
      status: cur.ccResponse.status, code: outcome.code, attempt: switches,
      from: cur.route.accountId || null, to: next.accountId || null,
    });
    // 3) 用新账号重放（重置本次尝试的记账状态）
    cur.route = next;
    cur.apiKey = next.upstreamKey;
    outcome.state = 'pending'; outcome.status = null; outcome.code = null; outcome.message = null; outcome.ttftMs = null; outcome.creditResetAt = null;
    cur.creditExhausted = false;
    try {
      cur.ccResponse = await forward(next.upstreamKey);
    } catch (e) {
      next.release({ state: 'fail', status: 502, message: 'Upstream forwarding failed' }, null);
      throw e;
    }
    cur.errorText = cur.ccResponse.ok ? '' : await cur.ccResponse.text().catch(() => '');
    cur.mapped = cur.ccResponse.ok ? null : mapCcError(cur.ccResponse.status, cur.errorText);
  }
  return { ...cur, switched: switches, stop: false };
}

// ── 凭据解析（池 / legacy 直通） ────────────────────────
function rawCredential(headers) {
  const auth = headers['authorization'] || headers['Authorization'] || '';
  if (typeof auth === 'string') {
    const m = auth.match(/^Bearer\s+(.+)$/i);
    if (m) return m[1].trim();
  }
  const xKey = headers['x-api-key'] || headers['X-Api-Key'] || '';
  if (typeof xKey === 'string' && xKey) return xKey.trim();
  return '';
}

function findClientByToken(raw) {
  if (!raw) return null;
  for (const c of STORE.clients) {
    if (c.enabled && timingSafeEqualStr(c.token, raw)) return c;
  }
  return null;
}

/**
 * 解析请求凭据。返回：
 *  - null                       → 无凭据（调用方按现有 401 处理）
 *  - { error:'no_available_account' } → 令牌有效但无可用账号（503）
 *  - { mode:'pool',  upstreamKey, accountId, clientId, release(outcome,latencyMs) }
 *  - { mode:'legacy', upstreamKey, release: no-op }
 */
function resolveRoute(headers) {
  const raw = rawCredential(headers);
  if (!raw) return null;

  // 池模式必须排在 legacy 之前（user_ 直通是兜底）
  const client = findClientByToken(raw);
  if (client) {
    const account = selectAccount(client);
    if (!account) return { error: 'no_available_account' };
    reserveAccount(account.id);
    client.lastUsedAt = Date.now();
    let released = false;
    return {
      mode: 'pool',
      clientId: client.id,
      accountId: account.id,
      upstreamKey: account.apiKey,
      release: (outcome, latencyMs) => {
        if (released) return;
        released = true;
        releaseAccount(account.id, outcome, latencyMs);
      },
    };
  }

  // legacy 直通：保留 getApiKey 的子串语义，与改造前逐字一致
  const legacyKey = getApiKey(headers);
  if (legacyKey) return { mode: 'legacy', upstreamKey: legacyKey, release: () => {} };
  return null;
}

// /v1/models 用的轻量选择：不记账，仅占用/释放在途
function selectForModels() {
  const account = selectAccount(null);
  if (!account) return null;
  const r = getRuntime(account.id);
  r.inFlight++;
  r.lastUsedAt = Date.now();
  return { mode: 'pool', accountId: account.id, upstreamKey: account.apiKey, release: () => releaseInflight(account.id) };
}

// ── 设备指纹（形态与哈希逐字对齐官方 CLI 1.53.1） ──────
// CPU 型号与核心数对应表（仅 Windows x64）
const FINGERPRINT_CPUS = [
  { model: '12th Gen Intel(R) Core(TM) i7-12650H', cores: 10 },   // TEMP-REVERT
  { model: '12th Gen Intel(R) Core(TM) i5-12400F', cores: 6 },
  { model: '12th Gen Intel(R) Core(TM) i9-12900K', cores: 16 },
  { model: '13th Gen Intel(R) Core(TM) i7-13700K', cores: 16 },
  { model: '13th Gen Intel(R) Core(TM) i5-13600K', cores: 14 },
  { model: '13th Gen Intel(R) Core(TM) i9-13900K', cores: 24 },
  { model: 'Intel(R) Core(TM) Ultra 7 155H', cores: 16 },
  { model: 'Intel(R) Core(TM) Ultra 9 285H', cores: 16 },
  { model: 'Intel(R) Core(TM) i9-14900K', cores: 24 },
  { model: 'Intel(R) Core(TM) i7-14700K', cores: 20 },
  { model: 'AMD Ryzen 7 7800X3D', cores: 8 },
  { model: 'AMD Ryzen 9 7950X', cores: 16 },
  { model: 'AMD Ryzen 5 7600', cores: 6 },
  { model: 'AMD Ryzen 9 7900X', cores: 12 },
  { model: 'AMD Ryzen 7 5800X3D', cores: 8 },
];
const FINGERPRINT_MEMS = [8, 16, 24, 32, 48, 64];
const FINGERPRINT_TZS = [
  'America/New_York', 'America/Chicago', 'America/Los_Angeles', 'America/Toronto',
  'Europe/London', 'Europe/Berlin', 'Europe/Paris', 'Europe/Moscow',
  'Asia/Shanghai', 'Asia/Tokyo', 'Asia/Singapore', 'Asia/Seoul', 'Asia/Hong_Kong',
  'Australia/Sydney', 'Pacific/Auckland',
];
const FINGERPRINT_MAC_COUNT_RANGE = [2, 3, 4, 5]; // 随机 2~5 个 MAC

// CLI 的根盐（buildMachineFingerprint 常量 sb）
const FP_SALT = 'command-code:device-fingerprint:v1';
// 设备档案：指纹 / config.environment / config.workingDir / x-project-slug / lifecycle.os 共用同一份，
// 避免出现「指纹说 win32、环境说 linux」这类自相矛盾，也避免把宿主机真实信息（平台、Node 版本、cwd）交给上游。
const DEVICE_PROFILE = {
  platform: 'win32',
  arch: 'x64',
  osRelease: '10.0.22631',
  isContainer: false,
  // 伪造的项目目录：与 x-project-slug 同源（真机里 slug = slugify(workingDir)）
  projectDir: CFG.deviceProjectDir || 'C:\\Users\\dev\\projects\\app',
};
const FP_OS_USERS = ['dev', 'user', 'admin', 'coder', 'engineer', 'work'];
const FP_MAIL_DOMAINS = ['gmail.com', 'outlook.com', 'qq.com', '163.com'];

// 伪造信号的派生源。加 CC_FINGERPRINT_SALT 可成批换身份 —— 真实账号的 key 动不了，这是逃生口。
// 注意：哈希阶段用的是 CLI 的固定盐（FP_SALT），salt 只影响「伪造出哪台机器」。
function fpDigest(apiKey, field) {
  return crypto.createHash('sha256')
    .update(`${CFG.fingerprintSalt || ''}\0${apiKey}\0${field}`)
    .digest();
}
// 从候选池确定性地挑一项：打分取最大。以后往池里加候选只影响「新候选恰好胜出」的那部分 key，
// 不会像取模那样因为池长度变化让所有 key 一起换设备。
function fpPickIndex(apiKey, field, items, labelOf) {
  let bestIdx = 0;
  let bestScore = null;
  for (let i = 0; i < items.length; i++) {
    const score = fpDigest(apiKey, `${field}\0${labelOf(i)}`);
    if (!bestScore || Buffer.compare(score, bestScore) > 0) { bestScore = score; bestIdx = i; }
  }
  return bestIdx;
}
// CLI 的 hashSignal：sha256(FP_SALT + "\0" + value.toLowerCase())，空值返回 undefined（JSON 里被丢掉）
function fingerprintHash(value) {
  const v = String(value ?? '').trim();
  if (!v) return undefined;
  return crypto.createHash('sha256').update(`${FP_SALT}\0${v.toLowerCase()}`).digest('hex');
}

// 与 CLI 的唯一区别是「信号值」：CLI 读真实机器（注册表 / ioreg / machine-id、网卡 MAC、
// os.userInfo、git config），这里按 apiKey 确定性地伪造一组逼真值。
// 为什么必须由 apiKey 派生而不是随机：指纹代表「这个账号对应的那台设备」，重启、内存回收、
// 多实例、月额度用尽停用数周后恢复，上游都应看到同一台设备；换指纹本身就是可疑信号。
function generateFingerprint(apiKey) {
  const cpuEntry = FINGERPRINT_CPUS[fpPickIndex(apiKey, 'cpu', FINGERPRINT_CPUS, i => `${FINGERPRINT_CPUS[i].model}|${FINGERPRINT_CPUS[i].cores}`)];
  const memGiB = FINGERPRINT_MEMS[fpPickIndex(apiKey, 'mem', FINGERPRINT_MEMS, i => String(FINGERPRINT_MEMS[i]))];
  const tz = FINGERPRINT_TZS[fpPickIndex(apiKey, 'timezone', FINGERPRINT_TZS, i => FINGERPRINT_TZS[i])];
  const macCount = FINGERPRINT_MAC_COUNT_RANGE[fpPickIndex(apiKey, 'macCount', FINGERPRINT_MAC_COUNT_RANGE, i => String(FINGERPRINT_MAC_COUNT_RANGE[i]))];
  const osUser = FP_OS_USERS[fpPickIndex(apiKey, 'osUser', FP_OS_USERS, i => FP_OS_USERS[i])];
  const mailDomain = FP_MAIL_DOMAINS[fpPickIndex(apiKey, 'mailDomain', FP_MAIL_DOMAINS, i => FP_MAIL_DOMAINS[i])];
  const hex = (field, bytes) => fpDigest(apiKey, field).subarray(0, bytes).toString('hex');
  // Windows MachineGuid 形状：8-4-4-4-12
  const mid = hex('machineId', 16);
  const machineId = `${mid.slice(0, 8)}-${mid.slice(8, 12)}-${mid.slice(12, 16)}-${mid.slice(16, 20)}-${mid.slice(20, 32)}`;
  const macs = [];
  for (let i = 0; i < macCount; i++) {
    const b = fpDigest(apiKey, `mac${i}`).subarray(0, 6);
    macs.push([...b].map(x => x.toString(16).padStart(2, '0')).join(':'));
  }
  macs.sort(); // CLI 对 MAC 去重后排序
  const hostname = `DESKTOP-${hex('hostname', 4).toUpperCase()}`;
  const gitEmail = `${osUser}.${hex('gitEmail', 3)}@${mailDomain}`;

  const machineIdHash = fingerprintHash(machineId);
  const macHashes = macs.map(fingerprintHash).filter(Boolean);
  const osUserHash = fingerprintHash(osUser);
  const hostnameHash = fingerprintHash(hostname);
  const gitEmailHash = fingerprintHash(gitEmail);

  // CLI 的 thumbmark：主盐 + "\0machine\0" + join([machineId, macs.join(",")])
  // （machineId 非空时不再拼 hostname/cpuModel）
  const thumbSeed = [machineId.trim(), macs.join(','), machineId.trim() ? '' : hostname, machineId.trim() ? '' : cpuEntry.model].filter(Boolean);
  const thumbmark = crypto.createHash('sha256').update(`${FP_SALT}\0machine\0${thumbSeed.join('|') || 'unknown'}`).digest('hex');

  return {
    thumbmark,
    components: {
      machineIdHash,
      macHashes,
      osUserHash,
      hostnameHash,
      gitEmailHash,
      platform: DEVICE_PROFILE.platform,
      arch: DEVICE_PROFILE.arch,
      osRelease: DEVICE_PROFILE.osRelease,
      cpuModel: cpuEntry.model,
      cpuCount: cpuEntry.cores,
      memGiB,
      isContainer: DEVICE_PROFILE.isContainer,
      timezone: tz,
      runtime: 'cli',
      collectorVersion: 1,
    },
  };
}

// 本代理**实际实现**的 wire 协议版本（对齐 command-code@1.53.1 源码）。
// 真机发的永远是「形状 + 版本号」自洽的组合；如果版本号跟着 npm 走而形状没变，
// 就变成「自称最新版、却说旧方言」—— 这比版本号过期更容易被行为分析挑出来。
// 因此这里报的是协议版本，npm 上更新了只告警、不自动改。
const CC_PROTOCOL_VERSION = '1.53.1';
let CC_VERSION = CC_PROTOCOL_VERSION;
const CC_VERSION_REFRESH_MS = 24 * 60 * 60 * 1000; // 24h — 检查一次是否发生漂移

// ── 协议漂移检测（只告警，不改版本号） ─────────────
// 上游 CLI 更新可能带来协议变化。这里只负责提醒「该重新读包对齐了」，
// 绝不会把 x-command-code-version 改成一个我们并未实现的版本。
async function checkProtocolDrift() {
  try {
    const url = 'https://registry.npmjs.org/command-code/latest';
    const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) throw new Error(`npm responded with ${res.status}`);
    const pkg = await res.json();
    const latest = typeof pkg?.version === 'string' ? pkg.version : null;
    if (latest && latest !== CC_PROTOCOL_VERSION) {
      log('warn', 'CC CLI version drift: protocol may have changed, re-align from the npm package', {
        implemented: CC_PROTOCOL_VERSION, latest,
      });
    } else if (latest) {
      log('info', 'CC CLI version in sync', { version: latest });
    }
  } catch (e) {
    log('warn', 'CC version check failed', { error: e.message });
  }
}
checkProtocolDrift(); // 启动时立即检查
setInterval(checkProtocolDrift, CC_VERSION_REFRESH_MS);

// 请求体大小上限：默认 100MB，可用环境变量 CC_MAX_BODY_MB 覆盖（正整数，单位 MB）
// ⚠️ 内存特性（issue #20 实测）：请求体在转发到上游前会同时存在多份副本 ——
//    chunks[] / Buffer.concat / utf8 字符串 / JSON.parse 对象树 / buildCcRequest 重建对象树 / JSON.stringify 序列化体。
//    实测峰值 ≈ body 大小 × 5.1~7.4（7MB→+52MB，20MB→+116MB；而 413 拒绝路径只要 ×1.05）。
//    故 100MB 上限意味着「单个请求」最坏可吃 ~550MB，且该上限是每请求的、不是全局的。
//    公网/多用户部署请在反向代理层同时限制 body 大小与在途请求数（见 README「内存与部署」）。
const MAX_BODY_SIZE = (() => {
  const mb = Number.parseInt(process.env.CC_MAX_BODY_MB ?? '', 10);
  return Number.isFinite(mb) && mb > 0 ? mb * 1024 * 1024 : 100 * 1024 * 1024;
})();
// 上游读空闲超时（issue #19）：只计「reader.read() 的等待」，每收到一个 chunk 重置，
// 不是整个请求的总时长。默认值保持不变（30s / 90s），可用环境变量覆盖 ——
// 官方 CLI 对上游没有任何 idle timeout（反编译 command-code@1.50.0 已验证，
// createApiClient 调用点均未传 timeout），合法的长思考停顿可达数百秒，
// 遇到推理模型被 30s 误杀 / 触发 429 重试放大时，调大这两个值即可。
const STREAM_IDLE_TIMEOUT_MS = (() => {
  const ms = Number.parseInt(process.env.CC_STREAM_IDLE_MS ?? '', 10);
  return Number.isFinite(ms) && ms > 0 ? ms : 30000;   // 默认 30s — 流式无新数据中断
})();
const NONSTREAM_IDLE_TIMEOUT_MS = (() => {
  const ms = Number.parseInt(process.env.CC_NONSTREAM_IDLE_MS ?? '', 10);
  return Number.isFinite(ms) && ms > 0 ? ms : 90000;   // 默认 90s — 非流式超时更宽容
})();

// ── 上游闪断透明重试（未吐字前 bounded retry）─────────
// CC 上游在高峰期会中途掐断流，undici 抛 `TypeError: terminated`
// （cause 多为 SocketError: other side closed）。若此刻尚未向下游写出任何字节，
// 这个请求对下游而言从未开始过 —— 代理内部重试即可消化抖动，下游（CPA / 客户端）
// 不必看到 502 再自行退避。
// 只在「未吐字」时重试：一旦写过头或输出过事件，语义就已提交，重试会造成重复文本。
// 默认 2 = 最多重试 2 次（共 3 次尝试）；CC_UPSTREAM_RETRY_MAX=0 可整体关闭。
const UPSTREAM_RETRY_MAX = (() => {
  const n = Number.parseInt(process.env.CC_UPSTREAM_RETRY_MAX ?? '', 10);
  return Number.isFinite(n) && n >= 0 ? n : 2;
})();
const UPSTREAM_RETRY_BASE_MS = (() => {
  const ms = Number.parseInt(process.env.CC_UPSTREAM_RETRY_BASE_MS ?? '', 10);
  return Number.isFinite(ms) && ms > 0 ? ms : 400;   // 退避 = base × 尝试序号
})();

// 区分「传输层闪断」（可安全重试）与「语义错误」（不可重试）。
// STREAM_IDLE_TIMEOUT 是刻意发给下游的「请减少上下文」信号，绝不重试。
function isRetryableUpstreamError(e) {
  if (!e) return false;
  const blob = [e.message, e.code, e.cause?.message, e.cause?.code].filter(Boolean).join(' | ');
  if (/STREAM_IDLE_TIMEOUT/.test(blob)) return false;
  return /terminated|ECONNRESET|ECONNREFUSED|EPIPE|ETIMEDOUT|UND_ERR_SOCKET|socket hang up|other side closed|fetch failed/i.test(blob);
}

// 仅用于日志：rewinds = 实际重试次数，recovered = 重试后成功交付的次数
const upstreamRetryStats = { rewinds: 0, recovered: 0 };
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// 客户端「僵死」保护：既不读也不断开时，该请求会连带上游连接一直挂着（背压修复后的残留）。
// 实测残留在途成本约 5MB/连接 —— 有界、不泄漏、断开即回收，但连接数本身无上限。
// 默认 0 = 禁用，保持既有行为不变：僵死客户端与「卡在工具执行的合法客户端」在协议层无法
// 区分，而官方 CLI 对上游没有任何 idle timeout（issue #19），贸然加超时会误杀健康请求。
// 在途请求上限（可选，默认关闭）。项目定位是纯反代层，并发控制属于下游（nginx
// limit_conn，per-IP / per-key）；本项仅为「不挂反代裸跑」的场景提供一个可选的
// 进程内全局兜底，不替代下游方案，也不感知客户端身份。
// 内存 = 在途数 × (0.13MB + 5.5 × body_MB)：body 上限只管住单请求量级，乘数由本项封顶。
// 超限返回 503 + Retry-After（SDK 会自行退避重试），而不是放任进程被 OOM 杀掉。
// 默认 0 = 关闭，不限制并发（既有的反代层定位不变，行为零变化）；需要时按需开启：
//   CC_MAX_INFLIGHT=32 npm start
// 注意：body 上限只管住单请求量级，乘数由本项封顶。默认 body 上限 100MB 时，
// N × 最坏 550MB —— 要硬性内存上界需同时下调 CC_MAX_BODY_MB。
const MAX_INFLIGHT = (() => {
  const n = Number.parseInt(process.env.CC_MAX_INFLIGHT ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : 0;            // 默认 0 = 不限
})();

let inflightCount = 0;   // 当前在途请求数（不含 /health）

const CLIENT_DRAIN_TIMEOUT_MS = (() => {
  const ms = Number.parseInt(process.env.CC_CLIENT_DRAIN_TIMEOUT_MS ?? '', 10);
  return Number.isFinite(ms) && ms > 0 ? ms : 0;
})();

// 连续超时计数：连续 3 次超时才提醒压缩上下文，任意成功请求后重置
let consecutiveTimeouts = 0;
const TIMEOUT_REDUCE_CONTEXT_THRESHOLD = 3;

// ── 日志 ─────────────────────────────────────────────
function log(level, msg, data) {
  const line = `[${new Date().toISOString()}] [${level}] ${msg}${data ? ' ' + JSON.stringify(data) : ''}`;
  console.log(line);
  if (CFG.logFile) {
    try { appendFileSync(CFG.logFile, line + '\n', 'utf-8'); } catch {}
  }
}

// 把上游错误体摘要成单行，便于日志排查。
// 之前 CC API error 只记 status，不记 body —— 遇到 400 只能靠猜（问题来源见 hk_sji 排查）。
// 截断到 500 字符，避免异常大的 body 刷爆日志；同时压掉换行，保证一条日志一行。
function summarizeUpstreamError(text, limit = 500) {
  if (!text) return '';
  const flat = String(text).replace(/\s+/g, ' ').trim();
  return flat.length > limit ? flat.slice(0, limit) + '…(' + (flat.length - limit) + ' more)' : flat;
}

// ── 会话管理 ───────────────────────────────────────
// 每个 API Key 独立一个 session，12h 过期 + 1h 随机抖动
// 同一 Key 在同一周期内复用，到期自动换新
const SESSION_DURATION_MS = 12 * 60 * 60 * 1000;    // 12h
const SESSION_JITTER_MS  = 60 * 60 * 1000;           // 1h 抖动范围

const sessionStore = new Map(); // apiKey → { sessionId, expiresAt }

function ensureSession(apiKey) {
  const now = Date.now();
  const entry = sessionStore.get(apiKey);

  if (entry && now < entry.expiresAt) {
    return entry.sessionId;
  }

  // 过期或第一次：生成新 session
  const jitter = Math.floor(Math.random() * SESSION_JITTER_MS);
  const sessionId = randomUUID();
  sessionStore.set(apiKey, { sessionId, expiresAt: now + SESSION_DURATION_MS + jitter });
      log('info', 'Session created', { sessionId: sessionId.slice(0, 8), storeSize: sessionStore.size });
  return sessionId;
}

// 定期清理过期 session 和 key 状态，防止 Map 无限增长
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [key, entry] of sessionStore) {
    if (now >= entry.expiresAt) {
      sessionStore.delete(key);
      keyStateStore.delete(key); // 同时清理该 key 的指纹状态
      cleaned++;
    }
  }
  if (cleaned > 0) log('info', 'Session cleanup', { cleaned, remaining: sessionStore.size });
}, 60 * 60 * 1000); // 每小时

function getSessionId(incomingHeaders, apiKey, promptCacheKey) {
  // 优先从客户端传来的 session 类 header 获取
  const candidates = [
    incomingHeaders['x-session-id'],
    incomingHeaders['x-claude-code-session-id'],
    incomingHeaders['session_id'],
    promptCacheKey,
  ];
  for (const id of candidates) {
    if (id && typeof id === 'string' && id.length >= 8) return id;
  }
  // 按 API Key 分 session
  return ensureSession(apiKey);
}

// 每个请求独立 thread ID
function newThreadId() { return randomUUID(); }

// ── 每 Key 独立状态（fingerprint + 初始化节流） ──
// 每个 API Key 拥有自己的设备指纹和初始化定时器
const keyStateStore = new Map(); // apiKey → { fingerprint, nextInitAt }

function getOrCreateKeyState(apiKey) {
  let state = keyStateStore.get(apiKey);
  if (!state) {
    state = {
      fingerprint: generateFingerprint(apiKey),
      nextInitAt: 0,
    };
    keyStateStore.set(apiKey, state);
    log('info', 'Fingerprint generated for key', { keyPrefix: apiKey.slice(0, 8) });
  }
  return state;
}

// ── 初始化预请求（fingerprint + lifecycle，首次 + 每 8h+2h 抖动） ────
const INIT_REFRESH_MS = 8 * 60 * 60 * 1000;    // 8h
const INIT_JITTER_MS  = 2 * 60 * 60 * 1000;    // 2h 抖动

async function ensureInitialized(apiKey, signal) {
  const state = getOrCreateKeyState(apiKey);
  const now = Date.now();
  if (now < state.nextInitAt) return;

  try {
    // 并行发两个预请求
    const headers = {
      'Content-Type': 'application/json',
      'x-cli-environment': 'production',
      'Authorization': `Bearer ${apiKey}`,
      'x-command-code-version': CC_VERSION,
      ...(CFG.zdr ? { 'x-cmd-zdr': '1' } : {}),
    };
    const fingerprint = state.fingerprint || {};

    await Promise.all([
      upstreamFetch(`${CFG.apiBase}/alpha/fingerprint/record`, {
        method: 'POST', headers, signal,
        body: JSON.stringify(fingerprint),
      }).then(r => {
        if (!r.ok) log('warn', 'Fingerprint record failed', { status: r.status });
        else log('info', 'Fingerprint recorded');
      }).catch(e => {
        if (e.name !== 'AbortError') log('warn', 'Fingerprint record error', { error: e.message });
      }),

      upstreamFetch(`${CFG.apiBase}/alpha/lifecycle-events`, {
        method: 'POST', headers, signal,
        body: JSON.stringify({
          eventType: 'cli_session_exists',
          metadata: {
            sessionId: `sess_${crypto.randomBytes(8).toString('hex')}`,
            cliVersion: CC_VERSION,
            mode: CFG.cliSessionMode || 'interactive',
            os: `${fingerprint.components.platform}-${fingerprint.components.arch}`,
          },
        }),
      }).then(r => {
        if (!r.ok) log('warn', 'Lifecycle event failed', { status: r.status });
        else log('info', 'Lifecycle event sent');
      }).catch(e => {
        if (e.name !== 'AbortError') log('warn', 'Lifecycle event error', { error: e.message });
      }),
    ]);

    // 成功：8h + 2h 随机抖动
    const jitter = Math.floor(Math.random() * INIT_JITTER_MS);
    state.nextInitAt = Date.now() + INIT_REFRESH_MS + jitter;
    log('info', 'Fingerprint/lifecycle next refresh', { nextIn: `${(INIT_REFRESH_MS + jitter) / 3600000}h` });
  } catch (e) {
    if (e.name !== 'AbortError') log('warn', 'Fingerprint/lifecycle refresh error, will retry next request', { error: e.message });
  }
}

// ── 模型列表 ───────────────────────────────────────
const MODELS = [
  // Anthropic
  { id: 'claude-sonnet-4-6', name: 'Claude Sonnet 4.6' },
  { id: 'claude-opus-4-8', name: 'Claude Opus 4.8' },
  { id: 'claude-opus-4-7', name: 'Claude Opus 4.7' },
  { id: 'claude-haiku-4-5-20251001', name: 'Claude Haiku 4.5' },
  // OpenAI
  { id: 'gpt-5.5', name: 'GPT-5.5' },
  { id: 'gpt-5.4', name: 'GPT-5.4' },
  { id: 'gpt-5.4-mini', name: 'GPT-5.4 Mini' },
  { id: 'gpt-5.3-codex', name: 'GPT-5.3 Codex' },
  // DeepSeek
  { id: 'deepseek/deepseek-v4-pro', name: 'DeepSeek V4 Pro' },
  { id: 'deepseek/deepseek-v4-flash', name: 'DeepSeek V4 Flash' },
  // Kimi
  { id: 'moonshotai/Kimi-K2.6', name: 'Kimi K2.6' },
  { id: 'moonshotai/Kimi-K2.5', name: 'Kimi K2.5' },
  // GLM
  { id: 'zai-org/GLM-5.1', name: 'GLM 5.1' },
  { id: 'zai-org/GLM-5', name: 'GLM 5' },
  // MiniMax
  { id: 'MiniMaxAI/MiniMax-M3', name: 'MiniMax M3' },
  { id: 'MiniMaxAI/MiniMax-M2.7', name: 'MiniMax M2.7' },
  { id: 'MiniMaxAI/MiniMax-M2.5', name: 'MiniMax M2.5' },
  // Qwen
  { id: 'Qwen/Qwen3.6-Max-Preview', name: 'Qwen 3.6 Max Preview' },
  { id: 'Qwen/Qwen3.6-Plus', name: 'Qwen 3.6 Plus' },
  { id: 'Qwen/Qwen3.7-Max', name: 'Qwen 3.7 Max' },
  // Step
  { id: 'stepfun/Step-3.7-Flash', name: 'Step 3.7 Flash' },
  { id: 'stepfun/Step-3.5-Flash', name: 'Step 3.5 Flash' },
  // Xiaomi
  { id: 'xiaomi/mimo-v2.5-pro', name: 'MiMo V2.5 Pro' },
  { id: 'xiaomi/mimo-v2.5', name: 'MiMo V2.5' },
  // Gemini
  { id: 'google/gemini-3.5-flash', name: 'Gemini 3.5 Flash' },
  { id: 'google/gemini-3.1-flash-lite', name: 'Gemini 3.1 Flash Lite' },
];

// ── 工具函数 ───────────────────────────────────────

// CLI 的 slug 规则：对**完整工作目录**做 slugify（@sindresorhus/slugify），空则 "root"，无随机后缀；
// 同一个 slug 也是 CLI 本地会话目录名。所以 slug 与 config.workingDir 同源：slug = slugify(workingDir)。
function slugifyProjectPath(p) {
  const s = String(p || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return s || 'root';
}

function generateTraceparent() {
  const traceId = crypto.randomBytes(16).toString('hex');
  const parentId = crypto.randomBytes(8).toString('hex');
  return `00-${traceId}-${parentId}-01`;
}

function nowUnix() {
  return Math.floor(Date.now() / 1000);
}

function getDateStr() {
  return new Date().toISOString().slice(0, 10);
}


// ── CC 请求体构建 ─────────────────────────────────

// 把客户端（Hermes / OpenAI 风格）的 reasoning_effort 归一化成 CC 能接受的档位。
// CC 的 params.reasoning_effort 只认 off|low|medium|high|xhigh|max，其它值会被
// 上游 400 拒绝：
//   Invalid request error. Often missing required parameters or typo.
//   HINT: Validation error: Invalid option: expected one of
//     "off"|"low"|"medium"|"high"|"xhigh"|"max" at "params.reasoning_effort"
// Hermes 会发 OpenAI 风格的 none/minimal 与自家档位 ultra，直接透传即 400，
// 所以在此统一映射；无法识别的值一律不发该字段，宁可用上游默认也不制造 400。
const REASONING_EFFORT_PASSTHROUGH = new Set(['off', 'low', 'medium', 'high', 'xhigh', 'max']);
function normalizeReasoningEffort(value) {
  // 非字符串（null / 数字 / 对象 …）无法识别，直接丢弃。
  if (typeof value !== 'string') return undefined;
  const key = value.trim().toLowerCase();
  if (!key) return undefined;                 // 空串 / 纯空白
  if (REASONING_EFFORT_PASSTHROUGH.has(key)) return key;  // 合法档位，忽略大小写与空白后原样下发
  if (key === 'none' || key === 'disabled' || key === 'false') return 'off';  // 语义等价：关闭思考
  if (key === 'minimal') return 'low';        // CC 没有比 low 更弱的"开启"档；绝不能折成 off（那会静默关闭思考）
  if (key === 'ultra') return 'max';          // Hermes 内部档位，CC 顶格是 max
  return undefined;                           // 其余未知值：省略字段，避免 400
}

function buildCcRequest(openaiReq) {
  const { model, messages, max_tokens, temperature, tools, stream, reasoning_effort, tool_choice, parallel_tool_calls, prompt_cache_key } = openaiReq;

  // 提取系统提示：OpenAI 的 system / developer 都映射为系统提示。
  // 形态对齐 CLI 的 toWireSystem —— **块数组**，非最后一块补 \n，cache_control 逐块保留。
  // （CLI 的 composeSystemPrompt：基础提示词是字符串时发字符串、是 sections 时发块数组；
  //   真机验证两种形态服务端都接受，见 PROTOCOL-FACTS-1.53.1.md。这里统一用块数组，
  //   才能把客户端标在 system 上的缓存断点原样送上去。）
  const systemMsgs = messages.filter(m => m.role === 'system' || m.role === 'developer');
  const systemBlocks = [];
  for (const m of systemMsgs) {
    if (typeof m.content === 'string') {
      if (m.content) systemBlocks.push({ type: 'text', text: m.content });
    } else if (Array.isArray(m.content)) {
      for (const c of m.content) {
        const text = c?.text ?? c?.content ?? '';
        if (text === '' && !c?.cache_control) continue;
        const block = { type: 'text', text: String(text) };
        if (c?.cache_control) block.cache_control = c.cache_control;
        systemBlocks.push(block);
      }
    } else if (m.content != null) {
      systemBlocks.push({ type: 'text', text: String(m.content) });
    }
  }
  for (let i = 0; i < systemBlocks.length - 1; i++) systemBlocks[i].text += '\n';
  const chatMessages = messages.filter(m => m.role !== 'system' && m.role !== 'developer');

  // Build tool_call_id → tool_name reverse lookup
  const toolNameMap = {};
  for (const msg of chatMessages) {
    if (msg.role === 'assistant' && msg.tool_calls) {
      for (const tc of msg.tool_calls) {
        if (tc.id) {
          toolNameMap[tc.id] = tc.function?.name || '';
        }
      }
    }
  }

  // 转换 messages 为 CC 格式
  const ccMessages = chatMessages.map(msg => {
    if (msg.role === 'user') {
      if (typeof msg.content === 'string') {
        return { role: 'user', content: [{ type: 'text', text: msg.content }] };
      }
      // 多模态：数组 content 原样透传（text + image_url → CC image 格式）
      if (Array.isArray(msg.content)) {
        const parts = msg.content.map(part => {
          if (part.type === 'image_url') {
            const url = part.image_url?.url || '';
            // CC CLI 真实格式: { type: "image", image: "data:<mime>;base64,...", mimeType: "<mime>" }
            const mediaType = /^data:([^;,]+)/.exec(url)?.[1];
            const imagePart = { type: 'image', image: url };
            if (mediaType) imagePart.mimeType = mediaType;
            return imagePart;
          }
          return part;
        }).filter(Boolean);
        return { role: 'user', content: parts };
      }
      return { role: 'user', content: [{ type: 'text', text: String(msg.content) }] };
    }
    if (msg.role === 'assistant') {
      const parts = [];
      // 思考内容必须回传：CC 在 thinking 模式下校验 reasoning 是否随历史带回，
      // 丢弃会让上游直接拒绝。次序也必须与 CC CLI 的抓包格式一致 ——
      // [reasoning, text, tool-call]，reasoning 在最前。
      if (msg.reasoning_content) {
        parts.push({ type: 'reasoning', text: msg.reasoning_content });
      }
      if (msg.content && typeof msg.content === 'string') {
        if (msg.content) parts.push({ type: 'text', text: msg.content });
      } else if (msg.content && Array.isArray(msg.content)) {
        for (const part of msg.content) {
          if (!part) continue;
          if (part.type === 'text') parts.push(part);
          // 客户端直接把 reasoning 放在 content 数组里时同样透传；
          // 已有 reasoning_content 字段则不重复
          else if (part.type === 'reasoning' && !msg.reasoning_content) parts.push(part);
        }
      }
      if (msg.tool_calls) {
        for (const tc of msg.tool_calls) {
          parts.push({
            type: 'tool-call',
            toolCallId: tc.id,
            toolName: tc.function?.name || '',
            input: (typeof tc.function?.arguments === 'string' ? tryParseJSON(tc.function.arguments) : (tc.function?.arguments || {})),
          });
        }
      }
      return { role: 'assistant', content: parts };
    }
    if (msg.role === 'tool') {
      return {
        role: 'tool',
        content: [{
          type: 'tool-result',
          toolCallId: msg.tool_call_id,
          toolName: toolNameMap[msg.tool_call_id] || msg.name || '',
          output: { type: 'text', value: toWireToolOutputValue(msg.content) },
        }],
      };
    }
    // 未知 role 兜底：归一化为 user 并保证 content 为数组，避免 CC 校验拒绝
    return { role: 'user', content: [{ type: 'text', text: String(msg.content ?? '') }] };
  });

  // 缓存断点：system 是块数组，断点可以原样留在 system 上（CLI 的 systemSections[].cache 同义）。
  // 客户端已在任意消息块 / system 块上打过断点就保留；否则若给了 OpenAI 系的 prompt_cache_key，
  // 把断点落在 system 最后一块 —— 缓存按前缀计算，system 正是最前的那段前缀。
  const hasCacheMarker = systemBlocks.some(b => b.cache_control) || ccMessages.some(msg =>
    Array.isArray(msg.content) && msg.content.some(part => part?.cache_control));
  if (prompt_cache_key && !hasCacheMarker && systemBlocks.length) {
    systemBlocks[systemBlocks.length - 1].cache_control = { type: 'ephemeral' };
  }

  const body = {
    config: {
      // 伪造的项目目录（不再发宿主真实 cwd）；environment 用伪装的平台词，与指纹保持自洽
      workingDir: DEVICE_PROFILE.projectDir,
      date: getDateStr(),
      environment: DEVICE_PROFILE.platform,
      structure: [],
      isGitRepo: false,
      currentBranch: '',
      mainBranch: '',
      gitStatus: '',
      recentCommits: [],
    },
    memory: null,
    taste: null,
    skills: null,          // CLI 发 null，不是空串
    permissionMode: 'standard',
    mode: CFG.cliMode || 'agent',
    // threadId 需为合法 UUID，否则整键省略（CLI 的 toWireThreadId）—— 在 forwardToCC 拿到 sessionId 后补
    params: {
      model: model || 'deepseek/deepseek-v4-flash',
      messages: ccMessages,
      max_tokens: Math.min(max_tokens || 64000, 200000),
      stream: true,  // CC API 总是 stream
    },
  };

  // 条件字段
  if (systemBlocks.length) {
    body.params.system = systemBlocks;
  } else if (CFG.emptySystemPlaceholder) {
    // CC 上游在 params.system 缺省时会注入自身约 7.5K token 的默认提示词（进入
    // 默认上下文/前缀路径），既产生大量 cached tokens 又污染对话（模型会以为
    // 自己在 CC 的可执行目录里，见 issue #17）。发一个空格占位即可绕过，
    // 真机验证 prompt_tokens 从 7653 降到 85。
    // 默认开启；config.json 设 "emptySystemPlaceholder": false 或环境变量
    // CC_EMPTY_SYSTEM_PLACEHOLDER=false 可关闭（回到原生的缺省行为）。
    body.params.system = [{ type: 'text', text: ' ' }];
  }
  if (temperature !== undefined) {
    body.params.temperature = temperature;
  }
  // 出口归一化：这是 /v1/chat/completions 与 /v1/messages 共用的唯一出口
  const normalizedEffort = normalizeReasoningEffort(reasoning_effort);
  if (normalizedEffort !== undefined) {
    body.params.reasoning_effort = normalizedEffort;
  }
  // CLI 总是下发 tools（没有工具时是空数组）—— 空数组与缺键在 wire 上可观测，这里对齐
  // CLI 的 toWireTools：只有 name / description / input_schema，没有 type 字段
  body.params.tools = (tools || []).map(t => ({
      name: toWireToolName(t.function?.name || t.name || ''),
      description: t.function?.description || t.description || '',
      input_schema: t.function?.parameters || t.input_schema || { type: 'object', properties: {} },
    }));
  if (tool_choice !== undefined) {
    // OpenAI 格式 → CC (Anthropic 风格) 格式
    if (typeof tool_choice === 'string') {
      const map = { 'auto': 'auto', 'none': 'none', 'required': 'any' };
      body.params.tool_choice = { type: map[tool_choice] || 'auto' };
    } else if (tool_choice.type === 'function') {
      // OpenAI object → Anthropic object
      body.params.tool_choice = { type: 'tool', name: tool_choice.function?.name };
    } else {
      body.params.tool_choice = tool_choice;
    }
  }
  if (parallel_tool_calls !== undefined) {
    body.params.parallel_tool_calls = parallel_tool_calls;
  }

  return body;
}

// CLI 发送前会重写部分工具名（resolveToolNameAlias / ow 表）
const TOOL_NAME_ALIASES = {
  bash_output: 'shell_output',
  task_output: 'shell_output',
  tool_search: 'search_tools',
  read_multiple_files: 'read_file',
};
function toWireToolName(name) { return TOOL_NAME_ALIASES[name] || name; }

// CLI 的 toWireToolOutput：只取文本块，用 '\n' 拼接
function toWireToolOutputValue(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content.filter(c => c && c.type === 'text').map(c => c.text ?? '').join('\n');
  }
  return content == null ? '' : String(content);
}

function tryParseJSON(str) {
  try { return JSON.parse(str); } catch { return {}; }
}

// ── CC NDJSON → OpenAI SSE 转换 ────────────────────

function createSseTranslator(model, completionId, created) {
  // 是否见过终态 finish 事件。CLI 用同一个标志判定「流是不是被截断了」。
  let sawFinish = false;
  let chunkIndex = 0;
  let sentRole = false;
  let finishReason = null;
  let usage = null;
  let toolCallIndex = 0;

  return {
    lastCcEvent: '',
    upstreamError: null,
    inputTokens: 0,
    outputTokens: 0,
    cachedInputTokens: 0,
    /** 解析一行 NDJSON，返回 OpenAI chunk 数组 */
    parseLine(line) {
      const trimmed = line.trim();
      if (!trimmed || trimmed === '[DONE]' || trimmed.startsWith(':')) return null;

      let event;
      try { event = JSON.parse(trimmed); } catch { return null; }
      if (!event.type) return null;
      this.lastCcEvent = event.type;

      const out = [];

      switch (event.type) {
        case 'text-start':
        case 'reasoning-start':
        case 'start':
        case 'start-step':
          // 忽略，无用户可见内容
          break;

        case 'text-delta': {
          const text = event.text || event.delta || '';
          if (!text) break;
          const delta = chunkIndex === 0 ? { role: 'assistant', content: text } : { content: text };
          chunkIndex++;
          sentRole = true;
          out.push(makeChunk(completionId, created, model, delta, null, null));
          break;
        }

        case 'reasoning-delta': {
          const text = event.text || '';
          if (!text) break;
          const delta = chunkIndex === 0
            ? { role: 'assistant', reasoning_content: text }
            : { reasoning_content: text };
          chunkIndex++;
          out.push(makeChunk(completionId, created, model, delta, null, null));
          break;
        }

        case 'tool-call': {
          const id = event.toolCallId || `call_${Date.now()}_${toolCallIndex}`;
          const name = event.toolName || '';
          const args = typeof event.input === 'string' ? event.input : JSON.stringify(event.input || {});
          const tcEntry = { index: toolCallIndex, id, type: 'function', function: { name, arguments: args } };
          const delta = chunkIndex === 0
            ? { role: 'assistant', content: null, tool_calls: [tcEntry] }
            : { tool_calls: [tcEntry] };
          chunkIndex++;
          toolCallIndex++;
          out.push(makeChunk(completionId, created, model, delta, null, null));
          break;
        }

        case 'finish-step': {
          sawFinish = true;
          if (event.finishReason) finishReason = mapFinishReason(event.finishReason);
          if (event.usage) {
            usage = event.usage;
            this.inputTokens = event.usage.inputTokens ?? 0;
            this.outputTokens = event.usage.outputTokens ?? 0;
            this.cachedInputTokens = event.usage.cachedInputTokens ?? 0;
          }
          break;
        }

        case 'finish': {
          sawFinish = true;
          const fr = toOpenAIFinishReason(finishReason || mapFinishReason(event.finishReason || 'stop'));
          const u = event.totalUsage || usage || {};
          normalizeUsage(u);
          this.inputTokens = u.inputTokens ?? 0;
          this.outputTokens = u.outputTokens ?? 0;
          this.cachedInputTokens = u.cachedInputTokens ?? 0;
          const openaiUsage = u ? {
            prompt_tokens: u.inputTokens ?? 0,
            completion_tokens: u.outputTokens ?? 0,
            total_tokens: (u.inputTokens ?? 0) + (u.outputTokens ?? 0),
            prompt_tokens_details: { cached_tokens: u.cachedInputTokens ?? 0 },
          } : undefined;
          out.push(makeChunk(completionId, created, model, {}, fr, openaiUsage));
          break;
        }

        case 'error': {
          const msg = event.error?.message || event.message || 'Unknown error';
          this.upstreamError = mapCcEventError(event);
          // 先映射再记日志，并把上游自带的状态/可重试性一并打出 ——
          // 排查容量/限流类问题时，真正需要的就是这两个字段
          log('warn', 'CC stream error', {
            message: msg,
            upstreamStatus: this.upstreamError.reportedStatus,
            upstreamRetryable: event.error?.isRetryable,
            code: this.upstreamError.code,
            mappedTo: this.upstreamError.status,
          });
          // Don't emit a finish_reason chunk — let the natural stream termination
          // handle it. Otherwise a subsequent finish(tool_calls) would be ignored
          // by downstream agent loops that stop at the first finish_reason.
          break;
        }

        case 'reasoning-end': case 'provider-metadata': case 'tool-input-start': case 'tool-input-delta': case 'tool-input-end': case 'tool-error': case 'text-end':
          // Silent - no user-visible content
          break;
        default:
          log('warn', 'Unknown CC event type', { type: event.type });
          break;
      }

      return out.length > 0 ? out : null;
    },

    /** 这次上游流若没有正常走完 finish，返回可读原因；正常则为 null。 */
    incompleteDetail() {
      return incompleteUpstreamDetail(sawFinish, finishReason);
    },

    /** 获取 SSE 结束标记 */
    getDoneEvent() {
      return 'data: [DONE]\n\n';
    },
  };
}

function makeChunk(id, created, model, delta, finishReason, usage) {
  const chunk = {
    id,
    object: 'chat.completion.chunk',
    created,
    model,
    choices: [{ index: 0, delta, finish_reason: finishReason || null }],
  };
  if (usage) chunk.usage = usage;
  return `data: ${JSON.stringify(chunk)}\n\n`;
}

// normalize CC usage stats:
// - outputTokens=0 → zero everything (anti false billing)
function normalizeUsage(u) {
  if (!u) return;
  const ot = Number(u.outputTokens);
  if (!ot) {  // 0, null, undefined, NaN → zero input + cached (anti false billing)
    u.inputTokens = 0;
    u.cachedInputTokens = 0;
  }
}

// CC 的 inputTokens 是「总数」（含缓存命中部分），而 Anthropic 的 input_tokens 只计
// 非缓存部分 —— 官方 SDK 注释：Total input tokens in a request is the summation of
// `input_tokens`, `cache_creation_input_tokens`, and `cache_read_input_tokens`。
// 直接把 CC 的 inputTokens 当 input_tokens 转发，会让下游把两者当成互不重叠的两部分，
// 相加后约为真实输入的两倍（issue #25）。
//
// CC 实际已经算好：inputTokenDetails.noCacheTokens（实测 noCacheTokens + cacheReadTokens
// === inputTokens）。优先采用该字段；缺失时回退到减法，保证老版本上游也能得到正确值。
function anthropicInputTokens(usage, noCacheOverride) {
  const u = usage || {};
  if (typeof noCacheOverride === 'number' && noCacheOverride >= 0) return noCacheOverride;
  const noCache = u.inputTokenDetails && u.inputTokenDetails.noCacheTokens;
  if (typeof noCache === 'number' && noCache >= 0) return noCache;
  const cacheRead = u.cachedInputTokens || (u.inputTokenDetails && u.inputTokenDetails.cacheReadTokens) || 0;
  const cacheWrite = (u.inputTokenDetails && u.inputTokenDetails.cacheWriteTokens) || 0;
  return Math.max(0, (u.inputTokens || 0) - cacheRead - cacheWrite);
}

// 上游 finishReason → 本代理内部规范化取值。
// 对齐 CLI 的 normalizeStopReason2 / isNetworkFailureFinish（command-code@1.54.0）：
//   tool_use | tool-calls | tool_calls                    → tool_calls
//   length | max_tokens | max_output_tokens
//          | model_context_window_exceeded                → length
//   /^(network|connection|upstream)[-_\s]?error$/i        → upstream_error
//   pause_turn                                            → pause_turn（原样保留）
// 关键点：'length' 家族**不止 'length' 一个值**。max_output_tokens 与
// model_context_window_exceeded 都是「输出被截断」，折成 stop/end_turn 等于
// 把半截回答谎报成完整回答。未知值一律原样返回，宁可让它露出来也不要静默折成 stop。
function mapFinishReason(reason) {
  const r = String(reason ?? '').trim().toLowerCase();
  if (!r) return 'stop';
  if (r === 'tool-calls' || r === 'tool_calls' || r === 'tool_use') return 'tool_calls';
  if (r === 'length' || r === 'max_tokens'
      || r === 'max_output_tokens' || r === 'model_context_window_exceeded') return 'length';
  if (/^(?:network|connection|upstream)[-_\s]?error$/.test(r)) return 'upstream_error';
  return r;
}

// 上游「没有正常走完」的两种情形，CLI 都当成可重试的 502：
//   · 流里根本没有 finish 事件 —— "Stream ended unexpectedly before completion
//     (no finish event) — response was truncated"
//   · provider 报 network/connection/upstream-error —— isNetworkFailureFinish
// 返回 null 表示这次流是正常结束的。
//
// sawFinish 的口径是「上游给过任何完成信号」：终态 finish，以及本代理一直在处理的
// finish-step。（'finish-step' 在 CLI 的事件集里不存在 —— 见 proxy.mjs 各处注释 ——
// 但既然代理认它，就不能让它变成「没完成」，否则会把原本正常的响应误判成 502。
// 真正要拦的是「一个完成信号都没有就断了」。）
function incompleteUpstreamDetail(sawFinish, finishReason) {
  if (!sawFinish) return 'no finish event';
  if (finishReason === 'upstream_error') return 'provider reported an upstream connection failure';
  return null;
}

function incompleteUpstreamError(detail) {
  return {
    status: 502,
    // retry_after 同时放在 body 里与顶层：sendJSON 只发 body，
    // 而 sendAnthropicError / sendResponsesError 需要单独的形参。
    body: {
      error: {
        message: `Upstream stream ended without a completion finish (${detail}) — response was truncated`,
        type: 'upstream_error',
      },
      retry_after: 10,
    },
    retry_after: 10,
  };
}

// ── 错误映射 ───────────────────────────────────────
const CC_STATUS_MAP = {
  400: { status: 400, type: 'invalid_request_error' },
  401: { status: 401, type: 'authentication_error' },
  402: { status: 429, type: 'rate_limit_error' },       // payment required → rate limit
  403: { status: 401, type: 'authentication_error' },
  404: { status: 404, type: 'not_found' },
  422: { status: 400, type: 'invalid_request_error' },
  429: { status: 429, type: 'rate_limit_error' },
  500: { status: 502, type: 'upstream_error' },
  502: { status: 502, type: 'upstream_error' },
  503: { status: 503, type: 'temporarily_unavailable' },
};

function mapCcError(ccStatus, ccBody) {
  const mapped = CC_STATUS_MAP[ccStatus] || { status: 502, type: 'upstream_error' };
  let message = `CC API error (${ccStatus})`;
  let code = null;

  if (ccBody) {
    try {
      const parsed = JSON.parse(ccBody);
      message = parsed.error?.message || parsed.message || message;
      // 上游错误体：{"success":false,"error":{"code":"BAD_REQUEST"|"USAGE_EXCEEDED",...}}
      // code 是上游的机器可读错误分类（BAD_REQUEST / USAGE_EXCEEDED 等），透出来便于下游 SDK 与运维判定
      code = parsed.error?.code || parsed.code || null;
    } catch {
      message = ccBody.slice(0, 200) || message;
    }
  }

  // CC 429 响应可能带 retry-after
  if (ccStatus === 429) {
    return {
      status: 429,
      code,
      body: {
        error: { message, type: 'rate_limit_error', ...(code ? { code } : {}) },
        retry_after: 30,
      },
    };
  }

  return { status: mapped.status, code, body: { error: { message, type: mapped.type, ...(code ? { code } : {}) } } };
}

function mapCcEventError(event) {
  const message = event.error?.message || event.message || 'Unknown CC error';
  const code = event.error?.code || event.code || null;
  // 上游 error 事件除了 message 还可能自带 statusCode / isRetryable ——
  // CLI 的 readStreamErrorEvent 读的正是这两个字段，取值链是
  //   parseEmbeddedErrorJSON(message)?.status ?? error.statusCode ?? null
  // 原实现只看 message 里的 "<NNN>" 前缀，statusCode 一律被丢掉，
  // 于是 429 / 503 这类「该退避重试」的信号在代理这一层被抹平成 502「服务端错误」：
  // 客户端不再按限流退避，监控也会把它错误归类成后端故障。
  const statusMatch = message.match(/^<(\d{3})>/);
  const reportedStatus = statusMatch
    ? Number(statusMatch[1])
    : (Number.isInteger(event.error?.statusCode) ? event.error.statusCode : null);
  const ccStatus = reportedStatus ?? 502;
  const mapped = CC_STATUS_MAP[ccStatus] || { status: 502, type: 'upstream_error' };

  // 与 mapCcError 保持一致：终态为 429 时带上 retry_after，
  // 否则客户端 SDK 拿不到退避提示（402 也映射成 429，一视同仁）
  if (mapped.status === 429) {
    return {
      status: 429,
      code,
      reportedStatus,
      body: { error: { message, type: 'rate_limit_error', ...(code ? { code } : {}) }, retry_after: 30 },
    };
  }

  return { status: mapped.status, code, reportedStatus,
    body: { error: { message, type: mapped.type, ...(code ? { code } : {}) } } };
}

// ── HTTP 请求处理 ──────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalSize = 0;
    let settled = false;
    let drained = 0;
    // 413 拒绝后转入排空模式：继续读取并丢弃剩余请求体，保持 keep-alive 连接可复用，
    // 让客户端明确收到 413 而不是 Connection reset（issue #7）。
    // 但若客户端无视 413 持续上传超过 DRAIN_LIMIT，则强制掐断，不无限吞带宽。
    const DRAIN_LIMIT = 32 * 1024 * 1024;
    req.on('data', c => {
      if (settled) {
        drained += c.length;
        if (drained > DRAIN_LIMIT) { try { req.destroy(); } catch {} }
        return;
      }
      totalSize += c.length;
      if (totalSize > MAX_BODY_SIZE) {
        settled = true;
        chunks.length = 0;
        const mb = Math.round(MAX_BODY_SIZE / 1024 / 1024);
        const err = new Error(`Request body exceeds ${mb}MB limit`);
        err.statusCode = 413;
        reject(err);
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString())); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', e => { if (!settled) { settled = true; reject(e); } });
  });
}

// 下游背压：res.write() 返回 false 表示 socket 写缓冲已超 highWaterMark（消费者跟不上）。
// 忽略它会让整个上游流在内存中无界堆积 —— 客户端不读时 RSS 随上游流一起增长（issue #20）。
// 必须同时监听 close/error，否则客户端断连会让请求协程永久挂起。
// CLIENT_DRAIN_TIMEOUT_MS > 0 时额外加一道空闲看门狗：超时则 destroy 该响应，
// 由此触发既有的 res 'close' 处理器 → aborted=true → 中止 CC 上游，无需改动各调用点。
function waitDrain(res) {
  if (!res.writableNeedDrain) return Promise.resolve();
  return new Promise((resolve) => {
    let timer = null;
    const done = () => {
      res.off('drain', done); res.off('close', done); res.off('error', done);
      if (timer) { clearTimeout(timer); timer = null; }
      resolve();
    };
    res.once('drain', done); res.once('close', done); res.once('error', done);
    if (CLIENT_DRAIN_TIMEOUT_MS > 0) {
      timer = setTimeout(() => {
        log('warn', 'Client stalled on backpressure, dropping connection', {
          path: res.req?.url || '(unknown)',
          timeoutMs: CLIENT_DRAIN_TIMEOUT_MS,
          bufferedBytes: res.writableLength,
        });
        try { res.destroy(); } catch {}
        done();
      }, CLIENT_DRAIN_TIMEOUT_MS);
    }
  });
}

// 上游读空闲看门狗：复用单个定时器，避免「每个 chunk 新建一个 setTimeout 且从不清理」。
// 实测每个待触发定时器滞留约 225B；稳态滞留 = 吞吐 × 超时窗口 × 每响应 chunk 数 × 225B
// （50 rps × 2000 chunk × 30s ≈ 644MB，非流式 90s 窗口约为其三倍）。
// arm() 用 refresh() 把窗口重置为「本轮 read 开始」，与原实现语义一致：超时只计 reader.read() 的等待。
function createIdleWatchdog(timeoutMs) {
  let rejectFn = null;
  const expired = new Promise((_, reject) => { rejectFn = reject; });
  expired.catch(() => {}); // 读循环退出后定时器才触发时，避免 unhandledRejection
  const timer = setTimeout(() => rejectFn(new Error('STREAM_IDLE_TIMEOUT')), timeoutMs);
  return {
    arm() { timer.refresh(); return expired; },
    dispose() { clearTimeout(timer); },
  };
}

function sendJSON(res, status, data) {
  const headers = { 'Content-Type': 'application/json' };
  if (data && data.retry_after !== undefined) {
    headers['Retry-After'] = String(data.retry_after);
  }
  res.writeHead(status, headers);
  res.end(JSON.stringify(data));
}

function getApiKey(headers) {
  // Try Authorization: Bearer header (OpenAI SDK style)
  const auth = headers['authorization'] || headers['Authorization'] || '';
  if (auth.startsWith('Bearer ')) {
    const match = auth.slice(7).match(/user_[a-zA-Z0-9_-]+/);
    if (match) return match[0];
  }
  // Fall back to x-api-key header (Anthropic SDK style)
  const xKey = headers['x-api-key'] || headers['X-Api-Key'] || '';
  if (xKey) {
    const match = xKey.match(/user_[a-zA-Z0-9_-]+/);
    if (match) return match[0];
  }
  return null;
}

// ── 上游 HTTP(S) 代理（issue #18）────────────────────
// 仅作用于发往 CC 上游的请求（/alpha/generate、/provider/v1/models）。
// 本地监听、/health 与 npm registry 版本检查都不经过代理。
//
// 零依赖实现：自己建立 CONNECT 隧道，再用 node:https 复用同一个 socket，
// 因此不需要 undici / https-proxy-agent，engines >=18 也能用。
// 注意 Node 原生 fetch 不读 HTTPS_PROXY/HTTP_PROXY；官方的环境变量方案需要
// Node >= 22.21 / 24.5 并设 NODE_USE_ENV_PROXY=1（README 有说明）。
const UPSTREAM_PROXY = CFG.upstreamProxy || '';
const PROXY_CONNECT_TIMEOUT_MS = 15000;

// 代理 URL 可能带 user:pass —— 任何日志/错误消息都只允许出现 host:port。
// （README 承诺「隐私保护日志」，把口令打进启动横幅是直接违反。）
function redactProxyUrl(raw) {
  if (!raw) return '(direct)';
  try {
    const u = new URL(raw);
    return `${u.protocol}//${u.hostname}${u.port ? ':' + u.port : ''}`;
  } catch {
    return '(invalid upstreamProxy)';
  }
}

function parseProxyUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    // 不回显原串：里面可能就是口令
    throw new Error('upstreamProxy is not a valid URL (expected http://host:port)');
  }
  if (u.protocol !== 'http:') {
    throw new Error(`upstreamProxy only supports http:// (CONNECT) proxies, got ${u.protocol}//`);
  }
  const auth = u.username
    ? 'Basic ' + Buffer.from(`${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`).toString('base64')
    : null;
  return { host: u.hostname, port: Number.parseInt(u.port || '80', 10), auth };
}

// 启动即校验：写错的代理地址应当立刻拒绝启动，而不是每个请求各 502 一次。
if (UPSTREAM_PROXY) {
  try {
    parseProxyUrl(UPSTREAM_PROXY);
  } catch (e) {
    log('error', 'Invalid upstreamProxy, refusing to start', {
      error: e.message, value: redactProxyUrl(UPSTREAM_PROXY),
    });
    process.exit(1);
  }
  log('info', 'Upstream requests will go through the configured proxy', {
    proxy: redactProxyUrl(UPSTREAM_PROXY),
  });
}

/** Response 的 headers 需要字符串值；node 的 set-cookie 是数组，展开为多行。 */
function headersToInit(raw) {
  const out = [];
  for (const [k, v] of Object.entries(raw)) {
    if (Array.isArray(v)) { for (const item of v) out.push([k, String(item)]); }
    else if (v !== undefined) out.push([k, String(v)]);
  }
  return out;
}

/** 经 HTTP 代理发上游请求，返回与 fetch 兼容的 Response（.ok/.status/.text()/.body）。 */
async function proxyFetch(urlStr, options = {}) {
  const proxy = parseProxyUrl(UPSTREAM_PROXY);
  const u = new URL(urlStr);
  const isTls = u.protocol === 'https:';
  const port = Number.parseInt(u.port || (isTls ? '443' : '80'), 10);
  const target = `${u.hostname}:${port}`;
  const { signal, body } = options;
  const onAbort = (fn) => { if (signal) signal.addEventListener('abort', fn, { once: true }); };

  // 1. CONNECT 隧道 —— 代理只做裸字节转发，TLS 由本端端到端完成
  const rawSocket = await new Promise((resolve, reject) => {
    const connectReq = http.request({
      host: proxy.host,
      port: proxy.port,
      method: 'CONNECT',
      path: target,
      headers: { Host: target, ...(proxy.auth ? { 'Proxy-Authorization': proxy.auth } : {}) },
      timeout: PROXY_CONNECT_TIMEOUT_MS,
    });
    connectReq.on('connect', (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        reject(new Error(`upstream proxy CONNECT ${target} failed: HTTP ${res.statusCode}`));
        return;
      }
      resolve(socket);
    });
    connectReq.on('timeout', () => connectReq.destroy(new Error('upstream proxy CONNECT timeout')));
    connectReq.on('error', reject);
    onAbort(() => { try { connectReq.destroy(); } catch {} });
    connectReq.end();
  });

  // 2. 隧道上做 TLS（证书按目标主机名校验，不做任何降级）
  let socket = rawSocket;
  if (isTls) {
    socket = tls.connect({ socket: rawSocket, servername: u.hostname });
    await new Promise((resolve, reject) => {
      socket.once('secureConnect', resolve);
      socket.once('error', reject);
      onAbort(() => { try { socket.destroy(); } catch {} });
    });
  }

  // 3. 复用隧道 socket 发请求
  return await new Promise((resolve, reject) => {
    const mod = isTls ? https : http;
    const req = mod.request({
      host: u.hostname,
      port,
      path: u.pathname + u.search,
      method: options.method || 'GET',
      headers: options.headers || {},
      createConnection: () => socket,
    }, (res) => {
      // 204/205/304 按规范不允许带 body，Response 构造器会直接抛 —— 这两个状态必须传 null，
      // 同时把连接排空，避免隧道 socket 悬着。
      const nullBodyStatus = res.statusCode === 204 || res.statusCode === 205 || res.statusCode === 304;
      if (nullBodyStatus) { try { res.resume(); } catch {} }
      resolve(new Response(nullBodyStatus ? null : Readable.toWeb(res), {
        status: res.statusCode,
        statusText: res.statusMessage,
        headers: headersToInit(res.headers),
      }));
    });
    req.on('error', reject);
    onAbort(() => { try { req.destroy(); } catch {} });
    if (body !== undefined && body !== null) req.write(body);
    req.end();
  });
}

/** 上游请求入口：配了代理走隧道，否则用原生 fetch（默认路径行为完全不变）。 */
function upstreamFetch(urlStr, options) {
  return UPSTREAM_PROXY ? proxyFetch(urlStr, options) : fetch(urlStr, options);
}

// ── 流式转发 ────────────────────────────────────────

async function forwardToCC(body, apiKey, incomingHeaders = {}, signal, promptCacheKey) {
  const url = `${CFG.apiBase}/alpha/generate`;
  const traceparent = generateTraceparent();
  const sessionId = getSessionId(incomingHeaders, apiKey, promptCacheKey);
  // CLI 的 toWireThreadId：只有合法 UUID 才放进信封，否则整个键省略。
  // 同时按 CLI 的键顺序重排：config, memory, taste, skills, permissionMode, threadId, mode, params
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(sessionId))) {
    const ordered = {};
    for (const k of ['config', 'memory', 'taste', 'skills', 'permissionMode']) ordered[k] = body[k];
    ordered.threadId = sessionId;
    for (const k of ['mode', 'promptCache', 'params']) if (k in body) ordered[k] = body[k];
    body = ordered;
  }

  // 与 CLI 的 buildCommandAuthHeaders 对齐：没有 x-co-flag；User-Agent 固定 "cli"
  const headers = {
    'Content-Type': 'application/json',
    'User-Agent': 'cli',
    'x-command-code-version': CC_VERSION,
    'x-cli-environment': 'production',
    'x-project-slug': slugifyProjectPath(DEVICE_PROFILE.projectDir),
    'x-taste-learning': 'false',
    'x-session-id': sessionId,
    'Authorization': `Bearer ${apiKey}`,
    'traceparent': traceparent,
  };

  if (CFG.zdr || incomingHeaders['x-cmd-zdr'] === '1') {
    headers['x-cmd-zdr'] = '1';
  }

  const response = await upstreamFetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
    signal,
  });

  return response;
}

// ── 路由 ────────────────────────────────────────────

async function handleChatCompletions(req, res) {
  let openaiReq;
  try {
    openaiReq = await readBody(req);
  } catch (e) {
    if (e.statusCode === 413) {
      sendJSON(res, 413, { error: { message: e.message, type: 'invalid_request_error' } });
      return;
    }
    sendJSON(res, 400, { error: { message: 'Invalid JSON body', type: 'invalid_request_error' } });
    return;
  }

  let route = resolveRoute(req.headers);
  if (route && route.error === 'no_available_account') {
    res.setHeader('Retry-After', '5');
    sendJSON(res, 503, { error: { message: 'No available upstream account for this token', type: 'no_available_account' }, retry_after: 5 });
    return;
  }
  if (!route) {
    sendJSON(res, 401, { error: { message: 'Missing API key. Send in Authorization: Bearer <key> or x-api-key header', type: 'auth_error' } });
    return;
  }
  let apiKey = route.upstreamKey;
  const outcome = { state: 'pending', ttftMs: null, status: null, code: null, message: null };
  const startTime = Date.now();
  const markTtft = () => { if (outcome.ttftMs == null) outcome.ttftMs = Date.now() - startTime; };
  try {

  const stream = openaiReq.stream === true;
  const model = openaiReq.model || 'deepseek/deepseek-v4-flash';
  const completionId = `chatcmpl-${randomUUID().slice(0, 12)}`;
  const created = nowUnix();

  // 构建 CC 请求体
  const ccBody = buildCcRequest(openaiReq);

  // AbortController 用于客户端断连时真正打断 CC 上游（pi-commandcode-provider 模式）
  // 每次尝试都换一个新的（已 abort 的 signal 不可复用）
  let abortController = new AbortController();
  let aborted = false;
  // 提前初始化，断连回调/超时 catch 安全引用（避免块级作用域 ReferenceError）
  let bytesReceived = 0; let lastCcEvent = ''; let keepaliveCount = 0; let fullText = '';
  let reader = null;
  let translator = null;
  let attempt = 0;
  let upstreamError = null;   // 非流式路径解析出的上游语义错误（error 事件）
  let delivered = false;      // 本次尝试是否真的把正常响应交付给了下游（用于重试后的日志/计数）

  // 发起下一次尝试前，把本次尝试的上游连接收干净并记账。
  // 只在「下游尚未收到任何字节」时调用 —— 下游没有开始过，重试才是无损的。
  const rewindAttempt = async (message, fields) => {
    try { reader?.cancel().catch(() => {}); } catch {}
    try { abortController.abort(); } catch {}
    upstreamRetryStats.rewinds++;
    log('warn', message, {
      path: '/v1/chat/completions',
      model,
      attempt,
      maxAttempts: UPSTREAM_RETRY_MAX + 1,
      elapsedMs: Date.now() - startTime,
      ...fields,
    });
    await sleep(UPSTREAM_RETRY_BASE_MS * attempt);
  };

  // 上游闪断重试循环：只在「传输层闪断」且「尚未向下游写出任何字节」时
  // 才再来一遍；正常路径第一轮即 break。循环体沿用原有缩进、未做重排，只为把 diff 控到最小。
  attemptLoop: for (attempt = 1; attempt <= UPSTREAM_RETRY_MAX + 1; attempt++) {
  // 退避期间客户端断开了：下游已经走了，再打一次上游只是白烧额度
  if (attempt > 1 && aborted) {
    log('info', 'Upstream retry abandoned (client disconnected during backoff)', {
      path: '/v1/chat/completions', model, attempt, elapsedMs: Date.now() - startTime,
    });
    return;
  }
  // 每次尝试开始：重置本次请求的状态（上一次可能已被中断 / 半途失败）
  abortController = new AbortController();
  bytesReceived = 0; lastCcEvent = ''; keepaliveCount = 0; fullText = '';
  reader = null; translator = null; upstreamError = null; delivered = false;

  try {
    // 首次初始化（fingerprint + lifecycle）
    await ensureInitialized(apiKey, abortController.signal);
    // 转发到 CC API（传入客户端 headers，用于提取 session ID）
    let ccResponse = await forwardToCC(ccBody, apiKey, req.headers, abortController.signal, openaiReq.prompt_cache_key);

    if (!ccResponse.ok) {
      let errorText = await ccResponse.text().catch(() => '');
      let mapped = mapCcError(ccResponse.status, errorText);
      // 额度耗尽 → 换号重放（客户端无感）；其余错误照旧返回
      const fo = await creditFailover({
        route, apiKey, ccResponse, errorText, mapped, outcome, req,
        forward: async (key) => {
          await ensureInitialized(key, abortController.signal);
          return forwardToCC(ccBody, key, req.headers, abortController.signal, openaiReq.prompt_cache_key);
        },
      });
      route = fo.route; apiKey = fo.apiKey; ccResponse = fo.ccResponse;
      errorText = fo.errorText; mapped = fo.mapped;
      if (!ccResponse.ok) {
        outcome.state = fo.creditExhausted
          ? 'credit_exhausted'
          : classifyUpstreamStatus(ccResponse.status);
        outcome.status = ccResponse.status;
        outcome.code = mapped.code || null;
        outcome.message = (mapped.body && mapped.body.error && mapped.body.error.message) || null;
        log('error', 'CC API error', { status: ccResponse.status, code: mapped.code, body: summarizeUpstreamError(errorText) });
        sendJSON(res, mapped.status, mapped.body);
        return;
      }
    }

    // 下游断连检测：打断 CC 上游 + 记录日志（只在首次尝试注册，重试不重复挂载监听器）
    if (attempt === 1) res.on('close', () => {
      if (res.writableEnded) return; // Normal completion, not a disconnect
      aborted = true;
      if (outcome.state === 'pending') outcome.state = 'aborted';
      const reason = lastCcEvent?.startsWith('tool-input') ? 'tool-input-silent-timeout'
        : lastCcEvent?.includes('delta') ? 'streaming-active-disconnect'
        : 'client-hangup';
      abortController.signal.aborted || log('warn', 'Client disconnected', {
        path: '/v1/chat/completions',
        model, completionId, reason,
        streaming: stream,
        elapsedMs: Date.now() - startTime,
        bytesSent: bytesReceived,
        lastCcEvent: lastCcEvent || '(none)',
        keepaliveCount,
        inputTokens: translator?.inputTokens ?? 0,
        outputTokens: translator?.outputTokens ?? 0,
        cachedInputTokens: translator?.cachedInputTokens ?? 0,
      });
      if (!abortController.signal.aborted) {
        // 断连前抢发 usage=0 终止 chunk，避免下游自行估算 token
        try {
          res.write(`data: ${JSON.stringify({
            id: completionId,
            object: 'chat.completion.chunk',
            created,
            model,
            choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
            usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0, prompt_tokens_details: { cached_tokens: 0 } },
          })}\n\n`);
          res.write('data: [DONE]\n\n');
        } catch {}
        try { abortController.abort(); } catch {}
      }
    });

    if (stream) {
      // ── 流式响应 ──
      translator = createSseTranslator(model, completionId, created);
      let buffer = '';
      let started = false; // 延迟写 200 header，超时/output=0 时返回 JSON 429/502 让 SDK 自动重试
      const decoder = new TextDecoder();
      reader = ccResponse.body.getReader();

      const idle = createIdleWatchdog(STREAM_IDLE_TIMEOUT_MS);
      try {
        while (true) {
          const result = await Promise.race([reader.read(), idle.arm()]);
          const { done, value } = result;
          if (done) break;
          if (aborted) break;
          bytesReceived += value.length;
          markTtft();

          const chunkText = decoder.decode(value, { stream: true });
          buffer += chunkText;
          // 仅在新到数据含换行时才切分：buffer 中永不残留 '\n'，故无换行即无完整行。
          // 避免对增长中的超长单行（大 tool-call / tool_result）反复做全量 split —— O(n²) → O(n)。
          let lines = [];
          if (chunkText.indexOf('\n') !== -1) {
            lines = buffer.split('\n');
            buffer = lines.pop() || '';
          }

          let hadOutput = false;
          for (const line of lines) {
            const events = translator.parseLine(line);
            if (events) {
              if (!started) {
                res.writeHead(200, {
                  'Content-Type': 'text/event-stream',
                  'Cache-Control': 'no-cache',
                  'Connection': 'keep-alive',
                  'X-Accel-Buffering': 'no',
                });
                started = true;
              }
              for (const evt of events) res.write(evt);
              await waitDrain(res);
              hadOutput = true;
            }
            if (translator.lastCcEvent) lastCcEvent = translator.lastCcEvent;
          }
          // silent events 期间发 keepalive，防止客户端超时断开
          if (started && !hadOutput) {
            try { res.write(': keepalive\n\n'); keepaliveCount++; } catch {}
            await waitDrain(res);
          }
        }

        if (!aborted) {
          // 成功完成一次请求，重置连续超时计数
          consecutiveTimeouts = 0;
          // 处理剩余 buffer
          if (buffer.trim()) {
            const events = translator.parseLine(buffer);
            if (events) {
              if (!started) started = true;
              for (const evt of events) res.write(evt);
              await waitDrain(res);
            }
          }
          if (translator.upstreamError) {
            outcome.state = 'fail';
            outcome.status = translator.upstreamError.status;
            if (!started) {
              sendJSON(res, translator.upstreamError.status, translator.upstreamError.body);
              return;
            }
            try { res.write(`data: ${JSON.stringify(translator.upstreamError.body)}\n\n`); } catch {}
          // 上游没有正常走完 finish（无 finish 事件 / provider 报连接失败）：
          // 不能补一个 finish_reason 就 [DONE] —— 那等于把截断谎报成完整回答。
          // 对齐 CLI：这一族一律按可重试的 502 处理。
          // 必须排在零输出判定之前 —— 上游压根没发 finish 时，「no finish event」才是根因，
          // 零输出只是它的表象（此时按 429 报会掩盖真实原因）。
          } else if (translator.incompleteDetail()) {
            const detail = translator.incompleteDetail();
            // 对端 FIN（干净收尾、没有 finish 事件）与 RST 是同一类闪断：既然还没向下游吐过
            // 字节，就先内部重试，而不是直接把 502 交给下游去自行重发整个上下文。
            if (!started && !aborted && attempt <= UPSTREAM_RETRY_MAX) {
              await rewindAttempt('Upstream stream ended incomplete before first byte - retrying', { reason: detail });
              continue attemptLoop;
            }
            log('warn', 'Upstream stream incomplete', { path: '/v1/chat/completions', reason: detail });
            const err = incompleteUpstreamError(detail);
            outcome.state = 'fail';
            outcome.status = err.status;
            try { if (!abortController.signal.aborted) abortController.abort(); } catch {}
            if (!started) { sendJSON(res, err.status, err.body); return; }
            try { res.write(`data: ${JSON.stringify(err.body)}\n\n`); } catch {}
          // 输出 token 为 0 时记为错误，避免下游异常计费
          } else if (translator.outputTokens === 0) {
            outcome.state = 'fail';
            outcome.status = 429;
            try { if (!abortController.signal.aborted) abortController.abort(); } catch {}
            if (!started) {
              sendJSON(res, 429, { error: { message: 'Empty response from upstream (zero output tokens)', type: 'rate_limit_error' }, retry_after: 10 });
              return;
            }
            try { res.write(`data: ${JSON.stringify({ error: { message: 'Empty response from upstream (zero output tokens)', type: 'rate_limit_error' }, retry_after: 10 })}\n\n`); } catch {}
          } else {
            if (!started) {
              res.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no',
              });
              started = true;
            }
            res.write(translator.getDoneEvent());
            delivered = true;
            outcome.state = 'ok';
          }
        }
      } catch (e) {
        if (aborted) {
          // 客户端已断连，只清理（close handler 已调用 abortController.abort()）
          // cancel() 返回 promise：不接住的话，连接已被对端掐断时会抛 UnhandledPromiseRejection
          try { reader.cancel().catch(() => {}); } catch {}
        } else if (e.message === 'STREAM_IDLE_TIMEOUT') {
          outcome.state = 'fail';
          outcome.status = 429;
          log('warn', 'Stream idle timeout', {
            path: '/v1/chat/completions',
            model,
            streaming: true,
            timeoutMs: STREAM_IDLE_TIMEOUT_MS,
            elapsedMs: Date.now() - startTime,
            id: completionId,
            bytesReceived,
            lastCcEvent: lastCcEvent || '(none)',
            inputTokens: translator.inputTokens,
            outputTokens: translator.outputTokens,
            cachedInputTokens: translator.cachedInputTokens,
          });
          try { reader.cancel().catch(() => {}); } catch {}
          try { abortController.abort(); } catch {} // 打断 CC 上游，避免浪费 token
          consecutiveTimeouts++;
          const timeoutMsg = consecutiveTimeouts >= TIMEOUT_REDUCE_CONTEXT_THRESHOLD
            ? 'Response timeout - try reducing context length (summarize earlier messages)'
            : 'Response timeout - request timed out';
          if (!started) {
            sendJSON(res, 429, { error: { message: timeoutMsg, type: 'rate_limit_error', input_tokens: 0 }, retry_after: 5 });
            return;
          }
          if (!res.writableEnded) {
            // 必须 end() 而不是 destroy()：res.write 是异步的，紧接着 destroy 会把尚未
            // 刷出的缓冲丢掉并发 RST。反向代理看到上游连接被重置，要么回 502，要么让
            // 客户端看到 connection error —— 这正是"吐字慢 + 间歇性 502"的成因之一。
            // end() 会把错误事件正常送进 SSE 流再发 FIN，客户端 SDK 能按可重试错误处理。
            // 下游若已僵死（不读也不断），由 CLIENT_DRAIN_TIMEOUT_MS 那条路径负责兜底。
            try { res.end(`data: ${JSON.stringify({ error: { message: timeoutMsg, type: 'rate_limit_error' }, retry_after: 5 })}\n\n`); } catch {}
          }
        // 已经解析出上游语义错误（429/503 等）时不重试：那是有意传下来的信号，重试会把它吞掉
        } else if (!started && !aborted && !translator?.upstreamError
                   && attempt <= UPSTREAM_RETRY_MAX && isRetryableUpstreamError(e)) {
          // 传输层闪断且尚未向下游写过任何字节 → 代理内部静默重试（下游全程无感）
          await rewindAttempt('Upstream stream terminated before first byte - retrying', {
            message: e.message,
            cause: e.cause?.code || e.cause?.message || '(none)',
          });
          continue attemptLoop;
        } else {
          // 传输层错误不要覆盖已经解析到的语义错误：把「上游容量不足」说成「代理挂了」是误导
          if (translator?.upstreamError && !started) {
            outcome.state = 'fail';
            outcome.status = translator.upstreamError.status;
            log('warn', 'Upstream terminated after a parsed semantic error', { message: e.message });
            try { abortController.abort(); } catch {}
            sendJSON(res, translator.upstreamError.status, translator.upstreamError.body);
            return;
          }
          log('error', 'Stream error', { message: e.message });
          try { abortController.abort(); } catch {} // 打断 CC 上游
          outcome.state = 'fail';
          outcome.status = 502;
          if (!started) {
            sendJSON(res, 502, { error: { message: `Upstream error: ${e.message}`, type: 'proxy_error', input_tokens: 0 }, retry_after: 10 });
            return;
          }
          if (!res.writableEnded) {
            try { res.write(`data: ${JSON.stringify({ error: { message: e.message, type: 'proxy_error' } })}\n\n`); } catch {}
          }
        }
      } finally {
        idle.dispose();
      }

      if (!res.writableEnded) res.end();
    } else {
      // ── 非流式响应（缓冲完整 NDJSON）──
      let reasoningContent = '';
      let finishReason = 'stop';
      let sawFinish = false;
      let usage = null;
      let toolCalls = null;

      reader = ccResponse.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';

      const processLines = () => {
        const lines = buf.split('\n');
        buf = lines.pop() || '';
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed === '[DONE]' || trimmed.startsWith(':')) continue;
          try {
            const event = JSON.parse(trimmed);
            switch (event.type) {
              case 'text-delta': lastCcEvent = event.type; fullText += event.text || ''; break;
              case 'reasoning-delta': lastCcEvent = event.type; reasoningContent += event.text || ''; break;
              case 'tool-call':
                lastCcEvent = event.type;
                toolCalls = toolCalls || [];
                toolCalls.push({
                  id: event.toolCallId || ('call_' + randomUUID().slice(0, 8)),
                  type: 'function',
                  function: {
                    name: event.toolName || '',
                    arguments: typeof event.input === 'string' ? event.input : JSON.stringify(event.input || {}),
                  },
                });
                break;
              case 'finish-step':
              case 'finish':
                lastCcEvent = event.type;
                sawFinish = true;
                finishReason = mapFinishReason(event.finishReason || 'stop');
                if (event.totalUsage) usage = event.totalUsage;
                break;
              case 'error':
                lastCcEvent = event.type;
                upstreamError = mapCcEventError(event);
                log('warn', 'CC stream error (non-stream)', {
                  message: event.error?.message || event.message,
                  upstreamStatus: upstreamError.reportedStatus,
                  upstreamRetryable: event.error?.isRetryable,
                  code: upstreamError.code,
                  mappedTo: upstreamError.status,
                });
                break;
              // 无内容的事件：与流式翻译器的静默列表保持一致。
              // text-start / start / start-step / reasoning-start 原先只在流式路径被识别，
              // 非流式路径会掉进 default 打成 'Unknown CC event type' —— 上游每个响应都会发，
              // 于是线上刷屏。它们本身不携带内容（内容在 text-delta），纯粹是噪音。
              case 'text-start': case 'text-end': case 'start': case 'start-step':
              case 'reasoning-start': case 'reasoning-end': case 'finish-step':
              case 'provider-metadata': case 'tool-input-start': case 'tool-input-delta': case 'tool-input-end':
              case 'tool-error':
                // Silent - no user-visible content
                break;
              default:
                log('warn', 'Unknown CC event type', { type: event.type });
                break;
            }
          } catch {}
        }
      };

      const idle = createIdleWatchdog(NONSTREAM_IDLE_TIMEOUT_MS);
      // 读循环抛错（闪断）时也必须释放看门狗：否则每次失败尝试都会留下一个 armed 的定时器，
      // 重试期间累积（流式路径的 finally 已覆盖同一件事）
      try {
        while (true) {
          const result = await Promise.race([reader.read(), idle.arm()]);
          const { done, value } = result;
          if (done) break;
          bytesReceived += value.length;
          markTtft();
          const chunkText = decoder.decode(value, { stream: true });
          buf += chunkText;
          // 无换行则不可能产生完整行，跳过全量 split（见 handleChatCompletions 流式段同处说明）
          if (chunkText.indexOf('\n') !== -1) processLines();
        }
      } finally {
        idle.dispose();
      }
      processLines();

      if (upstreamError) {
        outcome.state = 'fail';
        outcome.status = upstreamError.status;
        sendJSON(res, upstreamError.status, upstreamError.body);
        return;
      }

      // 上游没有正常走完 finish —— 对齐 CLI 按可重试 502 处理，不谎报成功
      const incomplete = incompleteUpstreamDetail(sawFinish, finishReason);
      if (incomplete) {
        // 尚未向下游写过任何字节（非流式此时 headers 还没发）→ 与传输层闪断同等对待，先重试
        if (!aborted && !upstreamError && attempt <= UPSTREAM_RETRY_MAX) {
          await rewindAttempt('Upstream stream ended incomplete before first byte - retrying', { reason: incomplete });
          continue attemptLoop;
        }
        log('warn', 'Upstream stream incomplete', { path: '/v1/chat/completions', reason: incomplete });
        const err = incompleteUpstreamError(incomplete);
        outcome.state = 'fail';
        outcome.status = err.status;
        try { if (!abortController.signal.aborted) abortController.abort(); } catch {}
        sendJSON(res, err.status, err.body);
        return;
      }

      // 输出 token 为 0 时记为错误，避免下游异常计费
      if ((usage?.outputTokens ?? 0) === 0) {
        outcome.state = 'fail';
        outcome.status = 429;
        try { if (!abortController.signal.aborted) abortController.abort(); } catch {}
        sendJSON(res, 429, { error: { message: 'Empty response from upstream (zero output tokens)', type: 'rate_limit_error' }, retry_after: 10 });
        return;
      }

      consecutiveTimeouts = 0;
      sendJSON(res, 200, {
        id: completionId,
        object: 'chat.completion',
        created,
        model,
        choices: [{
          index: 0,
          message: Object.assign(
            { role: 'assistant', content: fullText || null },
            toolCalls ? { tool_calls: toolCalls } : {},
            reasoningContent ? { reasoning_content: reasoningContent } : {},
          ),
          finish_reason: toOpenAIFinishReason(finishReason),
        }],
    usage: (() => {
      if (!usage) usage = {};
      normalizeUsage(usage);
      return {
        prompt_tokens: usage.inputTokens ?? 0,
        completion_tokens: usage.outputTokens ?? 0,
        total_tokens: (usage.inputTokens ?? 0) + (usage.outputTokens ?? 0),
        prompt_tokens_details: { cached_tokens: usage.cachedInputTokens ?? 0 },
      };
    })(),
      });
      delivered = true;
      outcome.state = 'ok';
    }
    // 只有本次尝试真的交付了正常响应才算「重试救回来了」；
    // 已向下游报错的尝试（502/429）不能记成 recovered
    if (attempt > 1 && delivered) {
      upstreamRetryStats.recovered++;
      log('info', 'Upstream retry recovered', {
        path: '/v1/chat/completions', model, attempt, elapsedMs: Date.now() - startTime,
      });
    }
    break attemptLoop;   // 本次尝试已完整处理（成功或已按语义返回错误）
  } catch (e) {
    if (abortController.signal.aborted) {
      if (outcome.state === 'pending') outcome.state = 'aborted';
      log('warn', 'Request cancelled (client disconnected before CC response)', {
        path: '/v1/chat/completions',
        model,
        completionId,
      });
      return; // 下游已断连：不再重试（res 已关闭）
    } else if (e.message === 'STREAM_IDLE_TIMEOUT') {
      outcome.state = 'fail';
      outcome.status = 429;
      log('warn', 'Stream idle timeout', {
        path: '/v1/chat/completions',
        model,
        streaming: false,
        timeoutMs: NONSTREAM_IDLE_TIMEOUT_MS,
        elapsedMs: Date.now() - startTime,
        id: completionId,
        bytesReceived,
        lastCcEvent: lastCcEvent || '(none)',
        partialLen: fullText ? fullText.length : 0,
      });
      try { reader?.cancel().catch(() => {}); } catch {}
      try { abortController.abort(); } catch {} // 打断 CC 上游
      consecutiveTimeouts++;
      const timeoutMsg = consecutiveTimeouts >= TIMEOUT_REDUCE_CONTEXT_THRESHOLD
        ? 'Response timeout - try reducing context length (summarize earlier messages)'
        : 'Response timeout - request timed out';
      res.setHeader('Retry-After', '5');
      sendJSON(res, 429, { error: { message: timeoutMsg, type: 'rate_limit_error', input_tokens: 0 }, retry_after: 5 });
      return; // 超时已按语义回给下游（由下游决定是否重试），本代理不重试
    // 已解析出上游语义错误（429/503 等）时不重试：那是有意传下来的信号，重试会把它吞掉
    } else if (!res.headersSent && !aborted && !upstreamError && !translator?.upstreamError
               && attempt <= UPSTREAM_RETRY_MAX && isRetryableUpstreamError(e)) {
      // 传输层闪断且尚未向下游写出任何字节 → 代理内部静默重试（下游全程无感）
      await rewindAttempt('Upstream error before first byte - retrying', {
        message: e.message,
        cause: e.cause?.code || e.cause?.message || '(none)',
      });
      continue attemptLoop;
    } else {
      // 传输层错误不要覆盖已经解析到的语义错误：把「上游容量不足」说成「代理挂了」是误导
      const semantic = upstreamError || translator?.upstreamError;
      if (semantic && !res.headersSent) {
        outcome.state = 'fail';
        outcome.status = semantic.status;
        log('warn', 'Upstream terminated after a parsed semantic error', { message: e.message });
        try { abortController.abort(); } catch {}
        sendJSON(res, semantic.status, semantic.body);
        return;
      }
      log('error', 'Upstream error', { message: e.message });
      try { abortController.abort(); } catch {} // 打断 CC 上游
      outcome.state = 'fail';
      outcome.status = 502;
      sendJSON(res, 502, { error: { message: `Upstream error: ${e.message}`, type: 'proxy_error', input_tokens: 0 }, retry_after: 10 });
      return;
    }
  }
  }   // ← end of attemptLoop
  } finally {
    route.release(outcome, Date.now() - startTime);
  }
}

// ── Anthropic /v1/messages 协议转换 ─────────────────

function mapAnthropicStopReason(finishReason) {
  switch (finishReason) {
    case 'tool_calls': return 'tool_use';
    case 'length': return 'max_tokens';
    case 'stop': return 'end_turn';
    // Anthropic 的原生枚举，必须原样透出：它表示「这一轮被暂停，后面还有内容」。
    // 折成 end_turn 会让下游把半截回答当成写完了（CLI 是靠自动续写把它吸收掉的，
    // 代理不自动续写，就必须如实上报，不能吞掉）。
    case 'pause_turn': return 'pause_turn';
    case 'refusal': return 'refusal';
    default: return 'end_turn';
  }
}

// OpenAI 的 finish_reason 只有 stop | length | tool_calls | content_filter | function_call。
// pause_turn 没有对应值：折成 'stop' 是谎报完成（正是要修的问题），
// 折成 'length' 至少如实表达了「输出不完整」，下游的截断处理会做对的事。
function toOpenAIFinishReason(finishReason) {
  return finishReason === 'pause_turn' ? 'length' : finishReason;
}

// Generate a Claude-format fake signature for thinking blocks.
// Anthropic validates thinking signatures cryptographically; third-party
// proxies cannot mint valid ones. Claude Code's shallow check only requires
// base64 starting with 'E' (single-layer) / 'R' (double-layer) with payload
// first byte 0x12 — this satisfies that, letting CC display thinking.
// The payload is derived from the thinking text so each block's signature
// differs (closer to spec, avoids identical-signature quirks).
function fakeThinkingSignature(thinkingText) {
  const seed = crypto.createHash('sha256').update(thinkingText || 'dsh-proxy-thinking').digest().subarray(0, 64);
  const raw = Buffer.concat([Buffer.from([0x12, seed.length]), seed]);
  return raw.toString('base64');
}

function buildAnthropicResponse(model, fullText, toolCalls, finishReason, usage, thinkingText) {
  const content = [];
  if (thinkingText) content.push({ type: 'thinking', thinking: thinkingText, signature: fakeThinkingSignature(thinkingText) });
  if (fullText) content.push({ type: 'text', text: fullText });
  if (toolCalls) {
    for (const tc of toolCalls) {
      let input = {};
      try { input = JSON.parse(tc.function.arguments); } catch { input = {}; }
      content.push({ type: 'tool_use', id: tc.id, name: tc.function.name, input });
    }
  }
  return {
    id: `msg_${randomUUID().slice(0, 12)}`,
    type: 'message',
    role: 'assistant',
    model,
    content,
    stop_reason: mapAnthropicStopReason(finishReason || 'stop'),
    stop_sequence: null,
    usage: (() => {
      normalizeUsage(usage || {});
      // CC 未回报 usage 时按内容长度估算输出 token，避免客户端展示/记账为 0
      const estOut = Math.max(1,
        Math.ceil(((fullText || '').length + (thinkingText || '').length) / 4) + (toolCalls ? toolCalls.length * 20 : 0));
      return {
        // input_tokens 只计非缓存部分（Anthropic 语义），与 cache_* 相加才等于总输入
        input_tokens: anthropicInputTokens(usage),
        output_tokens: usage?.outputTokens || estOut,
        cache_creation_input_tokens: usage?.inputTokenDetails?.cacheWriteTokens ?? 0,
        cache_read_input_tokens: usage?.cachedInputTokens ?? 0,
      };
    })(),
  };
}

function convertAnthropicToOpenAI(anthropicReq) {
  // 1. Extract system prompt (top-level, not in messages array)
  let systemPrompt = '';
  let systemBlocks = null;
  if (anthropicReq.system) {
    if (typeof anthropicReq.system === 'string') {
      systemPrompt = anthropicReq.system;
    } else if (Array.isArray(anthropicReq.system)) {
      // 保留 cache_control：buildCcRequest 需要块数组才能把断点下发（CLI 的 params.system 就是块数组）
      systemBlocks = anthropicReq.system
        .filter(b => b && b.type === 'text')
        .map(b => {
          const blk = { type: 'text', text: b.text ?? '' };
          if (b.cache_control) blk.cache_control = b.cache_control;
          return blk;
        });
      systemPrompt = systemBlocks.map(b => b.text).join('\n');
    }
  }

  // 2. Build tool name map + convert messages
  const toolNameFromId = {};
  const openaiMessages = [];

  if (systemPrompt) {
    openaiMessages.push({ role: 'system', content: systemBlocks && systemBlocks.length ? systemBlocks : systemPrompt });
  }

  const messages = anthropicReq.messages || [];
  for (const msg of messages) {
    if (msg.role === 'assistant') {
      let textContent = '';
      // Anthropic 的 thinking block 承载思考内容，需转成 reasoning_content
      // 交给 buildCcRequest 回传，否则 CC 会因缺少 reasoning 而拒绝
      let thinkingContent = '';
      const textParts = [];
      let textHasCache = false;
      const toolCalls = [];
      const blocks = Array.isArray(msg.content) ? msg.content : [{ type: 'text', text: msg.content || '' }];
      for (const block of blocks) {
        if (block.type === 'text') {
          textContent += block.text || '';
          const part = { type: 'text', text: block.text || '' };
          if (block.cache_control) { part.cache_control = block.cache_control; textHasCache = true; }
          textParts.push(part);
        } else if (block.type === 'thinking') {
          thinkingContent += block.thinking || '';
        } else if (block.type === 'tool_use') {
          toolNameFromId[block.id] = block.name;
          toolCalls.push({
            id: block.id,
            type: 'function',
            function: {
              name: block.name,
              arguments: JSON.stringify(block.input || {}),
            },
          });
        }
      }
      const assistantMsg = { role: 'assistant', content: (textParts.length > 1 || textHasCache) ? textParts : (textContent || null) };
      if (thinkingContent) assistantMsg.reasoning_content = thinkingContent;
      if (toolCalls.length > 0) assistantMsg.tool_calls = toolCalls;
      openaiMessages.push(assistantMsg);
    } else if (msg.role === 'user') {
      let textContent = '';
      // parts 保持原始顺序（text / image_url），与 CLI 的 toWireMessages 一致
      const parts = [];
      let textHasCache = false;
      const toolResults = [];
      if (typeof msg.content === 'string') {
        textContent = msg.content;
      } else if (Array.isArray(msg.content)) {
        for (const block of msg.content) {
          if (block.type === 'text') {
            textContent += block.text || '';
            const part = { type: 'text', text: block.text || '' };
            if (block.cache_control) { part.cache_control = block.cache_control; textHasCache = true; }
            parts.push(part);
          } else if (block.type === 'image') {
            // Anthropic 图片块：{ type:'image', source:{ type:'base64', media_type, data } } 或 source.url
            const s = block.source || {};
            const url = s.type === 'base64' && s.data
              ? `data:${s.media_type || 'image/png'};base64,${s.data}`
              : (s.url || '');
            if (url) parts.push({ type: 'image_url', image_url: { url } });
          } else if (block.type === 'tool_result') {
            toolResults.push(block);
          }
        }
      }
      if (textContent) {
        // 暂存，tool_result 优先入队：OpenAI 语义要求 tool 消息紧跟 assistant 的
        // tool_calls，同一条 user 消息里的文本要排在 tool 结果之后
      }
      for (const tr of toolResults) {
        const toolContent = typeof tr.content === 'string' ? tr.content
          : Array.isArray(tr.content) ? tr.content.map(c => c.text || '').join('\n')
          : String(tr.content || '');
        // OpenAI 语义里 tool 消息的 name 是可选的；会话恢复等场景下 tool_use_id 可能
        // 找不到对应 assistant tool_use（历史被客户端裁剪），此时不硬塞空 name，
        // 避免 CC 上游报 "Tool result is missing"（issue #15）
        const toolMsg = { role: 'tool', tool_call_id: tr.tool_use_id, content: toolContent };
        if (toolNameFromId[tr.tool_use_id]) toolMsg.name = toolNameFromId[tr.tool_use_id];
        openaiMessages.push(toolMsg);
      }
      if (parts.length || textContent) {
        // 单块纯文本仍用字符串（线格不变）；多块 / 带断点 / 含图片时用块数组（CLI 的形态）。
        // 注意：content 为字符串时 parts 为空，必须用 textContent 判空（否则整条消息会丢）
        const singleText = parts.length <= 1 && (parts.length === 0 || parts[0].type === 'text') && !textHasCache;
        openaiMessages.push({ role: 'user', content: singleText ? textContent : parts });
      }
    }
  }

  // 3. Build OpenAI request
  const openaiReq = {
    model: anthropicReq.model || 'deepseek/deepseek-v4-flash',
    messages: openaiMessages,
    max_tokens: anthropicReq.max_tokens || 64000,
    stream: anthropicReq.stream === true,
  };

  // 4. Map tools
  if (anthropicReq.tools && anthropicReq.tools.length > 0) {
    openaiReq.tools = anthropicReq.tools.map(t => ({
      type: 'function',
      function: {
        name: t.name,
        description: t.description || '',
        parameters: t.input_schema || { type: 'object', properties: {} },
      },
    }));
  }

  // 5. Map tool_choice
  if (anthropicReq.tool_choice) {
    const tc = anthropicReq.tool_choice;
    if (tc.type === 'auto' || tc.type === undefined) {
      openaiReq.tool_choice = 'auto';
    } else if (tc.type === 'any') {
      openaiReq.tool_choice = 'required';
    } else if (tc.type === 'tool') {
      openaiReq.tool_choice = { type: 'function', function: { name: tc.name } };
    } else if (tc.type === 'none') {
      openaiReq.tool_choice = 'none';
    }
  }

  // 6. Optional params
  if (anthropicReq.temperature !== undefined) openaiReq.temperature = anthropicReq.temperature;
  if (anthropicReq.top_p !== undefined) openaiReq.top_p = anthropicReq.top_p;
  if (anthropicReq.stop_sequences) openaiReq.stop = anthropicReq.stop_sequences;
  if (anthropicReq.metadata?.user_id) openaiReq.user = anthropicReq.metadata.user_id;

  // 7. Anthropic thinking → reasoning_effort（LiteLLM 标准映射）
  if (anthropicReq.thinking) {
    const t = anthropicReq.thinking;
    if (t.type === 'disabled' || t.type === 'none') {
      // 不发送 reasoning_effort
    } else if (t.type === 'adaptive') {
      openaiReq.reasoning_effort = t.effort ?? 'medium';
    } else if (t.budget_tokens !== undefined) {
      if (t.budget_tokens >= 10000) openaiReq.reasoning_effort = 'high';
      else if (t.budget_tokens >= 5000) openaiReq.reasoning_effort = 'medium';
      else if (t.budget_tokens >= 2000) openaiReq.reasoning_effort = 'low';
      else openaiReq.reasoning_effort = 'low'; // <2000 → low
    }
  }

  return openaiReq;
}

/**
 * Async generator that reads CC NDJSON response body and yields
 * Anthropic SSE events for streaming.
 */
async function* createAnthropicSseTranslator(response, model, messageId, ctx) {
  let nextBlockIndex = 0;
  let currentBlockIndex = -1;
  let currentBlockType = null;
  let blockStarted = false;
  let inputTokens = 0;
  let outputTokens = 0;
  let cachedInputTokens = 0;
  let cacheWriteTokens = 0;
  let noCacheTokens = -1;   // -1 = 上游未提供该字段，改用减法兜底
  let stopReason = null;
  // 归一化后的 finishReason（mapAnthropicStopReason 之前的值），用于判定「是否正常结束」
  let finishNorm = null;
  // 是否见过终态 finish 事件。CLI 用同一个标志判定流是否被截断 —— 它只认 'finish'，
  // 'finish-step' 不在 CLI 的事件集里，故这里同样只认 'finish'。
  let sawFinish = false;
  let hasError = false;
  let currentThinkingText = ''; // accumulated thinking text for the open block

  // Close the current block (text or thinking) if one is active.
  // For thinking blocks, emit a signature_delta (Anthropic standard) before stop.
  function closeBlock() {
    if (blockStarted) {
      const idx = currentBlockIndex;
      const type = currentBlockType;
      let out = '';
      if (type === 'thinking') {
        out += `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: idx, delta: { type: 'signature_delta', signature: fakeThinkingSignature(currentThinkingText) } })}\n\n`;
        currentThinkingText = '';
      }
      blockStarted = false;
      currentBlockType = null;
      return out + `event: content_block_stop\ndata: ${JSON.stringify({ type: 'content_block_stop', index: idx })}\n\n`;
    }
    return '';
  }
  const closeTextBlock = closeBlock;

  // Open a new block of the given type (closing any previous block first)
  function startBlock(type, contentBlock) {
    if (!blockStarted || currentBlockType !== type) {
      const close = closeBlock();
      currentBlockIndex = nextBlockIndex++;
      currentBlockType = type;
      blockStarted = true;
      return close + `event: content_block_start\ndata: ${JSON.stringify({ type: 'content_block_start', index: currentBlockIndex, content_block: contentBlock })}\n\n`;
    }
    return '';
  }

  // Open a new text block (closing any previous block first)
  function startTextBlock() {
    return startBlock('text', { type: 'text', text: '' });
  }

  // Open a new thinking block (closing any previous block first)
  function startThinkingBlock() {
    return startBlock('thinking', { type: 'thinking', thinking: '' });
  }

  // Emit message_start (always the first event)
  yield `event: message_start\ndata: ${JSON.stringify({
    type: 'message_start',
    message: {
      id: messageId,
      type: 'message',
      role: 'assistant',
      content: [],
      model,
      usage: { input_tokens: 0, output_tokens: 0 },
    }
  })}\n\n`;

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  const idle = createIdleWatchdog(STREAM_IDLE_TIMEOUT_MS);

  try {
    while (true) {
      const result = await Promise.race([reader.read(), idle.arm()]);
      const { done, value } = result;
      if (done) break;
      ctx.bytesReceived += value.length;
      const chunkText = decoder.decode(value, { stream: true });
      buffer += chunkText;
      // 同 handleChatCompletions：无换行即无完整行，跳过全量 split
      let lines = [];
      if (chunkText.indexOf('\n') !== -1) {
        lines = buffer.split('\n');
        buffer = lines.pop() || '';
      }

      let hadOutput = false;
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed === '[DONE]') continue;
        let event;
        try { event = JSON.parse(trimmed); } catch { continue; }
        if (!event.type) continue;
        ctx.lastCcEvent = event.type;

        switch (event.type) {
          case 'start': case 'start-step': case 'text-start': case 'reasoning-start':
            // Signal events, no user-visible data
            break;

          case 'reasoning-delta': {
            // CC reasoning → Anthropic thinking block (Claude Code shows this as thinking)
            const text = event.text || '';
            if (!text) break;
            const startBlock = startThinkingBlock();
            currentThinkingText += text;
            yield startBlock + `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: currentBlockIndex, delta: { type: 'thinking_delta', thinking: text } })}\n\n`;
            hadOutput = true;
            break;
          }

          case 'text-delta': {
            const text = event.text || '';
            const startBlock = startTextBlock();
            yield startBlock + `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: currentBlockIndex, delta: { type: 'text_delta', text } })}\n\n`;
            outputTokens += 1;
            hadOutput = true;
            break;
          }

          case 'tool-call': {
            // Close any pending text block
            const closeBlock = closeTextBlock();
            if (closeBlock) yield closeBlock;

            const id = event.toolCallId || `toolu_${randomUUID().slice(0, 12)}`;
            const name = event.toolName || '';
            const input = typeof event.input === 'string' ? event.input : JSON.stringify(event.input || {});

            const tcIndex = nextBlockIndex++;
            yield `event: content_block_start\ndata: ${JSON.stringify({ type: 'content_block_start', index: tcIndex, content_block: { type: 'tool_use', id, name, input: {} } })}\n\n`;
            yield `event: content_block_delta\ndata: ${JSON.stringify({ type: 'content_block_delta', index: tcIndex, delta: { type: 'input_json_delta', partial_json: input } })}\n\n`;
            yield `event: content_block_stop\ndata: ${JSON.stringify({ type: 'content_block_stop', index: tcIndex })}\n\n`;
            outputTokens += 20;
            break;
          }

          case 'finish-step':
          case 'finish': {
            // 上游的 finishReason 是 'tool-calls'（连字符），必须先过 mapFinishReason 规范化成
            // 'tool_calls'，否则会掉进 mapAnthropicStopReason 的 default 变成 end_turn。
            // 真机实测踩到过：工具调用成功但 stop_reason 报 end_turn。
            sawFinish = true;   // finish-step 与 finish 都算完成信号
            if (event.finishReason) {
              finishNorm = mapFinishReason(event.finishReason);
              stopReason = mapAnthropicStopReason(finishNorm);
            }
            const u = event.totalUsage || event.usage;
            if (u) {
              normalizeUsage(u);
              inputTokens = u.inputTokens ?? inputTokens;
              outputTokens = u.outputTokens ?? outputTokens;
              cachedInputTokens = u.cachedInputTokens ?? cachedInputTokens;
              cacheWriteTokens = u.inputTokenDetails?.cacheWriteTokens ?? cacheWriteTokens;
              if (typeof u.inputTokenDetails?.noCacheTokens === 'number') {
                noCacheTokens = u.inputTokenDetails.noCacheTokens;
              }
              ctx.inputTokens = inputTokens;
              ctx.outputTokens = outputTokens;
              ctx.cachedInputTokens = cachedInputTokens;
            }
            // 上游未回报 usage 时保留本地按 delta 计数的估算值——清零会把有内容的
            // 响应误判成零输出（触发 429）。未知字段保持原值即可。
            break;
          }

          case 'error': {
            hasError = true;
            const upstreamError = mapCcEventError(event);
            ctx.upstreamError = upstreamError;
            yield `event: error\ndata: ${JSON.stringify({ type: 'error', error: upstreamError.body.error })}\n\n`;
            break;
          }

          case 'reasoning-end': case 'provider-metadata': case 'tool-input-start': case 'tool-input-delta': case 'tool-input-end': case 'tool-error': case 'text-end':
            // Silent - no user-visible content
            break;
          default:
            log('warn', 'Unknown CC event type', { type: event.type });
            break;
        }
      }
    }

    // 无论上游是否回报 usage，都把本地计数同步进 ctx（零输出判定与超时日志依赖它）。
    // 注意：ctx.inputTokens 保存的是上游原始总数，仅供日志排查；
    // message_delta 的 input_tokens 走 anthropicInputTokens / noCacheTokens 换算，不读它。
    ctx.inputTokens = inputTokens;
    ctx.outputTokens = outputTokens;
    ctx.cachedInputTokens = cachedInputTokens;
    ctx.cacheWriteTokens = cacheWriteTokens;

    // Finalize — close pending text block, emit message_delta + message_stop
    if (!hasError) {
      const closeBlock = closeTextBlock();
      if (closeBlock) yield closeBlock;

      // 上游没有正常走完 finish（无 finish 事件 / provider 报连接失败）：
      // 绝不能补一个 end_turn 就 message_stop —— 那等于把截断谎报成完整回答。
      // 对齐 CLI：这一族一律按可重试错误处理。
      const incomplete = incompleteUpstreamDetail(sawFinish, finishNorm);
      if (incomplete) {
        log('warn', 'Upstream stream incomplete', { path: '/v1/messages', reason: incomplete });
        yield `event: error\ndata: ${JSON.stringify({ type: 'error', error: incompleteUpstreamError(incomplete).body.error })}\n\n`;
      // 输出 token 为 0 时记为错误，避免下游异常计费
      } else if (outputTokens === 0) {
        yield `event: error\ndata: ${JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: 'Empty response from upstream (zero output tokens)' }, retry_after: 10 })}\n\n`;
      } else {
        yield `event: message_delta\ndata: ${JSON.stringify({
          type: 'message_delta',
          delta: { stop_reason: stopReason || 'end_turn' },
          usage: {
            output_tokens: outputTokens,
            cache_read_input_tokens: cachedInputTokens,
            cache_creation_input_tokens: cacheWriteTokens || 0,
            // 只计非缓存部分；否则下游把 input 与 cache_read 相加会得到约两倍（issue #25）
            input_tokens: noCacheTokens >= 0
              ? noCacheTokens
              : Math.max(0, inputTokens - cachedInputTokens - (cacheWriteTokens || 0)),
          },
        })}\n\n`;

        yield `event: message_stop\ndata: ${JSON.stringify({ type: 'message_stop' })}\n\n`;
      }
    }
  } finally {
    // 确保流中断时通知上游
    idle.dispose();
    try { reader.cancel().catch(() => {}); } catch {}
  }
}

function sendAnthropicError(res, status, type, message, retryAfter) {
  const body = { type: 'error', error: { type, message } };
  const headers = { 'Content-Type': 'application/json' };
  if (retryAfter !== undefined) {
    body.retry_after = retryAfter;
    headers['Retry-After'] = String(retryAfter);
  }
  res.writeHead(status, headers);
  res.end(JSON.stringify(body));
}

async function handleMessages(req, res) {
  let anthropicReq;
  try {
    anthropicReq = await readBody(req);
  } catch (e) {
    if (e.statusCode === 413) {
      sendAnthropicError(res, 413, 'invalid_request_error', e.message);
      return;
    }
    sendAnthropicError(res, 400, 'invalid_request_error', 'Invalid JSON body');
    return;
  }

  let route = resolveRoute(req.headers);
  if (route && route.error === 'no_available_account') {
    res.setHeader('Retry-After', '5');
    sendJSON(res, 503, { type: 'error', error: { type: 'no_available_account', message: 'No available upstream account for this token' }, retry_after: 5 });
    return;
  }
  if (!route) {
    sendJSON(res, 401, { type: 'error', error: { type: 'authentication_error', message: 'Missing API key. Send in Authorization: Bearer <key> or x-api-key header' } });
    return;
  }
  let apiKey = route.upstreamKey;
  const outcome = { state: 'pending', ttftMs: null, status: null, code: null, message: null };

  const stream = anthropicReq.stream === true;
  const model = anthropicReq.model || 'claude-sonnet-4-6';

  // Convert Anthropic → OpenAI → CC
  const openaiReq = convertAnthropicToOpenAI(anthropicReq);
  const ccBody = buildCcRequest(openaiReq);

  const abortController = new AbortController();
  let aborted = false;
  // 提前初始化，断连回调/超时 catch 安全引用（避免块级作用域 ReferenceError）
  const startTime = Date.now();
  const markTtft = () => { if (outcome.ttftMs == null) outcome.ttftMs = Date.now() - startTime; };
  let messageId = '';
  let reader = null;
  let bytesReceived = 0; let lastCcEvent = ''; let fullText = '';

  try {
    // 首次初始化（fingerprint + lifecycle）
    await ensureInitialized(apiKey, abortController.signal);
    let ccResponse = await forwardToCC(ccBody, apiKey, req.headers, abortController.signal);

    if (!ccResponse.ok) {
      let errorText = await ccResponse.text().catch(() => '');
      let mapped = mapCcError(ccResponse.status, errorText);
      const fo = await creditFailover({
        route, apiKey, ccResponse, errorText, mapped, outcome, req,
        forward: async (key) => {
          await ensureInitialized(key, abortController.signal);
          return forwardToCC(ccBody, key, req.headers, abortController.signal);
        },
      });
      route = fo.route; apiKey = fo.apiKey; ccResponse = fo.ccResponse;
      errorText = fo.errorText; mapped = fo.mapped;
      if (!ccResponse.ok) {
        outcome.state = fo.creditExhausted
          ? 'credit_exhausted'
          : classifyUpstreamStatus(ccResponse.status);
        outcome.status = ccResponse.status;
        outcome.code = mapped.code || null;
        outcome.message = (mapped.body && mapped.body.error && mapped.body.error.message) || null;
        log('error', 'CC API error (Anthropic)', { status: ccResponse.status, code: mapped.code, body: summarizeUpstreamError(errorText) });
        sendAnthropicError(res, mapped.status, mapped.body.error.type, mapped.body.error.message);
        return;
      }
    }

    // 下游断连检测：打断 CC 上游 + 记录日志
    res.on('close', () => {
      if (res.writableEnded) return; // Normal completion, not a disconnect
      aborted = true;
      if (outcome.state === 'pending') outcome.state = 'aborted';
      if (!abortController.signal.aborted) {
        // 断连前抢发 usage=0 终止事件，避免下游自行估算 token
        try {
          res.write(`event: message_delta\ndata: ${JSON.stringify({
            type: 'message_delta',
            delta: { stop_reason: 'end_turn' },
            usage: { output_tokens: 0, input_tokens: 0, cache_read_input_tokens: 0 },
          })}\n\n`);
          res.write(`event: message_stop\ndata: ${JSON.stringify({ type: 'message_stop' })}\n\n`);
        } catch {}
        try { abortController.abort(); } catch {}
      }
      log('warn', 'Client disconnected', {
        path: '/v1/messages',
        model,
        messageId,
        streaming: stream,
        elapsedMs: Date.now() - startTime,
      });
    });

    if (stream) {
      // ── 流式 Anthropic SSE ──
      // 行为与 /v1/chat/completions 对齐：首个上游事件（thinking/text/tool_use）到达即
      // 发 header——之前扣到 text_delta 才发，推理模型 thinking 阶段客户端收不到任何
      // 字节，触发下游 60s 首字节超时（context canceled）。message_start 仍缓冲：
      // 完全无输出时还能回 JSON 429/502 让 SDK 自动重试（同 chat 端点）。
      let started = false;
      const buf = [];
      const SSE_HEADERS = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
      };
      const flushBuf = async () => {
        if (!started) {
          res.writeHead(200, SSE_HEADERS);
          started = true;
        }
        for (const ev of buf) { try { res.write(ev); } catch {} }
        buf.length = 0;
        await waitDrain(res);
      };

      // 心跳：等价于 chat 端点的 ': keepalive'——chat 在每轮读到静默事件时发注释行，
      // Anthropic 翻译器会吞掉 signal 事件，这里改用空闲计时发 ping（Anthropic 标准
      // 事件，官方 SDK 会忽略），覆盖上游排队/长 thinking 的静默窗口
      let lastSentAt = Date.now();
      const heartbeat = setInterval(() => {
        // 不向已积压的下游继续塞数据：定时器回调是同步的，无法 await waitDrain，
        // 因此用 writableNeedDrain 直接跳过本轮心跳（背压场景下少发一个 ping 无副作用）
        if (started && !aborted && !res.writableEnded && !res.writableNeedDrain && Date.now() - lastSentAt > 15000) {
          try { res.write('event: ping\ndata: {"type":"ping"}\n\n'); lastSentAt = Date.now(); } catch {}
        }
      }, 5000);

      let ctx;
      try {
        messageId = 'msg_' + randomUUID().slice(0, 12);
        ctx = { bytesReceived: 0, lastCcEvent: '', inputTokens: 0, outputTokens: 0, cachedInputTokens: 0, upstreamError: null };
        const generator = createAnthropicSseTranslator(ccResponse, model, messageId, ctx);
        for await (const event of generator) {
          if (aborted) break;
          markTtft();
          if (!started && !event.startsWith('event: message_start')) {
            await flushBuf();
          }
          if (started) {
            try { res.write(event); } catch {}
            lastSentAt = Date.now();
            await waitDrain(res);
          } else {
            buf.push(event);
          }
        }

        if (!aborted) {
          consecutiveTimeouts = 0;
          if (ctx.upstreamError) {
            outcome.state = 'fail';
            outcome.status = ctx.upstreamError.status;
            if (!started) {
              sendAnthropicError(
                res,
                ctx.upstreamError.status,
                ctx.upstreamError.body.error.type,
                ctx.upstreamError.body.error.message,
              );
            }
            // started 时 error 事件已在循环中经 SSE 下发，按规范 error 事件即终结
          } else if (ctx.outputTokens === 0) {
            outcome.state = 'fail';
            outcome.status = 429;
            try { abortController.abort(); } catch {}
            if (!started) {
              sendAnthropicError(res, 429, 'rate_limit_error', 'Empty response from upstream (zero output tokens)', 10);
              return;
            }
            await flushBuf();
          } else {
            outcome.state = 'ok';
            await flushBuf();
          }
        }
      } catch (e) {
        if (aborted) {
          // 客户端已断连，只清理（close handler 已调用 abortController.abort()）
        } else if (e.message === 'STREAM_IDLE_TIMEOUT') {
          outcome.state = 'fail';
          outcome.status = 429;
          log('warn', 'Stream idle timeout', {
            path: '/v1/messages',
            model,
            streaming: true,
            timeoutMs: STREAM_IDLE_TIMEOUT_MS,
            elapsedMs: Date.now() - startTime,
            id: messageId,
            bytesReceived: ctx.bytesReceived,
            lastCcEvent: ctx.lastCcEvent || '(none)',
            inputTokens: ctx.inputTokens,
            outputTokens: ctx.outputTokens,
            cachedInputTokens: ctx.cachedInputTokens,
          });
          try { abortController.abort(); } catch {} // 打断 CC 上游
          if (!started) {
            consecutiveTimeouts++;
            const timeoutMsg = consecutiveTimeouts >= TIMEOUT_REDUCE_CONTEXT_THRESHOLD
              ? 'Response timeout - try reducing context length (summarize earlier messages)'
              : 'Response timeout - request timed out';
            sendAnthropicError(res, 429, 'rate_limit_error', timeoutMsg);
            return;
          }
          if (!res.writableEnded) {
            consecutiveTimeouts++;
            const timeoutMsg = consecutiveTimeouts >= TIMEOUT_REDUCE_CONTEXT_THRESHOLD
              ? 'Response timeout - try reducing context length (summarize earlier messages)'
              : 'Response timeout - request timed out';
            // end() 而不是 destroy()：理由见 handleChatCompletions 流式超时分支
            try { res.end(`event: error\ndata: ${JSON.stringify({ type: 'error', error: { type: 'rate_limit_error', message: timeoutMsg }, retry_after: 5 })}\n\n`); } catch {}
          }
        } else {
          outcome.state = 'fail';
          outcome.status = 502;
          log('error', 'Anthropic stream error', { message: e.message });
          try { abortController.abort(); } catch {} // 打断 CC 上游
          if (!started) {
            sendAnthropicError(res, 502, 'proxy_error', `Upstream error: ${e.message}`, 10);
            return;
          }
          if (!res.writableEnded) {
            try {
              res.write(`event: error\ndata: ${JSON.stringify({ type: 'error', error: { type: 'internal_error', message: e.message } })}\n\n`);
            } catch {}
          }
        }
      } finally {
        clearInterval(heartbeat);
      }

      if (!res.writableEnded) res.end();
    } else {
      // ── 非流式 Anthropic JSON ──
      const messageId = 'msg_' + randomUUID().slice(0, 12);
      let finishReason = 'stop';
      let sawFinish = false;
      let usage = null;
      let toolCalls = null;
      let thinkingText = ''; // CC reasoning → Anthropic thinking block
      let upstreamError = null;

      reader = ccResponse.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';

      const processLines = () => {
        const lines = buf.split('\n');
        buf = lines.pop() || '';
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed === '[DONE]') continue;
          try {
            const event = JSON.parse(trimmed);
            switch (event.type) {
              case 'text-delta': lastCcEvent = event.type; fullText += event.text || ''; break;
              case 'reasoning-delta': lastCcEvent = event.type; thinkingText += event.text || ''; break;
              case 'tool-call':
                lastCcEvent = event.type;
                (toolCalls = toolCalls || []).push({
                  id: event.toolCallId || ('call_' + randomUUID().slice(0, 8)),
                  type: 'function',
                  function: {
                    name: event.toolName || '',
                    arguments: typeof event.input === 'string' ? event.input : JSON.stringify(event.input || {}),
                  },
                });
                break;
              case 'finish-step':
              case 'finish':
                lastCcEvent = event.type;
                sawFinish = true;
                finishReason = mapFinishReason(event.finishReason || 'stop');
                if (event.totalUsage || event.usage) usage = event.totalUsage || event.usage;
                break;
              case 'error':
                lastCcEvent = event.type;
                upstreamError = mapCcEventError(event);
                log('warn', 'CC error (Anthropic non-stream)', {
                  message: event.error?.message || event.message,
                  upstreamStatus: upstreamError.reportedStatus,
                  upstreamRetryable: event.error?.isRetryable,
                  code: upstreamError.code,
                  mappedTo: upstreamError.status,
                });
                break;
              // 无内容的事件：与流式翻译器的静默列表保持一致。
              // text-start / start / start-step / reasoning-start 原先只在流式路径被识别，
              // 非流式路径会掉进 default 打成 'Unknown CC event type' —— 上游每个响应都会发，
              // 于是线上刷屏。它们本身不携带内容（内容在 text-delta），纯粹是噪音。
              case 'text-start': case 'text-end': case 'start': case 'start-step':
              case 'reasoning-start': case 'reasoning-end': case 'finish-step':
              case 'provider-metadata': case 'tool-input-start': case 'tool-input-delta': case 'tool-input-end':
              case 'tool-error':
                // Silent - no user-visible content
                break;
              default:
                log('warn', 'Unknown CC event type', { type: event.type });
                break;
            }
          } catch {}
        }
      };

      const idle = createIdleWatchdog(NONSTREAM_IDLE_TIMEOUT_MS);
      while (true) {
        const result = await Promise.race([reader.read(), idle.arm()]);
        const { done, value } = result;
        if (done) break;
        bytesReceived += value.length;
        markTtft();
        const chunkText = decoder.decode(value, { stream: true });
        buf += chunkText;
        // 无换行则不可能产生完整行，跳过全量 split
        if (chunkText.indexOf('\n') !== -1) processLines();
      }
      idle.dispose();
      processLines();

      if (upstreamError) {
        outcome.state = 'fail';
        outcome.status = upstreamError.status;
        sendAnthropicError(res, upstreamError.status, upstreamError.body.error.type, upstreamError.body.error.message);
        return;
      }

      // 上游没有正常走完 finish —— 对齐 CLI 按可重试 502 处理，不谎报成功
      {
        const incomplete = incompleteUpstreamDetail(sawFinish, finishReason);
        if (incomplete) {
          outcome.state = 'fail';
          log('warn', 'Upstream stream incomplete', { path: '/v1/messages', reason: incomplete });
          const err = incompleteUpstreamError(incomplete);
          outcome.status = err.status;
          try { if (!abortController.signal.aborted) abortController.abort(); } catch {}
          sendAnthropicError(res, err.status, err.body.error.type, err.body.error.message, err.retry_after);
          return;
        }
      }

      // 零输出判定改为按实际内容：上游偶发不回 totalUsage 时，旧逻辑（usage?.outputTokens ?? 0 === 0）
      // 会把有完整文本的响应误杀成 429
      if (!fullText && !thinkingText && !toolCalls) {
        outcome.state = 'fail';
        outcome.status = 429;
        try { if (!abortController.signal.aborted) abortController.abort(); } catch {}
        sendAnthropicError(res, 429, 'rate_limit_error', 'Empty response from upstream (zero output tokens)', 10);
        return;
      }

      consecutiveTimeouts = 0;
      outcome.state = 'ok';
      sendJSON(res, 200, buildAnthropicResponse(model, fullText, toolCalls, finishReason, usage, thinkingText));
    }
  } catch (e) {
    if (abortController.signal.aborted) {
      log('warn', 'Request cancelled (client disconnected before CC response)', {
        path: '/v1/messages',
        model,
        messageId,
      });
    } else if (e.message === 'STREAM_IDLE_TIMEOUT') {
      outcome.state = 'fail';
      outcome.status = 429;
      log('warn', 'Stream idle timeout', {
        path: '/v1/messages',
        model,
        streaming: false,
        timeoutMs: NONSTREAM_IDLE_TIMEOUT_MS,
        elapsedMs: Date.now() - startTime,
        id: messageId,
        bytesReceived,
        lastCcEvent: lastCcEvent || '(none)',
        partialLen: fullText ? fullText.length : 0,
      });
      try { reader?.cancel().catch(() => {}); } catch {}
      try { abortController.abort(); } catch {} // 打断 CC 上游
      consecutiveTimeouts++;
      const timeoutMsg = consecutiveTimeouts >= TIMEOUT_REDUCE_CONTEXT_THRESHOLD
        ? 'Response timeout - try reducing context length (summarize earlier messages)'
        : 'Response timeout - request timed out';
      res.setHeader('Retry-After', '5');
      sendAnthropicError(res, 429, 'rate_limit_error', timeoutMsg);
    } else {
      outcome.state = 'fail';
      outcome.status = 502;
      log('error', 'Upstream error', { message: e.message });
      try { abortController.abort(); } catch {} // 打断 CC 上游
      sendAnthropicError(res, 502, 'proxy_error', `Upstream error: ${e.message}`, 10);
    }
  } finally {
    route.release(outcome, Date.now() - startTime);
  }
}

// ── 动态模型列表 ────────────────────────────────────

let dynamicModels = null;
let modelsLastFetch = 0;

async function fetchModels(apiKey) {
  const now = Date.now();
  if (dynamicModels && (now - modelsLastFetch) < CFG.modelRefreshIntervalMs) {
    return dynamicModels;
  }

  try {
    if (!apiKey || !CFG.useProviderModels) throw new Error('Provider models disabled');

    const response = await upstreamFetch(`${CFG.apiBase}/provider/v1/models`, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'x-cli-environment': 'production',
        'x-command-code-version': CC_VERSION,
      },
      signal: AbortSignal.timeout(10000),
    });

    if (response.ok) {
      const data = await response.json();
      if (Array.isArray(data.data)) {
        dynamicModels = data.data.map(m => ({
          id: m.id,
          name: m.id,
        }));
        modelsLastFetch = now;
        log('info', 'Fetched models from Provider API', { count: dynamicModels.length });
        return dynamicModels;
      }
    }
    log('warn', 'Provider models fetch failed, using hardcoded list', { status: response.status });
  } catch (e) {
    log('warn', 'Provider models fetch error, using hardcoded list', { error: e.message });
  }

  // Fallback to hardcoded MODELS
  return MODELS;
}

// ── OpenAI Responses API（/v1/responses）──────────────
// 供 Codex 等使用 Responses 协议的客户端接入。代理仍是无状态转换层：
// 把 input 翻译成内部 Chat 格式，复用同一套 CC 转发管线。
// 不支持 previous_response_id / store（需要服务端保存会话，与无状态定位冲突），
// 收到直接 400，避免静默降级成错误答案。

function responsesTextOf(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content.map(p => (p && typeof p === 'object' ? (p.text || '') : '')).join('');
}

// data URL 图片：一段文本里超过这个长度的 data URL 就当成"图"，提出来单独发；小图留在文本里
const INLINE_IMAGE_MIN = 256 * 1024;
// 单张 data URL 上限：再大就不要了，只留一句占位说明（既撑爆上游窗口，也撑爆内存）
const MAX_TOOL_IMAGE_URL = 12 * 1024 * 1024;
const DATA_URL_RE = /data:image\/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]+/gi;

// 从一段文本里捞出体积可观的 data URL 图片，原地替换成 [image] 占位。
// 必要性：base64 一旦被上游按**文本**分词就极其昂贵 —— 真机实测单张 2.76MB 截图 ≈ 1.92M token。
function extractInlineImages(text) {
  const images = [];
  const stripped = String(text).replace(DATA_URL_RE, (url) => {
    if (url.length < INLINE_IMAGE_MIN) return url;          // 小图留文本，别把工具输出切碎
    if (url.length > MAX_TOOL_IMAGE_URL) return '[image omitted: too large]';
    images.push(url);
    return '[image]';
  });
  return { text: stripped, images };
}

// Responses 的 function_call_output.output 可能是字符串，也可能是内容块数组；后者能带图。
// Codex Desktop 的截图工具就是 [{type:'input_image', image_url:'data:image/png;base64,...'}]。
// 返回 { text, images }，images 为 data URL 字符串数组。
function splitToolOutput(output) {
  if (output === undefined || output === null) return { text: '', images: [] };
  const texts = [];
  const images = [];
  const pushText = (raw) => {
    const r = extractInlineImages(raw);
    if (r.text) texts.push(r.text);
    images.push(...r.images);
  };
  if (typeof output === 'string') {
    pushText(output);
  } else if (Array.isArray(output)) {
    for (const part of output) {
      if (!part) continue;
      if (part.type === 'input_image' || part.type === 'image_url') {
        const url = typeof part.image_url === 'string' ? part.image_url : (part.image_url && part.image_url.url) || '';
        if (url.startsWith('data:')) {
          if (url.length <= MAX_TOOL_IMAGE_URL) images.push(url);
          else texts.push('[image omitted: too large]');
        } else if (url) {
          texts.push(`[image: ${url}]`);      // 外链图上游不认，只能留个说明
        }
      } else if (typeof part.text === 'string') {
        pushText(part.text);
      } else {
        pushText(JSON.stringify(part));       // 未知块保持原样，与旧行为一致
      }
    }
  } else {
    pushText(JSON.stringify(output));
  }
  return { text: texts.filter(Boolean).join('\n'), images };
}
// 单条请求内"工具截图"的总字节预算。工具截图会随每一轮请求全量重传，是内存与首字延迟的
// 头号杀手：真机实测一个 Codex 会话里 11 张截图 ≈5.5MB base64，配合 README 记录的内存放大
// ×5.1~7.4，把 1GB 的机器打到 global OOM（node anon-rss 532MB，内核把整机拖死）。
// 策略：从**最新**往回保留，预算内照发，超预算的老图替换成占位说明 —— 让模型知道有图被丢，
// 而不是以为历史里本来就没图。CC_MAX_TOOL_IMAGE_MB=0 关闭该行为。
const MAX_TOOL_IMAGE_BYTES = (() => {
  const mb = Number.parseFloat(process.env.CC_MAX_TOOL_IMAGE_MB ?? '6');
  return Number.isFinite(mb) && mb > 0 ? Math.round(mb * 1024 * 1024) : 0;
})();

function trimToolImages(messages) {
  if (!MAX_TOOL_IMAGE_BYTES) return;
  const refs = [];
  for (const m of messages) {
    if (!Array.isArray(m.content)) continue;
    for (const part of m.content) if (part && part._toolImage) refs.push({ m, part });
  }
  if (!refs.length) return;
  const keep = new Set();
  let used = 0;
  for (let i = refs.length - 1; i >= 0; i--) {           // 从最新往回挑，至少保一张
    const len = (refs[i].part.image_url && refs[i].part.image_url.url || '').length;
    if (keep.size === 0 || used + len <= MAX_TOOL_IMAGE_BYTES) { keep.add(i); used += len; }
  }
  if (keep.size === refs.length) return;                 // 没超预算，原样不动
  let droppedBytes = 0;
  for (let i = 0; i < refs.length; i++) {
    if (keep.has(i)) continue;
    const idx = refs[i].m.content.indexOf(refs[i].part);
    if (idx === -1) continue;
    droppedBytes += (refs[i].part.image_url && refs[i].part.image_url.url || '').length;
    refs[i].m.content[idx] = { type: 'text', text: '[older tool screenshot omitted: image budget exceeded]' };
  }
  log('warn', 'Tool images trimmed to budget', {
    total: refs.length, kept: keep.size, dropped: refs.length - keep.size,
    keptBytes: used, droppedBytes, budgetBytes: MAX_TOOL_IMAGE_BYTES,
  });
}


function responsesReasoningOf(item) {
  if (!item) return '';
  if (Array.isArray(item.summary) && item.summary.length) return item.summary.map(p => (p && p.text) || '').join('');
  if (Array.isArray(item.content) && item.content.length) return item.content.map(p => (p && p.text) || '').join('');
  return typeof item.text === 'string' ? item.text : '';
}

function newResponsesId(prefix) {
  return prefix + randomUUID().replace(/-/g, '').slice(0, 24);
}

function convertResponsesToChat(respReq) {
  const messages = [];

  if (respReq.instructions !== undefined && respReq.instructions !== null) {
    const sys = responsesTextOf(respReq.instructions);
    if (sys) messages.push({ role: 'system', content: sys });
  }

  // Responses 把 reasoning / message / function_call 拆成并列 item，
  // Chat 要求它们挂在同一条 assistant 消息上，故先累积再冲刷。
  let pending = null;
  const ensurePending = () => (pending = pending || { role: 'assistant', content: null, tool_calls: [] });
  const flushPending = () => {
    if (!pending) return;
    if (!pending.tool_calls.length) delete pending.tool_calls;
    if (!pending.reasoning_content) delete pending.reasoning_content;
    if (pending.content === null && !pending.tool_calls) { pending = null; return; }
    messages.push(pending);
    pending = null;
  };

  const input = respReq.input;
  if (typeof input === 'string') {
    messages.push({ role: 'user', content: input });
  } else if (Array.isArray(input)) {
    for (const item of input) {
      if (!item || typeof item !== 'object') continue;
      // OpenAI 规范里 input 数组的联合类型第一个成员是 EasyInputMessage，它的
      // required 只有 role 与 content —— type 是可选的（官方文档与 SDK 示例普遍写作
      // { role: 'user', content: 'hi' }）。item.type 为 undefined 但有 role 时按
      // message 处理，否则这类 item 会落进 default 被丢弃：全部省略时只剩
      // "input is required" 的误导性报错；混合形态时更糟 —— 校验能过，用户在
      // HTTP 200 下静默丢消息。这里只在 type 缺失时兜底，带 type 的 item 判定不变。
      switch (item.type ?? (item.role ? 'message' : undefined)) {
        case 'reasoning': {
          const t = responsesReasoningOf(item);
          if (t) ensurePending().reasoning_content = t;
          break;
        }
        case 'message': {
          const text = responsesTextOf(item.content);
          if (item.role === 'assistant') {
            if (text) ensurePending().content = text;
          } else if (item.role === 'system' || item.role === 'developer') {
            flushPending();
            messages.push({ role: 'system', content: text });
          } else {
            flushPending();
            messages.push({ role: 'user', content: text });
          }
          break;
        }
        case 'function_call': {
          ensurePending().tool_calls.push({
            id: item.call_id || item.id || ('call_' + randomUUID().slice(0, 8)),
            type: 'function',
            function: { name: item.name || '', arguments: item.arguments || '{}' },
          });
          break;
        }
        case 'function_call_output': {
          flushPending();
          // 工具结果里可能带图（Codex Desktop 截图工具即 output=[{type:'input_image', image_url:'data:image/png;base64,...'}]）。
          // 绝不能 JSON.stringify 成文本送上游：base64 会按文本分词，真机实测单张 2.76MB 截图 ≈ 1.92M token，
          // 直接撞穿模型 1M 窗口（"maximum context length is 1048576 tokens ... 1922800 in the messages"）。
          // 官方 CLI 的排布是：tool-result 只放文本，图片提出来放进紧跟其后的一条 user 消息
          // （见 command-code@1.66.0 dist/cli.mjs 的 convertUserMessage / tool_result 分支）。
          const { text, images } = splitToolOutput(item.output);
          messages.push({ role: 'tool', tool_call_id: item.call_id || '', content: text });
          if (images.length) {
            log('info', 'Hoisted tool-output images to user message', {
              count: images.length, bytes: images.reduce((a, u) => a + u.length, 0),
            });
            // content 走 image_url 形态，交给 buildCcRequest 里已验证的 user 图片分支转成 CC 的 {type:'image',image,mimeType}
            messages.push({
              role: 'user',
              content: [
                { type: 'text', text: '[image returned by tool call]' },
                ...images.map(url => ({ type: 'image_url', image_url: { url }, _toolImage: true })),
              ],
            });
          }
          break;
        }
        default: {
          log('warn', 'Unknown Responses input item type', { type: item.type });
          break;
        }
      }
    }
  }
  flushPending();

  // 统一裁剪工具截图（此时所有 item 都已转成 chat 形态，按顺序处理最直观）
  trimToolImages(messages);

  let tools;
  if (Array.isArray(respReq.tools) && respReq.tools.length) {
    tools = respReq.tools.filter(t => t && (t.type === 'function' || t.name)).map(t => ({
      type: 'function',
      function: {
        name: t.name || '',
        description: t.description || '',
        parameters: t.parameters || { type: 'object', properties: {} },
      },
    }));
    if (!tools.length) tools = undefined;
  }

  let toolChoice;
  const tc = respReq.tool_choice;
  if (typeof tc === 'string') toolChoice = tc;
  else if (tc && typeof tc === 'object' && tc.name) toolChoice = { type: 'function', function: { name: tc.name } };

  const out = { model: respReq.model, messages, stream: respReq.stream === true };
  if (tools) out.tools = tools;
  if (toolChoice) out.tool_choice = toolChoice;
  if (respReq.max_output_tokens !== undefined) out.max_tokens = respReq.max_output_tokens;
  if (respReq.temperature !== undefined) out.temperature = respReq.temperature;
  if (respReq.top_p !== undefined) out.top_p = respReq.top_p;
  if (respReq.parallel_tool_calls !== undefined) out.parallel_tool_calls = respReq.parallel_tool_calls;
  const eff = respReq.reasoning && typeof respReq.reasoning === 'object' ? respReq.reasoning.effort : undefined;
  if (eff) out.reasoning_effort = eff;
  return out;
}

// Responses 的 input_tokens 是总数，cached / cache_write 均为其子集 ——
// 与 Anthropic 相反（那里 cache_read 是独立增量，必须做减法，见 issue #25）。
// 本代理上游 CC 的 inputTokens 同样已含缓存，故此处直接沿用、不做减法。
// 实测：total_tokens === input_tokens + output_tokens（即使 cached 占绝大多数）。
function buildResponsesUsage(usage, fallbackOutputTokens) {
  const u = usage || {};
  normalizeUsage(u);
  const inTok = u.inputTokens || 0;
  const outTok = u.outputTokens || fallbackOutputTokens || 0;
  return {
    input_tokens: inTok,
    // 规范里 cached_tokens 与 cache_write_tokens 都是 required
    input_tokens_details: {
      cached_tokens: u.cachedInputTokens || 0,
      cache_write_tokens: (u.inputTokenDetails && u.inputTokenDetails.cacheWriteTokens) || 0,
    },
    output_tokens: outTok,
    output_tokens_details: { reasoning_tokens: 0 },
    total_tokens: inTok + outTok,
  };
}

function buildResponsesOutput(fullText, thinkingText, toolCalls) {
  const output = [];
  if (thinkingText) {
    output.push({ type: 'reasoning', id: newResponsesId('rs_'), summary: [{ type: 'summary_text', text: thinkingText }] });
  }
  if (fullText) {
    output.push({
      type: 'message', id: newResponsesId('msg_'), status: 'completed', role: 'assistant',
      content: [{ type: 'output_text', text: fullText, annotations: [] }],
    });
  }
  for (const tc of (toolCalls || [])) {
    const rawArgs = tc.function ? tc.function.arguments : '{}';
    output.push({
      type: 'function_call', id: newResponsesId('fc_'), call_id: tc.id,
      name: tc.function ? (tc.function.name || '') : '',
      arguments: typeof rawArgs === 'string' ? rawArgs : JSON.stringify(rawArgs || {}),
      status: 'completed',
    });
  }
  return output;
}

function buildResponsesObject(responseId, model, created, fullText, thinkingText, toolCalls, usage, opts) {
  const o = opts || {};
  const truncated = o.finishReason === 'length';
  const paused = o.finishReason === 'pause_turn';
  return {
    id: responseId,
    object: 'response',
    created_at: created,
    status: (truncated || paused) ? 'incomplete' : 'completed',
    completed_at: nowUnix(),
    error: null,
    incomplete_details: truncated ? { reason: 'max_output_tokens' }
      : paused ? { reason: 'pause_turn' } : null,
    input: o.input || [],
    instructions: o.instructions === undefined ? null : o.instructions,
    max_output_tokens: o.max_output_tokens === undefined ? null : o.max_output_tokens,
    model,
    output: buildResponsesOutput(fullText, thinkingText, toolCalls),
    output_text: fullText || '',
    parallel_tool_calls: true,
    previous_response_id: null,
    reasoning: o.reasoning || null,
    store: false,
    temperature: o.temperature === undefined ? 1 : o.temperature,
    text: { format: { type: 'text' } },
    tool_choice: o.tool_choice || 'auto',
    tools: o.tools || [],
    top_p: o.top_p === undefined ? 1 : o.top_p,
    truncation: 'disabled',
    usage: buildResponsesUsage(usage, 0),
    user: null,
    metadata: {},
  };
}

function sendResponsesError(res, status, type, message, retryAfter) {
  const body = { error: { message, type, code: null, param: null } };
  if (retryAfter !== undefined) body.retry_after = retryAfter;
  sendJSON(res, status, body);
}

// CC NDJSON → Responses 具名 SSE 事件（每个事件都必需的 sequence_number 递增发送）
function createResponsesSseTranslator(model, responseId, created) {
  let seq = 0;
  const sse = (type, data) => 'event: ' + type + '\ndata: ' + JSON.stringify(Object.assign({ type, sequence_number: seq++ }, data)) + '\n\n';
  let createdSent = false;
  let current = null;
  let outputIndex = 0;
  const doneItems = [];
  let usage = null;
  let textAcc = '';
  let finishReason = null;
  // 是否见过完成信号（见 incompleteUpstreamDetail 的口径说明）
  let sawFinish = false;

  const baseResponse = (status, output) => ({
    id: responseId, object: 'response', created_at: created, status,
    output: output || [], output_text: '', model, error: null, incomplete_details: null,
    parallel_tool_calls: true, previous_response_id: null, store: false, tools: [], metadata: {},
  });

  function startResponse() {
    createdSent = true;
    return [
      sse('response.created', { response: baseResponse('in_progress') }),
      sse('response.in_progress', { response: baseResponse('in_progress') }),
    ];
  }

  function closeItem() {
    if (!current) return [];
    const out = [];
    const item = current.item;
    const idx = current.index;
    if (current.kind === 'message') {
      out.push(sse('response.output_text.done', { item_id: item.id, output_index: idx, content_index: 0, text: current.textBuf, logprobs: [] }));
      out.push(sse('response.content_part.done', {
        item_id: item.id, output_index: idx, content_index: 0,
        part: { type: 'output_text', text: current.textBuf, annotations: [] },
      }));
      item.content = [{ type: 'output_text', text: current.textBuf, annotations: [] }];
      item.status = 'completed';
    } else if (current.kind === 'function_call') {
      out.push(sse('response.function_call_arguments.done', { item_id: item.id, output_index: idx, arguments: item.arguments }));
      item.status = 'completed';
    } else if (current.kind === 'reasoning') {
      out.push(sse('response.reasoning_summary_text.done', { item_id: item.id, output_index: idx, summary_index: 0, text: current.textBuf }));
      out.push(sse('response.reasoning_summary_part.done', {
        item_id: item.id, output_index: idx, summary_index: 0,
        part: { type: 'summary_text', text: current.textBuf },
      }));
      item.summary = [{ type: 'summary_text', text: current.textBuf }];
      item.status = 'completed';
    }
    out.push(sse('response.output_item.done', { output_index: idx, item }));
    doneItems.push(item);
    current = null;
    return out;
  }

  function openItem(kind, item) {
    const out = closeItem();
    current = { kind, index: outputIndex++, item, textBuf: '' };
    out.push(sse('response.output_item.added', { output_index: current.index, item }));
    if (kind === 'message') {
      out.push(sse('response.content_part.added', {
        item_id: item.id, output_index: current.index, content_index: 0,
        part: { type: 'output_text', text: '', annotations: [] },
      }));
    } else if (kind === 'reasoning') {
      out.push(sse('response.reasoning_summary_part.added', {
        item_id: item.id, output_index: current.index, summary_index: 0,
        part: { type: 'summary_text', text: '' },
      }));
    }
    return out;
  }

  return {
    lastCcEvent: '',
    upstreamError: null,
    inputTokens: 0,
    outputTokens: 0,
    cachedInputTokens: 0,
    // 提前发 created/in_progress（不带内容）：上游是 reasoning 模型，大 prompt 首字可能要十几秒，
    // 这期间一个字节都不出网就会被中间层（实测 EdgeOne 源站 ~15s）或客户端首字节超时掐掉
    start: startResponse,
    get started() { return createdSent; },
    get stopReason() { return finishReason; },
    parseLine(line) {
      const trimmed = line.trim();
      if (!trimmed || trimmed === '[DONE]' || trimmed.startsWith(':')) return null;
      let event;
      try { event = JSON.parse(trimmed); } catch { return null; }
      if (!event.type) return null;
      this.lastCcEvent = event.type;
      const out = [];

      switch (event.type) {
        case 'text-start': case 'reasoning-start': case 'start': case 'start-step':
          break;

        case 'text-delta': {
          const text = event.text || event.delta || '';
          if (!text) break;
          if (!createdSent) out.push.apply(out, startResponse());
          if (!current || current.kind !== 'message') {
            out.push.apply(out, openItem('message', { type: 'message', id: newResponsesId('msg_'), status: 'in_progress', role: 'assistant', content: [] }));
          }
          current.textBuf += text;
          textAcc += text;
          out.push(sse('response.output_text.delta', { item_id: current.item.id, output_index: current.index, content_index: 0, delta: text, logprobs: [] }));
          break;
        }

        case 'reasoning-delta': {
          const text = event.text || '';
          if (!text) break;
          if (!createdSent) out.push.apply(out, startResponse());
          if (!current || current.kind !== 'reasoning') {
            out.push.apply(out, openItem('reasoning', { type: 'reasoning', id: newResponsesId('rs_'), summary: [], status: 'in_progress' }));
          }
          current.textBuf += text;
          out.push(sse('response.reasoning_summary_text.delta', {
            item_id: current.item.id, output_index: current.index, summary_index: 0, delta: text,
          }));
          break;
        }

        case 'tool-call': {
          if (!createdSent) out.push.apply(out, startResponse());
          const callId = event.toolCallId || newResponsesId('call_');
          const args = typeof event.input === 'string' ? event.input : JSON.stringify(event.input || {});
          out.push.apply(out, openItem('function_call', {
            type: 'function_call', id: newResponsesId('fc_'), call_id: callId,
            name: event.toolName || '', arguments: '', status: 'in_progress',
          }));
          current.item.arguments = args;
          out.push(sse('response.function_call_arguments.delta', { item_id: current.item.id, output_index: current.index, delta: args }));
          break;
        }

        case 'finish': {
          sawFinish = true;
          // 必须归一化：截断类不止 'length'（还有 max_output_tokens /
          // model_context_window_exceeded），原来直接比对原始值会漏判成 completed。
          finishReason = event.finishReason ? mapFinishReason(event.finishReason) : null;
          const u = event.totalUsage || event.usage || null;
          if (u) {
            normalizeUsage(u);
            usage = u;
            this.inputTokens = u.inputTokens || 0;
            this.outputTokens = u.outputTokens || 0;
            this.cachedInputTokens = u.cachedInputTokens || 0;
          }
          break;
        }

        case 'error': {
          this.upstreamError = mapCcEventError(event);
          // 上游在 HTTP 200 之后于**流内**报错时，这里以前只赋值不打日志：客户端收到 400，
          // 而 journalctl 里一片安静（本次排障就是靠 nginx 的 body_bytes_sent=0 反推的）。
          // 对齐 /v1/chat/completions 路径的 CC stream error。
          log('warn', 'CC stream error', {
            path: '/v1/responses',
            message: event.error?.message || event.message || 'Unknown error',
            upstreamStatus: this.upstreamError.reportedStatus,
            code: this.upstreamError.code,
            mappedTo: this.upstreamError.status,
          });
          break;
        }

        default: break;
      }
      return out.length ? out : null;
    },
    finish() {
      if (!createdSent) return [];
      const out = closeItem();
      // 上游没有正常走完 finish —— 不能报 response.completed（那是把截断谎报成完整）。
      // 对齐 CLI：按可重试的 upstream_error 处理。
      const incomplete = incompleteUpstreamDetail(sawFinish, finishReason);
      if (incomplete) {
        log('warn', 'Upstream stream incomplete', { path: '/v1/responses', reason: incomplete });
        out.push(sse('response.failed', {
          response: Object.assign(baseResponse('failed'), {
            error: { code: 'upstream_error', message: incompleteUpstreamError(incomplete).body.error.message },
          }),
        }));
        return out;
      }
      // 'length' 表示被截断（max_output_tokens / model_context_window_exceeded 都归一到这里）；
      // 'pause_turn' 同样是「后面还有内容没发完」，规范要求 status=incomplete。
      const truncated = finishReason === 'length';
      const paused = finishReason === 'pause_turn';
      out.push(sse(truncated || paused ? 'response.incomplete' : 'response.completed', {
        response: Object.assign(baseResponse(truncated || paused ? 'incomplete' : 'completed', doneItems.slice()), {
          output_text: textAcc,
          incomplete_details: truncated ? { reason: 'max_output_tokens' }
            : paused ? { reason: 'pause_turn' } : null,
          usage: buildResponsesUsage(usage, this.outputTokens),
        }),
      }));
      return out;
    },
    fail(message) {
      if (!createdSent) return [];
      return [sse('response.failed', {
        response: Object.assign(baseResponse('failed'), {
          error: { code: 'upstream_error', message: message || 'Upstream error' },
        }),
      })];
    },
    errorEvent(message) {
      return sse('error', { code: null, message: message || 'Upstream error', param: null });
    },
  };
}

async function handleResponses(req, res) {
  let respReq;
  try {
    respReq = await readBody(req);
  } catch (e) {
    if (e.statusCode === 413) { sendResponsesError(res, 413, 'invalid_request_error', e.message); return; }
    sendResponsesError(res, 400, 'invalid_request_error', 'Invalid JSON body');
    return;
  }

  if (respReq.previous_response_id) {
    sendResponsesError(res, 400, 'invalid_request_error',
      'previous_response_id is not supported (this proxy is stateless); send the full input each turn');
    return;
  }

  let route = resolveRoute(req.headers);
  if (route && route.error === 'no_available_account') {
    res.setHeader('Retry-After', '5');
    sendResponsesError(res, 503, 'no_available_account', 'No available upstream account for this token', 5);
    return;
  }
  if (!route) {
    sendResponsesError(res, 401, 'authentication_error',
      'Missing API key. Send in Authorization: Bearer <key> or x-api-key header');
    return;
  }
  let apiKey = route.upstreamKey;
  const outcome = { state: 'pending', ttftMs: null, status: null, code: null, message: null };

  let chatReq = convertResponsesToChat(respReq);
  if (!chatReq.messages.length) {
    sendResponsesError(res, 400, 'invalid_request_error', 'input is required');
    return;
  }

  const stream = chatReq.stream === true;
  const model = chatReq.model || 'deepseek/deepseek-v4-flash';
  const responseId = newResponsesId('resp_');
  const created = nowUnix();
  const echoOpts = {
    instructions: respReq.instructions === undefined ? null : respReq.instructions,
    max_output_tokens: respReq.max_output_tokens === undefined ? null : respReq.max_output_tokens,
    temperature: respReq.temperature,
    top_p: respReq.top_p,
    reasoning: respReq.reasoning || null,
    tool_choice: typeof respReq.tool_choice === 'string' ? respReq.tool_choice : 'auto',
    tools: respReq.tools || [],
  };
  const ccBody = buildCcRequest(chatReq);
  const promptCacheKey = chatReq.prompt_cache_key;
  chatReq = null;

  const abortController = new AbortController();
  let aborted = false;
  const startTime = Date.now();
  const markTtft = () => { if (outcome.ttftMs == null) outcome.ttftMs = Date.now() - startTime; };
  let bytesReceived = 0;
  let lastCcEvent = '';
  let reader = null;
  let translator = null;

  res.on('close', () => {
    if (res.writableEnded) return;
    aborted = true;
    if (outcome.state === 'pending') outcome.state = 'aborted';
    log('warn', 'Client disconnected', {
      path: '/v1/responses', model, responseId, elapsedMs: Date.now() - startTime,
      bytesSent: bytesReceived, lastCcEvent: lastCcEvent || '(none)',
    });
    if (!abortController.signal.aborted) { try { abortController.abort(); } catch (e2) {} }
  });

  try {
    await ensureInitialized(apiKey, abortController.signal);
    let ccResponse = await forwardToCC(ccBody, apiKey, req.headers, abortController.signal, promptCacheKey);

    if (!ccResponse.ok) {
      let errorText = await ccResponse.text().catch(() => '');
      let mapped = mapCcError(ccResponse.status, errorText);
      const fo = await creditFailover({
        route, apiKey, ccResponse, errorText, mapped, outcome, req,
        forward: async (key) => {
          await ensureInitialized(key, abortController.signal);
          return forwardToCC(ccBody, key, req.headers, abortController.signal, promptCacheKey);
        },
      });
      route = fo.route; apiKey = fo.apiKey; ccResponse = fo.ccResponse;
      errorText = fo.errorText; mapped = fo.mapped;
      if (!ccResponse.ok) {
        outcome.state = fo.creditExhausted
          ? 'credit_exhausted'
          : classifyUpstreamStatus(ccResponse.status);
        outcome.status = ccResponse.status;
        outcome.code = mapped.code || null;
        outcome.message = (mapped.body && mapped.body.error && mapped.body.error.message) || null;
        log('error', 'CC API error', { status: ccResponse.status, path: '/v1/responses', code: mapped.code, body: summarizeUpstreamError(errorText) });
        sendResponsesError(res, mapped.status, mapped.body.error.type, mapped.body.error.message, mapped.body.retry_after);
        return;
      }
    }

    if (stream) {
      translator = createResponsesSseTranslator(model, responseId, created);
      let buffer = '';
      let started = false;
      const decoder = new TextDecoder();
      reader = ccResponse.body.getReader();
      const idle = createIdleWatchdog(STREAM_IDLE_TIMEOUT_MS);
      const SSE_HEADERS = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
      };
      const writeEvents = async (evts) => {
        if (!started) { res.writeHead(200, SSE_HEADERS); started = true; }
        for (const e2 of evts) res.write(e2);
        await waitDrain(res);
      };

      // 上游已 200：立刻把响应头 + response.created / response.in_progress 推下去。
      // 不能等首个内容事件 —— Codex 实测 reasoning_effort=max + 大 prompt，首字要 15s+，
      // 这段时间此前**零字节出网**，于是 nginx access.log 全是 `499 0`（body_bytes_sent=0）、
      // 中间 CDN（EdgeOne）按源站超时掐掉连接、客户端只能每 15 秒重试一次。
      // created 是不带内容的协议首事件，先发符合 Responses 语义；上游随后失败会走 response.failed。
      await writeEvents(translator.start());

      // SSE 保活：对齐 /v1/messages 的心跳思路，但这里发**注释行**。
      // Responses 协议没有 ping 事件，塞未知 event 类型有被严格解析器判错的风险；
      // 注释行（以 ':' 开头）按 SSE 规范必须被忽略 —— chat 端点在静默事件时也是这么发的。
      // 为什么必须发：首字前的静默期实测 15~40s，中间层的"源站空闲"超时（EdgeOne 实测约 15s）
      // 会把连接掐掉 —— 现象是客户端 ~16s 断连、代理侧 Client disconnected、nginx 只记到很少字节。
      const heartbeat = setInterval(() => {
        // 回调是同步的，无法 await waitDrain，所以用 writableNeedDrain 直接跳过（背压时少一条注释无副作用）
        if (aborted || !started || res.writableEnded || res.writableNeedDrain) return;
        try { res.write(': keepalive\n\n'); } catch (e2) {}
      }, 5000);

      try {
        while (true) {
          const result = await Promise.race([reader.read(), idle.arm()]);
          const done = result.done;
          const value = result.value;
          if (done) break;
          if (aborted || res.destroyed) break;
          bytesReceived += value.length;
          markTtft();

          const chunkText = decoder.decode(value, { stream: true });
          buffer += chunkText;
          let lines = [];
          if (chunkText.indexOf('\n') !== -1) {
            lines = buffer.split('\n');
            buffer = lines.pop() || '';
          }

          for (const line of lines) {
            const evts = translator.parseLine(line);
            if (evts) await writeEvents(evts);
            if (translator.lastCcEvent) lastCcEvent = translator.lastCcEvent;
          }
        }

        if (!aborted) {
          if (buffer.trim()) {
            const evts = translator.parseLine(buffer);
            if (evts) await writeEvents(evts);
          }
          if (translator.upstreamError) {
            outcome.state = 'fail';
            outcome.status = translator.upstreamError.status;
            if (!started) {
              sendResponsesError(res, translator.upstreamError.status,
                translator.upstreamError.body.error.type, translator.upstreamError.body.error.message,
                translator.upstreamError.body.retry_after);
              return;
            }
            const failed = translator.fail(translator.upstreamError.body.error.message);
            if (failed.length) await writeEvents(failed);
          } else if (translator.outputTokens === 0 && !translator.started) {
            outcome.state = 'fail';
            outcome.status = 429;
            try { if (!abortController.signal.aborted) abortController.abort(); } catch (e2) {}
            sendResponsesError(res, 429, 'rate_limit_error',
              'Empty response from upstream (zero output tokens)', 10);
            return;
          } else {
            outcome.state = 'ok';
            if (!started) { res.writeHead(200, SSE_HEADERS); started = true; }
            for (const e2 of translator.finish()) res.write(e2);
          }
          consecutiveTimeouts = 0;
        }
      } catch (e) {
        if (aborted) {
          try { reader.cancel().catch(() => {}); } catch (e2) {}
        } else if (e.message === 'STREAM_IDLE_TIMEOUT') {
          outcome.state = 'fail';
          outcome.status = 429;
          log('warn', 'Stream idle timeout', {
            path: '/v1/responses', model, streaming: true, timeoutMs: STREAM_IDLE_TIMEOUT_MS,
            elapsedMs: Date.now() - startTime, bytesReceived, lastCcEvent: lastCcEvent || '(none)',
          });
          consecutiveTimeouts++;
          const timeoutMsg = consecutiveTimeouts >= TIMEOUT_REDUCE_CONTEXT_THRESHOLD
            ? 'Response timeout - try reducing context length (summarize earlier messages)'
            : 'Response timeout - request timed out';
          if (!started) { sendResponsesError(res, 429, 'rate_limit_error', timeoutMsg, 5); return; }
          if (!res.writableEnded) {
            // end() 而不是 destroy()：理由见 handleChatCompletions 流式超时分支
            try { res.end(translator.errorEvent(timeoutMsg)); } catch (e2) {}
          }
        } else {
          outcome.state = 'fail';
          outcome.status = 502;
          log('error', 'Stream error', { message: e.message, path: '/v1/responses' });
          try { abortController.abort(); } catch (e2) {}
          if (!started) {
            sendResponsesError(res, 502, 'proxy_error', 'Upstream error: ' + e.message, 10);
            return;
          }
          if (!res.writableEnded) {
            try { res.write(translator.errorEvent(e.message)); } catch (e2) {}
          }
        }
      } finally {
        clearInterval(heartbeat);
        idle.dispose();
      }

      if (!res.writableEnded) res.end();
    } else {
      // ── 非流式：缓冲完整 NDJSON 后一次性构造 Responses 对象 ──
      let fullText = '';
      let thinkingText = '';
      let usage = null;
      let finishReason = 'stop';
      let sawFinish = false;
      let upstreamError = null;
      const toolCalls = [];
      reader = ccResponse.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';

      const processLines = () => {
        const lines = buf.split('\n');
        buf = lines.pop() || '';
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed === '[DONE]' || trimmed.startsWith(':')) continue;
          let event;
          try { event = JSON.parse(trimmed); } catch (e2) { continue; }
          switch (event.type) {
            case 'text-delta': lastCcEvent = event.type; fullText += event.text || ''; break;
            case 'reasoning-delta': lastCcEvent = event.type; thinkingText += event.text || ''; break;
            case 'tool-call': {
              lastCcEvent = event.type;
              toolCalls.push({
                id: event.toolCallId || ('call_' + randomUUID().slice(0, 8)),
                type: 'function',
                function: {
                  name: event.toolName || '',
                  arguments: typeof event.input === 'string' ? event.input : JSON.stringify(event.input || {}),
                },
              });
              break;
            }
            case 'finish-step':
            case 'finish':
              lastCcEvent = event.type;
              sawFinish = true;
              finishReason = mapFinishReason(event.finishReason || 'stop');
              if (event.totalUsage || event.usage) usage = event.totalUsage || event.usage;
              break;
            case 'error':
              lastCcEvent = event.type;
              upstreamError = mapCcEventError(event);
              log('warn', 'CC stream error (non-stream)', {
                message: event.error ? event.error.message : event.message,
                upstreamStatus: upstreamError.reportedStatus,
                upstreamRetryable: event.error?.isRetryable,
                code: upstreamError.code,
                mappedTo: upstreamError.status,
              });
              break;
            // 无内容的事件：与流式翻译器以及另两条非流式路径保持一致。
            // 这条路径原先**没有静默列表**，于是上游每个响应都会发的一串无内容事件
            //（text-start / text-end / start / start-step / reasoning-start / reasoning-end /
            //  provider-metadata / tool-input-* / tool-error）全部掉进 default 打成
            // 'Unknown CC event type'，线上刷屏、把真正的错误淹掉。
            case 'text-start': case 'text-end': case 'start': case 'start-step':
            case 'reasoning-start': case 'reasoning-end': case 'finish-step':
            case 'provider-metadata': case 'tool-input-start': case 'tool-input-delta': case 'tool-input-end':
            case 'tool-error':
              // Silent - no user-visible content
              break;
            default:
              log('warn', 'Unknown CC event type', { type: event.type });
              break;
          }
        }
      };

      const idle = createIdleWatchdog(NONSTREAM_IDLE_TIMEOUT_MS);
      while (true) {
        const result = await Promise.race([reader.read(), idle.arm()]);
        const done = result.done;
        const value = result.value;
        if (done) break;
        bytesReceived += value.length;
        markTtft();
        const chunkText = decoder.decode(value, { stream: true });
        buf += chunkText;
        if (chunkText.indexOf('\n') !== -1) processLines();
      }
      idle.dispose();
      processLines();

      if (upstreamError) {
        outcome.state = 'fail';
        outcome.status = upstreamError.status;
        sendResponsesError(res, upstreamError.status, upstreamError.body.error.type,
          upstreamError.body.error.message, upstreamError.body.retry_after);
        return;
      }

      // 上游没有正常走完 finish —— 对齐 CLI 按可重试 502 处理，不谎报成功
      {
        const incomplete = incompleteUpstreamDetail(sawFinish, finishReason);
        if (incomplete) {
          outcome.state = 'fail';
          log('warn', 'Upstream stream incomplete', { path: '/v1/responses', reason: incomplete });
          const err = incompleteUpstreamError(incomplete);
          outcome.status = err.status;
          try { if (!abortController.signal.aborted) abortController.abort(); } catch {}
          sendResponsesError(res, err.status, err.body.error.type, err.body.error.message, err.retry_after);
          return;
        }
      }

      if (!fullText && !thinkingText && !toolCalls.length) {
        outcome.state = 'fail';
        outcome.status = 429;
        try { if (!abortController.signal.aborted) abortController.abort(); } catch (e2) {}
        sendResponsesError(res, 429, 'rate_limit_error',
          'Empty response from upstream (zero output tokens)', 10);
        return;
      }

      consecutiveTimeouts = 0;
      outcome.state = 'ok';
      echoOpts.finishReason = finishReason;
      sendJSON(res, 200, buildResponsesObject(
        responseId, model, created, fullText, thinkingText, toolCalls, usage, echoOpts));
    }
  } catch (e) {
    if (e.name === 'AbortError' || e.code === 'ABORT_ERR') return;
    if (outcome.state === 'pending') { outcome.state = 'fail'; outcome.status = 502; }
    log('error', 'Responses handler error', { message: e.message });
    if (!res.headersSent) {
      sendResponsesError(res, 502, 'proxy_error', 'Upstream error: ' + e.message, 10);
    } else if (!res.writableEnded) {
      try { res.write(translator ? translator.errorEvent(e.message) : ''); } catch (e2) {}
      try { res.end(); } catch (e2) {}
    }
  } finally {
    route.release(outcome, Date.now() - startTime);
  }
}

async function handleModels(req, res) {
  // /v1/models 不计入成败指标，只按池模式借用一个账号（legacy 直通保持原样）
  const raw = rawCredential(req.headers);
  let apiKey = null;
  let lease = null;
  if (raw && findClientByToken(raw)) {
    lease = selectForModels();
    if (!lease) {
      res.setHeader('Retry-After', '5');
      sendJSON(res, 503, { error: { message: 'No available upstream account for this token', type: 'no_available_account' }, retry_after: 5 });
      return;
    }
    apiKey = lease.upstreamKey;
  } else {
    apiKey = getApiKey(req.headers);
  }
  try {
    const models = await fetchModels(apiKey);
    const now = nowUnix();
    sendJSON(res, 200, {
      object: 'list',
      data: models.map(m => ({
        id: m.id,
        object: 'model',
        created: now,
        owned_by: 'command-code',
      })),
    });
  } finally {
    if (lease) lease.release();
  }
}

function handleHealth(req, res) {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('OK');
}

// ══════════════════════════════════════════════════════════════
// 管理 API（/admin 外壳 + /admin/api/*）
// 安全约定：账号 key / client 令牌永不出明文；仅新建/轮换时一次性返回 client 明文令牌。
// ══════════════════════════════════════════════════════════════
const ADMIN_BODY_LIMIT = 1048576; // 管理请求体 1MB 上限
const SERVER_STARTED_AT = Date.now();
let ADMIN_DISABLED_WARNED = false;

function adminEnabled() { return !!CFG.adminToken; }

function checkAdminAuth(req) {
  if (!adminEnabled()) return false;
  const h = req.headers || {};
  let token = h['x-admin-token'] || h['X-Admin-Token'] || '';
  if (!token) {
    const auth = h['authorization'] || h['Authorization'] || '';
    if (typeof auth === 'string') {
      const m = auth.match(/^Bearer\s+(.+)$/i);
      if (m) token = m[1].trim();
    }
  }
  if (typeof token !== 'string' || !token) return false;
  return timingSafeEqualStr(CFG.adminToken, token);
}

function adminJSON(res, status, data) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function readAdminBody(req, limit = ADMIN_BODY_LIMIT) {
  return new Promise((resolvePromise, rejectPromise) => {
    let size = 0, done = false;
    const chunks = [];
    req.on('data', (c) => {
      if (done) return;
      size += c.length;
      if (size > limit) {
        done = true;
        req.destroy();
        rejectPromise(Object.assign(new Error('Payload too large'), { statusCode: 413 }));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolvePromise({});
      try { resolvePromise(JSON.parse(raw)); }
      catch { rejectPromise(Object.assign(new Error('Invalid JSON body'), { statusCode: 400 })); }
    });
    req.on('error', (e) => { if (!done) { done = true; rejectPromise(e); } });
  });
}

// 对外视图：apiKey 一律掩码
function accountView(a) {
  return {
    id: a.id, name: a.name, apiKey: maskKey(a.apiKey),
    enabled: a.enabled, weight: a.weight, priority: a.priority,
    maxInflight: a.maxInflight, tags: a.tags, notes: a.notes,
    createdAt: a.createdAt, updatedAt: a.updatedAt,
  };
}
// 对外视图：token 一律掩码（明文仅新建/轮换时一次性返回）
function clientView(c) {
  return {
    id: c.id, name: c.name, enabled: c.enabled, accountIds: c.accountIds,
    notes: c.notes, token: maskKey(c.token),
    createdAt: c.createdAt, updatedAt: c.updatedAt, lastUsedAt: c.lastUsedAt,
  };
}
function findAccountIndex(id) { return STORE.accounts.findIndex(a => a.id === id); }
function findClientIndex(id) { return STORE.clients.findIndex(c => c.id === id); }
function persistWarning() { return PERSISTENCE_OK ? {} : { warning: 'persistence disabled' }; }

// 校验 accountIds 白名单：null = 全部；数组则每个 id 必须存在
function validateAccountIds(v) {
  if (v === undefined || v === null) return { ok: true, value: null };
  if (!Array.isArray(v)) return { ok: false, error: 'accountIds must be an array or null' };
  const unknown = v.filter(x => findAccountIndex(String(x)) < 0);
  if (unknown.length) return { ok: false, error: 'Unknown account id(s): ' + unknown.join(', ') };
  return { ok: true, value: v.map(String) };
}

// ── Command Code 额度 / 用量（只读上游；只打 CFG.apiBase；永不回显 key） ──
// 端点与字段对齐官方 CLI（command-code dist/cli.mjs）：
//   GET /alpha/whoami?limits=1                → { org:{id,login}, user:{userName}, orgLimits:[...] }
//   GET /alpha/billing/credits?orgId=…        → { credits:{ planId, monthlyCredits, purchasedCredits, freeCredits, windowLimits, sandboxMinutes, sandboxAccess } }
//   GET /alpha/billing/subscriptions?orgId=…  → { data:{ planId, status, currentPeriodStart, currentPeriodEnd } }
//   GET /alpha/usage/summary?orgId=…&since=…  → { totalCost }
const USAGE_TTL_MS = 300000;   // 同一账号额度结果缓存 5 分钟，避免前端轮询把上游打爆
const USAGE_TIMEOUT_MS = 10000;
const USAGE_CONCURRENCY = 4;   // 批量拉取并发上限
const PLAN_TOTAL_CREDITS = {
  'individual-go': 10, 'individual-go-v1': 10, 'individual-goat': 70,
  'individual-pro': 30, 'individual-pro-v1': 80, 'individual-provider': 15,
  'individual-max': 150, 'individual-ultra': 300, 'teams-pro': 40,
};
const PLAN_NAMES = {
  'individual-go': 'Go', 'individual-go-v1': 'Go', 'individual-goat': 'GOAT',
  'individual-pro': 'Pro', 'individual-pro-v1': 'Pro', 'individual-provider': 'Provider',
  'individual-max': 'Max', 'individual-ultra': 'Ultra', 'teams-pro': 'Teams Pro',
};
const PLAN_KEYS = Object.keys(PLAN_TOTAL_CREDITS).sort((a, b) => b.length - a.length);
const usageCache = new Map();  // accountId → { at, view }
const usageInFlight = new Map();  // accountId → Promise

function planInfoOf(planId) {
  if (!planId || typeof planId !== 'string') return null;
  const norm = planId.toLowerCase().replace(/_/g, '-');
  const key = PLAN_KEYS.find(k => norm.startsWith(k));
  if (!key) return null;
  return { id: planId, name: PLAN_NAMES[key] || key, monthlyCredits: PLAN_TOTAL_CREDITS[key] };
}
function uNum(x) { const n = Number(x); return Number.isFinite(n) ? n : 0; }
function uDaysLeft(iso, now) {
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? Math.max(0, Math.ceil((t - now) / 86400000)) : null;
}
async function usageJSON(path, apiKey) {
  const resp = await upstreamFetch(CFG.apiBase + path, {
    headers: {
      'User-Agent': 'cli',
      'x-command-code-version': CC_VERSION,
      'x-cli-environment': 'production',
      'x-project-slug': CFG.projectSlug,
      'Authorization': 'Bearer ' + apiKey,
    },
    signal: AbortSignal.timeout(USAGE_TIMEOUT_MS),
  });
  if (!resp.ok) { const e = new Error('upstream_' + resp.status); e.status = resp.status; throw e; }
  return resp.json();
}
async function fetchAccountUsage(account) {
  const whoRaw = await usageJSON('/alpha/whoami?limits=1', account.apiKey);
  const who = whoRaw && whoRaw.data ? whoRaw.data : (whoRaw || {});
  const org = who.org || {};
  const q = org.id ? ('?orgId=' + encodeURIComponent(org.id)) : '';
  const [credRaw, subRaw] = await Promise.all([
    usageJSON('/alpha/billing/credits' + q, account.apiKey),
    usageJSON('/alpha/billing/subscriptions' + q, account.apiKey),
  ]);
  const creds = (credRaw && (credRaw.credits || (credRaw.data && credRaw.data.credits))) || {};
  const sub = (subRaw && (subRaw.data || subRaw)) || {};
  let summary = null;
  if (sub.currentPeriodStart) {
    try {
      const sRaw = await usageJSON(
        '/alpha/usage/summary' + q + (q ? '&' : '?') + 'since=' + encodeURIComponent(sub.currentPeriodStart),
        account.apiKey,
      );
      summary = sRaw && sRaw.data ? sRaw.data : sRaw;
    } catch { /* summary 缺失不影响其余额度展示 */ }
  }
  const now = Date.now();
  const plan = planInfoOf(creds.planId || sub.planId);
  const monthlyRemaining = Math.max(0, uNum(creds.monthlyCredits));
  const purchasedRemaining = Math.max(0, uNum(creds.purchasedCredits));
  const freeRemaining = Math.max(0, uNum(creds.freeCredits));
  const totalRemaining = monthlyRemaining + purchasedRemaining + freeRemaining;
  const totalSpent = Math.max(0, uNum(summary && summary.totalCost));
  const poolBase = (sub.status === 'active' && plan)
    ? Math.max(plan.monthlyCredits, monthlyRemaining)
    : totalSpent + totalRemaining;
  const totalPool = poolBase + purchasedRemaining + freeRemaining;
  return {
    ok: true,
    fetchedAt: new Date(now).toISOString(),
    whoami: { orgId: org.id || null, orgLogin: org.login || null, userName: (who.user && who.user.userName) || null },
    plan,
    subscription: { status: sub.status || null, currentPeriodStart: sub.currentPeriodStart || null, currentPeriodEnd: sub.currentPeriodEnd || null },
    daysLeft: sub.currentPeriodEnd ? uDaysLeft(sub.currentPeriodEnd, now) : null,
    credits: {
      monthlyRemaining, purchasedRemaining, freeRemaining,
      totalRemaining, totalSpent, totalPool,
      usagePercent: totalPool > 0 ? Math.min(1, Math.max(0, (totalPool - totalRemaining) / totalPool)) : 0,
      hasCreditsInfo: totalRemaining > 0 || totalSpent > 0,
      windowLimits: creds.windowLimits || null,
      sandboxMinutes: creds.sandboxMinutes !== undefined ? creds.sandboxMinutes : null,
      sandboxAccess: creds.sandboxAccess === true,
    },
    orgLimits: who.orgLimits || [],
  };
}
async function getAccountUsage(account, force) {
  const pending = usageInFlight.get(account.id);
  if (pending) return pending;
  const cached = usageCache.get(account.id);
  if (!force && cached && Date.now() - cached.at < USAGE_TTL_MS) return cached.view;
  const query = (async () => {
    let view;
    try {
      const data = await fetchAccountUsage(account);
      view = { id: account.id, name: account.name, enabled: account.enabled, ...data };
      const rt = getRuntime(account.id);
      const resetAt = creditResetAtOf(view);
      // 查询只补充套餐时间，不因余额变化解锁；已到期的周期交由选路解除。
      if (rt.creditExhausted && resetAt !== null
          && (rt.creditResetAt === null || rt.creditResetAt > Date.now())) {
        rt.creditResetAt = rt.creditResetAt === null ? resetAt : Math.max(rt.creditResetAt, resetAt);
        rt.cooldownUntil = rt.creditResetAt;
      }
    } catch (e) {
      const status = e && e.status;
      view = {
        id: account.id, name: account.name, enabled: account.enabled, ok: false,
        error: e && e.name === 'TimeoutError' ? 'timeout' : (status ? 'upstream_' + status : 'network_error'),
        fetchedAt: new Date().toISOString(),
      };
    }
    usageCache.set(account.id, { at: Date.now(), view });
    return view;
  })();
  usageInFlight.set(account.id, query);
  try {
    return await query;
  } finally {
    usageInFlight.delete(account.id);
  }
}
async function allAccountsUsage(force) {
  const items = STORE.accounts.slice();
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(USAGE_CONCURRENCY, items.length) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await getAccountUsage(items[idx], force); }
  });
  await Promise.all(workers);
  return out;
}

// 零机密 HTML 外壳：不需要令牌（令牌由前端弹框输入，仅存 sessionStorage）
// 转义纪律：内嵌 JS 一律单引号拼接，禁止反引号与 ${；DOM 一律 textContent/createElement，严禁 innerHTML。
function sendAdminShell(req, res) {
  const nonce = crypto.randomBytes(16).toString('base64');
  const html = `<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>CC Proxy Admin</title>
<style>
:root{
  --bg:#f5f5f7;--bg-sunken:#e9e9ee;--card:#ffffff;
  --line:#d6d6dc;--line-soft:#e9e9ee;
  --fg:#1d1d1f;--dim:#6e6e73;--mute:#8e8e93;
  --accent:#007aff;--accent-hover:#0a84ff;--accent-soft:rgba(0,122,255,.12);
  --ok:#34c759;--warn:#ff9500;--bad:#ff3b30;
  --r:14px;--r-sm:10px;--r-xs:8px;
  --shadow-sm:0 1px 2px rgba(0,0,0,.05),0 1px 3px rgba(0,0,0,.04);
  --shadow-md:0 4px 14px rgba(0,0,0,.08),0 1px 3px rgba(0,0,0,.05);
  --shadow-lg:0 20px 52px rgba(0,0,0,.20),0 6px 16px rgba(0,0,0,.08);
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --sans:-apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue","Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;font-family:var(--sans);font-size:13.5px;line-height:1.5;color:var(--fg);background:var(--bg);
  -webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;font-feature-settings:"tnum" 1}
::selection{background:rgba(0,122,255,.22)}
p{margin:0 0 12px}
::-webkit-scrollbar{width:12px;height:12px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(0,0,0,.18);border:3px solid transparent;border-radius:999px;background-clip:content-box}
::-webkit-scrollbar-thumb:hover{background:rgba(0,0,0,.3);border:3px solid transparent;background-clip:content-box}
header#bar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:14px;flex-wrap:wrap;
  padding:11px 20px;background:rgba(255,255,255,.72);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);
  border-bottom:1px solid var(--line-soft)}
.lights{display:flex;gap:8px;align-items:center;flex:none}
.lights i{display:block;width:12px;height:12px;border-radius:50%}
.lights i:nth-child(1){background:#ff5f57}
.lights i:nth-child(2){background:#febc2e}
.lights i:nth-child(3){background:#28c840}
.brand{display:flex;align-items:center;gap:8px;font-size:14px;font-weight:600;letter-spacing:-.01em;color:var(--fg)}
.brand .muted{font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--mute)}
.muted{color:var(--dim)}
.stats{display:flex;gap:8px;flex-wrap:wrap;font-size:12px}
.stat{display:inline-flex;align-items:center;gap:7px;background:#fff;border:1px solid var(--line-soft);border-radius:999px;padding:4px 11px;white-space:nowrap;box-shadow:0 1px 1px rgba(0,0,0,.03)}
.stat .sk{color:var(--mute);font-size:11px}
.stat b{color:var(--fg);font-weight:600;font-variant-numeric:tabular-nums}
.stat.bad{border-color:rgba(255,59,48,.4);background:rgba(255,59,48,.06)}
.stat.bad b{color:var(--bad)}
.spacer{flex:1}
nav#tabs{display:flex;gap:2px;flex-wrap:wrap;width:max-content;max-width:calc(100% - 40px);margin:16px 20px 0;padding:3px;background:var(--bg-sunken);border-radius:11px}
.tab{background:transparent;border:0;color:var(--dim);padding:6px 15px;border-radius:8px;cursor:pointer;font-size:13px;font-weight:500;font-family:inherit;transition:color .18s ease,background .18s ease,box-shadow .18s ease}
.tab:hover{color:var(--fg)}
.tab.active{background:#fff;color:var(--fg);box-shadow:0 1px 2px rgba(0,0,0,.10),0 0 0 .5px rgba(0,0,0,.04)}
main#view{padding:20px;max-width:1440px;margin:0 auto}
main#view .stats{margin:0 0 14px}
.section-head{display:flex;align-items:center;gap:12px;margin:0 0 14px}
.section-head h2{margin:0;font-size:17px;font-weight:600;letter-spacing:-.015em}
.section-head .btn{margin-left:auto}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px}
.card{position:relative;background:var(--card);border:1px solid var(--line-soft);border-radius:var(--r);padding:16px;box-shadow:var(--shadow-sm);transition:box-shadow .22s ease}
.card:hover{box-shadow:var(--shadow-md)}
.card::before{content:"";position:absolute;left:0;top:16px;bottom:16px;width:3px;border-radius:0 3px 3px 0;background:var(--line)}
.card.ok::before{background:var(--ok)}
.card.warn::before{background:var(--warn)}
.card.bad::before{background:var(--bad)}
.card.gray{opacity:.6}
.card h3{margin:0 0 8px;font-size:14.5px;font-weight:600;color:var(--fg);display:flex;align-items:center;gap:8px}
.badge{font-size:10.5px;font-weight:600;letter-spacing:.02em;padding:2px 9px;border-radius:999px;border:1px solid transparent}
.b-green{background:rgba(52,199,89,.14);color:#1d8a3a;border-color:rgba(52,199,89,.32)}
.b-yellow{background:rgba(255,149,0,.14);color:#a86500;border-color:rgba(255,149,0,.32)}
.b-red{background:rgba(255,59,48,.12);color:#c9271e;border-color:rgba(255,59,48,.28)}
.b-gray{background:rgba(0,0,0,.05);color:var(--dim);border-color:var(--line)}
.key{font-family:var(--mono);font-size:12px;color:var(--mute);word-break:break-all;margin:6px 0}
.rows{display:grid;grid-template-columns:1fr auto;gap:7px 14px;margin:12px 0;font-size:12.5px}
.rows .k{color:var(--dim)}
.rows .v{color:var(--fg);text-align:right;font-weight:500;font-variant-numeric:tabular-nums}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;align-items:center}
.btn{background:#fff;border:1px solid var(--line);color:var(--fg);padding:6px 14px;border-radius:var(--r-xs);cursor:pointer;font-size:13px;font-weight:500;font-family:inherit;line-height:1.35;box-shadow:0 1px 1px rgba(0,0,0,.04);transition:background .15s,border-color .15s,box-shadow .15s,transform .06s}
.btn:hover{background:#fafafa;border-color:#c6c6cd}
.btn:active{transform:scale(.975);background:#f0f0f3}
.btn:focus-visible{outline:0;box-shadow:0 0 0 3.5px var(--accent-soft)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff;box-shadow:0 1px 2px rgba(0,122,255,.32)}
.btn.primary:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
.btn.primary:active{background:#0069d9}
.btn.danger{color:var(--bad);border-color:rgba(255,59,48,.32)}
.btn.danger:hover{background:rgba(255,59,48,.07);border-color:rgba(255,59,48,.5)}
.btn.tiny{padding:4px 10px;font-size:12px}
input[type=text],input[type=number],input[type=password],select,textarea{background:#fff;border:1px solid var(--line);color:var(--fg);border-radius:var(--r-xs);padding:6px 10px;font-size:13px;font-family:inherit;width:100%;transition:border-color .15s,box-shadow .15s}
input[type=text]:focus,input[type=number]:focus,input[type=password]:focus,select:focus,textarea:focus{outline:0;border-color:var(--accent);box-shadow:0 0 0 3.5px var(--accent-soft)}
input[type=range]{width:100%;accent-color:var(--accent);padding:0;background:transparent;border:0;box-shadow:none}
select{appearance:none;-webkit-appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--mute) 50%),linear-gradient(135deg,var(--mute) 50%,transparent 50%);background-position:calc(100% - 15px) 13px,calc(100% - 10px) 13px;background-size:5px 5px,5px 5px;background-repeat:no-repeat;padding-right:30px}
label.field{display:block;margin-bottom:10px}
label.field>span{display:block;color:var(--dim);font-size:12px;margin-bottom:5px}
label.field .muted{font-size:11.5px}
.switch{display:flex;align-items:center;gap:8px;margin:6px 0;cursor:pointer}
.switch input{width:auto;accent-color:var(--accent)}
.table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--line-soft);border-radius:var(--r);background:var(--card);box-shadow:var(--shadow-sm)}
.table-wrap.plain{border:0;border-radius:0;background:transparent;box-shadow:none;margin-top:6px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{border-bottom:1px solid var(--line-soft);padding:9px 13px;text-align:left;vertical-align:middle}
tbody tr:last-child td{border-bottom:0}
tbody tr{transition:background .12s}
tbody tr:hover{background:rgba(0,0,0,.022)}
th{color:var(--mute);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em;background:#fafafa;white-space:nowrap}
td{font-variant-numeric:tabular-nums}
.bar{height:6px;background:#e6e6ea;border-radius:999px;overflow:hidden;display:inline-block;width:74px;vertical-align:middle}
.bar>i{display:block;height:100%;background:var(--ok);border-radius:999px;transition:width .4s ease}
.loading{display:flex;align-items:center;gap:10px;color:var(--dim);padding:12px 0}
.spin{width:14px;height:14px;border-radius:50%;border:2px solid var(--line);border-top-color:var(--accent);animation:spin .7s linear infinite;flex:none}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.28);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;z-index:50;padding:16px;animation:fade .18s ease}
.modal{background:#fff;border:1px solid rgba(0,0,0,.06);border-radius:18px;padding:22px;width:480px;max-width:96vw;max-height:88vh;overflow:auto;box-shadow:var(--shadow-lg);animation:pop .22s cubic-bezier(.2,.9,.3,1.12)}
.modal h2{margin:0 0 14px;font-size:16px;font-weight:600;letter-spacing:-.01em}
.err{color:var(--bad);font-size:12.5px;min-height:16px;margin:6px 0;word-break:break-word}
.toast-wrap{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:8px;z-index:60;pointer-events:none}
.toast{pointer-events:auto;background:rgba(255,255,255,.94);backdrop-filter:blur(20px) saturate(180%);-webkit-backdrop-filter:blur(20px) saturate(180%);border:1px solid rgba(0,0,0,.06);border-left:3px solid var(--accent);padding:11px 15px;border-radius:12px;font-size:13px;max-width:340px;box-shadow:var(--shadow-md);animation:slidein .24s cubic-bezier(.2,.9,.3,1.05)}
.toast.ok{border-left-color:var(--ok)}
.toast.err{border-left-color:var(--bad)}
.token-once{background:rgba(255,149,0,.07);border:1px solid rgba(255,149,0,.3);border-radius:12px;padding:12px;margin-top:10px}
.token-once code{display:block;font-family:var(--mono);font-size:12px;color:var(--fg);word-break:break-all;margin:8px 0}
#app[hidden]{display:none}
@keyframes fade{from{opacity:0}to{opacity:1}}
@keyframes pop{from{opacity:0;transform:translateY(8px) scale(.97)}to{opacity:1;transform:none}}
@keyframes slidein{from{opacity:0;transform:translateX(12px)}to{opacity:1;transform:none}}
@keyframes spin{to{transform:rotate(360deg)}}
@media (max-width:640px){
  header#bar{padding:10px 14px;gap:10px}
  nav#tabs{margin:12px 14px 0;max-width:calc(100% - 28px)}
  main#view{padding:14px}
  .brand .muted{display:none}
  .grid{grid-template-columns:1fr}
  .modal{width:100%;padding:18px}
}
@media (prefers-reduced-motion:reduce){
  *{animation-duration:.001ms!important;transition-duration:.001ms!important}
}
</style>
</head>
<body>
<div id="app" hidden>
  <header id="bar">
    <div class="lights" aria-hidden="true"><i></i><i></i><i></i></div>
    <div class="brand">CC Proxy <span class="muted">Admin</span></div>
    <div class="stats" id="stats"></div>
    <div class="spacer"></div>
    <button class="btn" id="logout">登出</button>
  </header>
  <nav id="tabs">
    <button class="tab" data-tab="accounts">账号</button>
    <button class="tab" data-tab="clients">客户端令牌</button>
    <button class="tab" data-tab="routing">路由配置</button>
    <button class="tab" data-tab="metrics">指标</button>
    <button class="tab" data-tab="usage">额度</button>
  </nav>
  <main id="view"></main>
</div>
<div class="toast-wrap" id="toasts"></div>
<script nonce="${nonce}">
(function(){
'use strict';
var TKEY='ccp_admin_token';
var token=sessionStorage.getItem(TKEY)||'';
var S={tab:'accounts',accounts:[],clients:[],routing:null,metrics:null,config:null,usage:null,usageLoading:false};

function byId(x){return document.getElementById(x);}
function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined&&text!==null)e.textContent=String(text);return e;}
function append(n){for(var i=1;i<arguments.length;i++){var c=arguments[i];if(c)n.appendChild(c);}return n;}
function clear(n){while(n.firstChild)n.removeChild(n.firstChild);}
function mkbtn(label,cls,fn){var b=el('button','btn'+(cls?(' '+cls):''),label);b.onclick=fn;return b;}
function loadingEl(text){var w=el('div','loading');append(w,el('span','spin'),el('span',null,text||'加载中…'));return w;}
function tableWrap(tbl,plain){var w=el('div','table-wrap'+(plain?' plain':''));w.appendChild(tbl);return w;}
function fmtDur(ms){ms=Number(ms)||0;var s=Math.floor(ms/1000);var d=Math.floor(s/86400);var h=Math.floor((s%86400)/3600);var m=Math.floor((s%3600)/60);var ss=s%60;if(d>0)return d+'d '+h+'h';if(h>0)return h+'h '+m+'m';if(m>0)return m+'m '+ss+'s';return ss+'s';}
function pct(x){if(x===null||x===undefined||!isFinite(x))return '—';return (x*100).toFixed(1)+'%';}
function msfmt(x){if(x===null||x===undefined||!isFinite(x)||x<=0)return '—';return Math.round(x)+'ms';}
function fmtTime(v){if(!v)return '—';var d=new Date(v);if(isNaN(d.getTime()))return '—';return d.toLocaleString();}
function toast(msg,kind){var t=el('div','toast '+(kind||''),msg);byId('toasts').appendChild(t);setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t);},3600);}

function api(path,opts){
  opts=opts||{};
  var headers={};
  if(opts.headers){for(var k in opts.headers)headers[k]=opts.headers[k];}
  if(token)headers['x-admin-token']=token;
  var body;
  if(opts.body!==undefined){body=typeof opts.body==='string'?opts.body:JSON.stringify(opts.body);headers['Content-Type']='application/json';}
  return fetch(path,{method:opts.method||'GET',headers:headers,body:body}).then(function(r){
    if(r.status===401){token='';try{sessionStorage.removeItem(TKEY);}catch(e){}var er=new Error('unauthorized');er.auth=true;throw er;}
    return r.text().then(function(txt){
      var j={};try{j=txt?JSON.parse(txt):{};}catch(e){j={};}
      if(!r.ok){var m=(j&&j.error&&j.error.message)||('HTTP '+r.status);var e2=new Error(m);e2.status=r.status;throw e2;}
      return j;
    });
  });
}
function post(path,body){return api(path,{method:'POST',body:body});}
function del(path){return api(path,{method:'DELETE'});}

function refresh(){
  if(!token){showAuth();return;}
  return Promise.all([
    api('/admin/api/accounts'),
    api('/admin/api/clients'),
    api('/admin/api/routing'),
    api('/admin/api/metrics'),
    api('/admin/api/config')
  ]).then(function(res){
    S.accounts=res[0].accounts||[];
    S.clients=res[1].clients||[];
    S.routing=res[2].routing||null;
    S.metrics=res[3]||null;
    S.config=res[4]||null;
    render();
  }).catch(function(e){
    if(e&&e.auth){showAuth();return;}
    toast('刷新失败：'+(e&&e.message?e.message:String(e)),'err');
  });
}

function showAuth(){
  if(byId('authbox'))return;
  byId('app').hidden=true;
  var ov=el('div','overlay');ov.id='authbox';
  var box=el('div','modal');
  append(box,el('h2',null,'管理后台登录'));
  append(box,el('p','muted','请输入 Admin Token（对应 CC_ADMIN_TOKEN）。令牌仅存于本会话 sessionStorage，不会落盘。'));
  var inp=el('input');inp.type='password';inp.placeholder='Admin Token';inp.value=token||'';
  append(box,inp);
  var err=el('div','err');
  append(box,err);
  var btn=mkbtn('连接','primary',function(){
    var t=inp.value.trim();
    if(!t){err.textContent='令牌不能为空';return;}
    token=t;try{sessionStorage.setItem(TKEY,token);}catch(e){}
    api('/admin/api/config').then(function(cfg){
      S.config=cfg;
      if(ov.parentNode)ov.parentNode.removeChild(ov);
      byId('app').hidden=false;
      toast('已连接','ok');
      refresh();
    }).catch(function(e){
      token='';try{sessionStorage.removeItem(TKEY);}catch(x){}
      err.textContent=(e&&e.auth)?'令牌无效':((e&&e.message)?e.message:'连接失败');
    });
  });
  inp.onkeydown=function(ev){if(ev.key==='Enter')btn.click();};
  append(box,btn);append(ov,box);document.body.appendChild(ov);
  setTimeout(function(){inp.focus();},30);
}
function logout(){token='';try{sessionStorage.removeItem(TKEY);}catch(e){}showAuth();}

function render(){renderStats();renderTabs();renderView();}

function stat(k,v){var s=el('span','stat');append(s,el('span','sk',k),el('b',null,String(v)));return s;}
function renderStats(){
  var w=byId('stats');clear(w);
  var m=S.metrics||{};var t=m.totals||{};
  append(w,stat('运行',fmtDur(m.uptimeMs)));
  append(w,stat('在途',(m.inflight||0)+(m.maxInflight>0?(' / '+m.maxInflight):' / ∞')));
  append(w,stat('账号',(t.enabledAccounts||0)+' 启用 / '+(t.accounts||0)));
  append(w,stat('健康',t.healthy||0));
  append(w,stat('冷却',t.cooling||0));
  append(w,stat('客户端',t.clients||0));
  var p=el('span','stat',m.persistence===false?'仅内存（持久化失败）':'持久化正常');
  if(m.persistence===false)p.className='stat bad';
  append(w,p);
}
function renderTabs(){
  var tabs=byId('tabs').children;
  for(var i=0;i<tabs.length;i++){
    if(tabs[i].getAttribute('data-tab')===S.tab)tabs[i].classList.add('active');
    else tabs[i].classList.remove('active');
  }
}
function renderView(){
  var v=byId('view');clear(v);
  if(S.tab==='accounts')renderAccounts(v);
  else if(S.tab==='clients')renderClients(v);
  else if(S.tab==='routing')renderRouting(v);
  else if(S.tab==='usage')renderUsage(v);
  else renderMetrics(v);
}
function metricOf(id){var a=S.metrics&&S.metrics.accounts;if(!a)return null;for(var i=0;i<a.length;i++)if(a[i].id===id)return a[i];return null;}
function healthOf(a,m){if(!a.enabled)return 'gray';if(m&&m.cooling)return 'red';if(m&&m.window&&m.window.n>=3&&(m.window.ok/m.window.n)<0.5)return 'yellow';return 'green';}
function badgeText(h){if(h==='green')return '健康';if(h==='yellow')return '降级';if(h==='red')return '冷却';return '禁用';}

function addRow(rows,k,v){rows.appendChild(el('span','k',k));rows.appendChild(el('span','v',v));}
function fieldInput(labelText,value,type){
  var l=el('label','field');append(l,el('span',null,labelText));
  var i=el('input');i.type=type||'text';i.value=(value===undefined||value===null)?'':String(value);
  append(l,i);return {el:l,inp:i};
}
function fieldTextarea(labelText,value){
  var l=el('label','field');append(l,el('span',null,labelText));
  var t=el('textarea');t.rows=3;t.value=(value===undefined||value===null)?'':String(value);
  append(l,t);return {el:l,inp:t};
}
function sliderField(labelText,value,min,max,step){
  var l=el('label','field');append(l,el('span',null,labelText));
  var i=el('input');i.type='range';i.min=String(min);i.max=String(max);i.step=String(step);i.value=String(value);
  var lbl=el('span','muted',String(value));
  i.addEventListener('input',function(){lbl.textContent=i.value;});
  append(l,i,lbl);return {el:l,inp:i};
}
function selectField(labelText,opts,value){
  var l=el('label','field');append(l,el('span',null,labelText));
  var s=el('select');
  opts.forEach(function(o){var op=el('option',null,o[1]);op.value=o[0];if(o[0]===value)op.selected=true;s.appendChild(op);});
  append(l,s);return {el:l,inp:s};
}
function confirmDelete(msg,onYes){
  var ov=el('div','overlay');var box=el('div','modal');
  append(box,el('h2',null,'请确认'),el('p',null,msg));
  var act=el('div','actions');
  act.appendChild(mkbtn('取消',null,function(){document.body.removeChild(ov);}));
  act.appendChild(mkbtn('确认删除','danger',function(){document.body.removeChild(ov);onYes();}));
  append(box,act);append(ov,box);document.body.appendChild(ov);
}

// ── 账号 Tab ───────────────────────────────────────
function renderAccounts(root){
  var head=el('div','section-head');
  append(head,el('h2',null,'账号池'));
  append(head,mkbtn('+ 新增账号','primary',function(){openAccountModal(null);}));
  root.appendChild(head);
  if(!S.accounts.length){root.appendChild(el('p','muted','暂无账号，点击右上角新增。'));return;}
  var grid=el('div','grid');
  S.accounts.forEach(function(a){grid.appendChild(accountCard(a,metricOf(a.id)));});
  root.appendChild(grid);
}
function accountCard(a,m){
  var h=healthOf(a,m);
  var c=el('div','card '+h);
  var hd=el('h3');append(hd,document.createTextNode(a.name),el('span','badge b-'+h,badgeText(h)));
  c.appendChild(hd);
  append(c,el('div','key',a.apiKey));
  var wl=el('label','field');append(wl,el('span',null,'权重 '+(a.weight!==undefined?a.weight:1)+'（×流量份额）'));
  var rng=el('input');rng.type='range';rng.min='0.1';rng.max='10';rng.step='0.1';rng.value=String(a.weight||1);
  rng.oninput=function(){wl.firstChild.textContent='权重 '+rng.value+'（×流量份额）';};
  rng.onchange=function(){patchAccount(a.id,{weight:Number(rng.value)});};
  append(wl,rng);c.appendChild(wl);
  var rows=el('div','rows');
  var wr=m&&m.window?m.window:null;
  var sr=wr&&wr.n>0?(wr.ok/wr.n):null;
  addRow(rows,'成功率',sr===null?'—':(pct(sr)+'（'+(wr?wr.n:0)+' 样本）'));
  addRow(rows,'EWMA TTFT',msfmt(m?m.ewmaTtftMs:0));
  addRow(rows,'平均 TTFT',msfmt(wr?wr.avgTtftMs:0));
  addRow(rows,'在途',String(m?m.inFlight:0));
  addRow(rows,'评分',(m&&m.score!==undefined)?m.score.toFixed(3):'—');
  addRow(rows,'冷却',(m&&m.cooling)?(m.creditResetUnknown?'套餐重置时间未知':('剩余 '+fmtDur(m.cooldownUntil-Date.now()))):'否');
  if(m&&m.creditExhausted)addRow(rows,'额度',m.creditResetAt?'耗尽（到套餐重置时间恢复：'+new Date(m.creditResetAt).toLocaleString()+'）':'耗尽（套餐重置时间未知，保持停用）');
  c.appendChild(rows);
  if(m&&m.lastError){append(c,el('div','key','最后错误: '+(m.lastError.status||'')+' '+(m.lastError.code||m.lastError.message||'')));}
  var sw=el('label','switch');var cb=el('input');cb.type='checkbox';cb.checked=!!a.enabled;
  cb.onchange=function(){patchAccount(a.id,{enabled:cb.checked});};
  append(sw,cb,el('span',null,a.enabled?'已启用':'已禁用'));c.appendChild(sw);
  var act=el('div','actions');
  append(act,mkbtn('编辑',null,function(){openAccountModal(a);}));
  append(act,mkbtn('测试',null,function(){testAccount(a,act);}));
  append(act,mkbtn('重置指标',null,function(){post('/admin/api/accounts/'+a.id+'/reset-metrics').then(function(){toast('指标已重置','ok');refresh();}).catch(function(e){toast('重置失败：'+(e&&e.message?e.message:String(e)),'err');});}));
  append(act,mkbtn('删除','danger',function(){confirmDelete('删除账号「'+a.name+'」？此操作不可撤销。',function(){del('/admin/api/accounts/'+a.id).then(function(){toast('已删除','ok');refresh();});});}));
  c.appendChild(act);
  return c;
}
function patchAccount(id,patch){
  return api('/admin/api/accounts/'+id,{method:'PATCH',body:patch}).then(function(){return refresh();})
    .catch(function(e){toast('更新失败：'+(e&&e.message?e.message:String(e)),'err');refresh();});
}
function testAccount(a,host){
  var line=el('div','key','测试中…');host.appendChild(line);
  api('/admin/api/accounts/'+a.id+'/test',{method:'POST'}).then(function(r){
    var txt='测试'+(r.ok?'通过':'失败')+' · HTTP '+r.status+' · '+r.elapsedMs+'ms';
    if(r.modelCount!==undefined)txt+=' · '+r.modelCount+' 个模型';
    if(r.error)txt+=' · '+r.error;
    line.textContent=txt;
    toast(r.ok?'测试通过':'测试失败',r.ok?'ok':'err');
  }).catch(function(e){line.textContent='测试请求失败：'+(e&&e.message?e.message:String(e));});
}
function openAccountModal(a){
  var isNew=!a;
  var ov=el('div','overlay');var box=el('div','modal');
  append(box,el('h2',null,isNew?'新增账号':'编辑账号'));
  var err=el('div','err');
  var fName=fieldInput('名称',a?a.name:'');
  var fKey=fieldInput(isNew?'API Key（user_...）':'API Key（留空则保持不变）','');
  var fWeight=fieldInput('权重（0.1–10）',a?(a.weight!==undefined?a.weight:1):1,'number');
  var fMax=fieldInput('最大并发 in-flight（0 = 不限）',a?a.maxInflight:0,'number');
  var fTags=fieldInput('标签（逗号分隔）',a&&a.tags?a.tags.join(', '):'');
  var fNotes=fieldTextarea('备注',a?a.notes:'');
  var fEn=el('label','switch');var cb=el('input');cb.type='checkbox';cb.checked=a?a.enabled!==false:true;append(fEn,cb,el('span',null,'启用'));
  append(box,fName.el,fKey.el,fWeight.el,fMax.el,fTags.el,fNotes.el,fEn,err);
  var act=el('div','actions');
  act.appendChild(mkbtn('取消',null,function(){document.body.removeChild(ov);}));
  act.appendChild(mkbtn(isNew?'创建':'保存','primary',function(){
    var body={};
    body.name=fName.inp.value.trim();
    if(fKey.inp.value.trim())body.apiKey=fKey.inp.value.trim();
    body.weight=Number(fWeight.inp.value);
    body.maxInflight=Number(fMax.inp.value);
    body.tags=fTags.inp.value.split(',').map(function(s){return s.trim();}).filter(Boolean);
    body.notes=fNotes.inp.value;
    body.enabled=cb.checked;
    if(isNew&&!body.apiKey){err.textContent='API Key 不能为空';return;}
    var p=isNew?post('/admin/api/accounts',body):api('/admin/api/accounts/'+a.id,{method:'PATCH',body:body});
    p.then(function(){document.body.removeChild(ov);toast(isNew?'账号已创建':'账号已更新','ok');refresh();})
     .catch(function(e){err.textContent=(e&&e.message)?e.message:'操作失败';});
  }));
  append(box,act);append(ov,box);document.body.appendChild(ov);
}

// ── 客户端令牌 Tab ─────────────────────────────────
function renderClients(root){
  var head=el('div','section-head');
  append(head,el('h2',null,'客户端令牌'));
  append(head,mkbtn('+ 新建令牌','primary',function(){openClientModal(null);}));
  root.appendChild(head);
  append(root,el('p','muted','客户端用 ccp_ 令牌访问代理；明文令牌仅在创建/轮换时显示一次，请立即保存。'));
  if(!S.clients.length){root.appendChild(el('p','muted','暂无客户端令牌。'));return;}
  var tbl=el('table');
  var thead=el('thead');var tr=el('tr');
  ['名称','令牌','状态','允许账号','最近使用','操作'].forEach(function(x){append(tr,el('th',null,x));});
  append(thead,tr);append(tbl,thead);
  var tb=el('tbody');
  S.clients.forEach(function(c){
    var r=el('tr');
    append(r,el('td',null,c.name),el('td','key',c.token),el('td',null,c.enabled?'启用':'禁用'));
    append(r,el('td',null,c.accountIds===null?'全部':(c.accountIds.length+' 个')));
    append(r,el('td',null,c.lastUsedAt?fmtTime(c.lastUsedAt):'—'));
    var ops=el('td');var av=el('div','actions');
    append(av,mkbtn('轮换','tiny',function(){rotateClient(c);}));
    append(av,mkbtn('编辑','tiny',function(){openClientModal(c);}));
    append(av,mkbtn('删除','tiny danger',function(){confirmDelete('删除令牌「'+c.name+'」？',function(){del('/admin/api/clients/'+c.id).then(function(){toast('已删除','ok');refresh();});});}));
    append(ops,av);append(r,ops);
    append(tb,r);
  });
  append(tbl,tb);root.appendChild(tableWrap(tbl));
}
function rotateClient(c){
  post('/admin/api/clients/'+c.id+'/rotate').then(function(res){
    if(res.client&&res.client.token)showTokenOnce(res.client.token,'令牌已轮换（仅显示一次）');
    refresh();
  }).catch(function(e){toast('轮换失败：'+(e&&e.message?e.message:String(e)),'err');});
}
function openClientModal(c){
  var isNew=!c;
  var ov=el('div','overlay');var box=el('div','modal');
  append(box,el('h2',null,isNew?'新建客户端令牌':'编辑客户端令牌'));
  var err=el('div','err');
  var fName=fieldInput('名称',c?c.name:'');
  var fEn=el('label','switch');var cb=el('input');cb.type='checkbox';cb.checked=c?c.enabled!==false:true;append(fEn,cb,el('span',null,'启用'));
  var allowAll=el('label','switch');var ca=el('input');ca.type='checkbox';ca.checked=c?(c.accountIds===null):true;
  append(allowAll,ca,el('span',null,'允许使用全部账号'));
  append(box,fName.el,fEn,allowAll,el('span','muted','指定账号白名单（取消勾选「全部账号」后生效）：'));
  var listBox=el('div');append(box,listBox);
  var checks=[];
  S.accounts.forEach(function(a){
    var l=el('label','switch');var k=el('input');k.type='checkbox';
    k.checked=!!(c&&Array.isArray(c.accountIds)&&c.accountIds.indexOf(a.id)>=0);
    k.disabled=ca.checked;
    append(l,k,el('span',null,a.name+'（'+a.id+'）'));
    listBox.appendChild(l);checks.push({id:a.id,input:k});
  });
  if(!S.accounts.length)append(listBox,el('p','muted','（暂无账号）'));
  ca.onchange=function(){checks.forEach(function(x){x.input.disabled=ca.checked;});};
  append(box,err);
  var act=el('div','actions');
  act.appendChild(mkbtn('取消',null,function(){document.body.removeChild(ov);}));
  act.appendChild(mkbtn(isNew?'创建':'保存','primary',function(){
    var body={name:fName.inp.value.trim(),enabled:cb.checked};
    if(ca.checked)body.accountIds=null;
    else body.accountIds=checks.filter(function(x){return x.input.checked;}).map(function(x){return x.id;});
    var p=isNew?post('/admin/api/clients',body):api('/admin/api/clients/'+c.id,{method:'PATCH',body:body});
    p.then(function(res){
      document.body.removeChild(ov);
      toast(isNew?'令牌已创建':'已更新','ok');
      if(isNew&&res.client&&res.client.token)showTokenOnce(res.client.token,'新令牌（仅显示一次）');
      refresh();
    }).catch(function(e){err.textContent=(e&&e.message)?e.message:'操作失败';});
  }));
  append(box,act);append(ov,box);document.body.appendChild(ov);
}
function showTokenOnce(tk,title){
  var ov=el('div','overlay');var box=el('div','modal');
  append(box,el('h2',null,title||'令牌'));
  append(box,el('p',null,'请立即复制保存。关闭后将无法再次查看明文。'));
  var sec=el('div','token-once');append(sec,el('code',null,tk));append(box,sec);
  var act=el('div','actions');
  act.appendChild(mkbtn('复制',null,function(){
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(tk).then(function(){toast('已复制','ok');},function(){toast('复制失败，请手动选择','err');});}
    else toast('请手动选择复制','err');
  }));
  act.appendChild(mkbtn('我已保存','primary',function(){document.body.removeChild(ov);}));
  append(box,act);append(ov,box);document.body.appendChild(ov);
}

// ── 路由配置 Tab ───────────────────────────────────
function renderRouting(root){
  var head=el('div','section-head');append(head,el('h2',null,'路由配置'));root.appendChild(head);
  var R=S.routing||{};
  var W=R.weights||{successRate:0.5,latency:0.3,load:0.2};
  append(root,el('p','muted','评分：score = (wS·成功率 + wL·延迟 + wC·负载) × 账号权重因子。修改后立即热生效（无需重启）。'));
  var card=el('div','card');
  var wRow=el('div','grid');
  var sS=sliderField('成功率权重',W.successRate,0,100,1);
  var sL=sliderField('延迟权重',W.latency,0,100,1);
  var sC=sliderField('负载权重',W.load,0,100,1);
  append(wRow,sS.el,sL.el,sC.el);append(card,wRow);
  var norm=el('div','muted');append(card,norm);
  var g=el('div','grid');
  var pSel=selectField('选择策略',[['weighted_random','加权随机（轮盘赌）'],['best','严格最优（best）']],R.selection||'weighted_random');
  var pWin=fieldInput('窗口 windowSizeMs',R.windowSizeMs||300000,'number');
  var pAlpha=fieldInput('先验 priorAlpha',R.priorAlpha!==undefined?R.priorAlpha:5,'number');
  var pPsr=fieldInput('先验成功率 priorSuccessRate',R.priorSuccessRate!==undefined?R.priorSuccessRate:0.8,'number');
  var pEwma=fieldInput('EWMA 系数 latencyEwmaAlpha',R.latencyEwmaAlpha!==undefined?R.latencyEwmaAlpha:0.3,'number');
  var pFloor=fieldInput('延迟下限 latencyFloorMs',R.latencyFloorMs||400,'number');
  var pCeil=fieldInput('延迟上限 latencyCeilMs',R.latencyCeilMs||60000,'number');
  var pUnk=fieldInput('无样本延迟分 unknownLatencyScore',R.unknownLatencyScore!==undefined?R.unknownLatencyScore:0.5,'number');
  var pRef=fieldInput('负载参考 loadReference',R.loadReference||4,'number');
  var pCb=fieldInput('冷却基数 cooldownBaseMs',R.cooldownBaseMs||30000,'number');
  var pCm=fieldInput('冷却上限 cooldownMaxMs',R.cooldownMaxMs||300000,'number');
  var pTh=fieldInput('连续失败阈值 failureCooldownThreshold',R.failureCooldownThreshold||3,'number');
  var pCf=fieldInput('额度换号上限 creditFailoverMax',R.creditFailoverMax!==undefined?R.creditFailoverMax:3,'number');
  var pCu=fieldInput('额度兜底阈值 creditUsageThreshold',R.creditUsageThreshold!==undefined?R.creditUsageThreshold:0.95,'number');
  [pSel.el,pWin.el,pAlpha.el,pPsr.el,pEwma.el,pFloor.el,pCeil.el,pUnk.el,pRef.el,pCb.el,pCm.el,pTh.el,pCf.el,pCu.el].forEach(function(x){g.appendChild(x);});
  append(card,g);
  append(card,el('h3',null,'策略预览（按当前滑杆值实时计算）'));
  var prevBox=el('div');append(card,prevBox);
  var err=el('div','err');append(card,err);
  var act=el('div','actions');
  act.appendChild(mkbtn('保存路由配置','primary',function(){
    var body={
      selection:pSel.inp.value,
      windowSizeMs:Number(pWin.inp.value),
      priorAlpha:Number(pAlpha.inp.value),
      priorSuccessRate:Number(pPsr.inp.value),
      latencyEwmaAlpha:Number(pEwma.inp.value),
      latencyFloorMs:Number(pFloor.inp.value),
      latencyCeilMs:Number(pCeil.inp.value),
      unknownLatencyScore:Number(pUnk.inp.value),
      loadReference:Number(pRef.inp.value),
      cooldownBaseMs:Number(pCb.inp.value),
      cooldownMaxMs:Number(pCm.inp.value),
      failureCooldownThreshold:Number(pTh.inp.value),
      creditFailoverMax:Number(pCf.inp.value),
      creditUsageThreshold:Number(pCu.inp.value),
      weights:{successRate:Number(sS.inp.value)/100,latency:Number(sL.inp.value)/100,load:Number(sC.inp.value)/100}
    };
    api('/admin/api/routing',{method:'PUT',body:body}).then(function(){toast('路由配置已更新','ok');refresh();})
      .catch(function(e){err.textContent=(e&&e.message)?e.message:'保存失败';});
  }));
  append(card,act);
  root.appendChild(card);
  function updatePreview(){
    var ws=Number(sS.inp.value),wl=Number(sL.inp.value),wc=Number(sC.inp.value);
    var sum=ws+wl+wc;
    norm.textContent='归一化权重：成功率 '+(sum>0?(ws/sum*100).toFixed(1):'0')+'% · 延迟 '+(sum>0?(wl/sum*100).toFixed(1):'0')+'% · 负载 '+(sum>0?(wc/sum*100).toFixed(1):'0')+'%';
    clear(prevBox);
    var acc=(S.metrics&&S.metrics.accounts)||[];
    var maxW=0;acc.forEach(function(a){if(a.enabled&&a.weight>maxW)maxW=a.weight;});
    var tbl=el('table');var thead=el('thead');var tr=el('tr');
    ['账号','成功率S','延迟L','负载C','权重因子','评分','状态'].forEach(function(x){append(tr,el('th',null,x));});
    append(thead,tr);append(tbl,thead);
    var tb=el('tbody');
    acc.forEach(function(a){
      var cp=a.components||{};
      var s=sum>0?sum:1;
      var base=(ws/s)*(cp.success||0)+(wl/s)*(cp.latency||0)+(wc/s)*(cp.load||0);
      var wf=maxW>0?(a.weight/maxW):1;
      var sc=a.cooling?0:base*wf;
      var r=el('tr');
      append(r,el('td',null,a.name));
      append(r,el('td',null,(cp.success!==undefined?cp.success:0).toFixed(3)));
      append(r,el('td',null,(cp.latency!==undefined?cp.latency:0).toFixed(3)));
      append(r,el('td',null,(cp.load!==undefined?cp.load:0).toFixed(3)));
      append(r,el('td',null,wf.toFixed(2)));
      append(r,el('td',null,sc.toFixed(3)));
      append(r,el('td',null,a.cooling?'冷却':(a.enabled?'正常':'禁用')));
      append(tb,r);
    });
    append(tbl,tb);prevBox.appendChild(tableWrap(tbl,true));
  }
  sS.inp.addEventListener('input',updatePreview);
  sL.inp.addEventListener('input',updatePreview);
  sC.inp.addEventListener('input',updatePreview);
  updatePreview();
}

// ── 指标 Tab ───────────────────────────────────────
function renderMetrics(root){
  var head=el('div','section-head');append(head,el('h2',null,'指标'));root.appendChild(head);
  var m=S.metrics;
  if(!m){append(root,loadingEl('加载指标…'));return;}
  var t=m.totals||{};
  var sum=el('div','stats');
  append(sum,stat('账号',t.accounts||0),stat('启用',t.enabledAccounts||0),stat('健康',t.healthy||0),stat('冷却',t.cooling||0));
  append(sum,stat('全局在途',m.inflight||0));
  append(sum,stat('上游重试',(m.upstreamRetryStats?m.upstreamRetryStats.rewinds:0)+' 次 / 恢复 '+(m.upstreamRetryStats?m.upstreamRetryStats.recovered:0)));
  root.appendChild(sum);
  var tbl=el('table');var thead=el('thead');var tr=el('tr');
  ['账号','状态','成功率','平均TTFT','EWMA','在途','请求','成功','失败','中性','重试','评分'].forEach(function(x){append(tr,el('th',null,x));});
  append(thead,tr);append(tbl,thead);
  var tb=el('tbody');
  (m.accounts||[]).forEach(function(a){
    var w=a.window||{};var sr=w.n>0?(w.ok/w.n):null;
    var r=el('tr');
    append(r,el('td',null,a.name),el('td',null,a.cooling?'冷却':(a.enabled?'正常':'禁用')));
    var td=el('td');var bar=el('div','bar');var fill=el('i');
    fill.style.width=(sr===null?'0':(Math.round(sr*100)+'%'));
    if(sr!==null&&sr<0.5)fill.style.background='#f85149';
    else if(sr!==null&&sr<0.8)fill.style.background='#d29922';
    append(bar,fill);append(td,bar,document.createTextNode(' '+(sr===null?'—':pct(sr))));append(r,td);
    append(r,el('td',null,msfmt(w.avgTtftMs)),el('td',null,msfmt(a.ewmaTtftMs)),el('td',null,String(a.inFlight)));
    var tt=a.totals||{};
    append(r,el('td',null,String(tt.requests||0)),el('td',null,String(tt.ok||0)),el('td',null,String(tt.fail||0)));
    append(r,el('td',null,String(tt.neutral||0)),el('td',null,String(tt.retried||0)));
    append(r,el('td',null,(a.score!==undefined)?a.score.toFixed(3):'—'));
    append(tb,r);
  });
  append(tbl,tb);root.appendChild(tableWrap(tbl));
}

function usageMoney(v){return (v===null||v===undefined||!isFinite(v))?'—':('$'+Number(v).toFixed(2));}
function usageBar(percent){
  var bar=el('div','bar');var fill=el('i');var p=percent||0;
  fill.style.width=(Math.round(p*100)+'%');
  if(p>=0.9)fill.style.background='#f85149';
  else if(p>=0.7)fill.style.background='#d29922';
  append(bar,fill);return bar;
}
function loadUsage(force){
  if(S.usageLoading)return Promise.resolve();
  S.usageLoading=true;
  return api('/admin/api/usage'+(force?'?refresh=1':'')).then(function(j){
    S.usage=j.usage||[];S.usageLoading=false;
    if(S.tab==='usage')renderView();
    if(force)toast('额度已刷新','ok');
  }).catch(function(e){
    S.usageLoading=false;
    if(e&&e.auth){showAuth();return;}
    toast('额度加载失败：'+(e&&e.message?e.message:String(e)),'err');
  });
}
function renderUsage(root){
  var head=el('div','section-head');
  append(head,el('h2',null,'Command Code 额度'));
  append(head,mkbtn('刷新','',function(){loadUsage(true);}));
  root.appendChild(head);
  append(root,el('p','muted','直接读取上游 /alpha/whoami 与 /alpha/billing/*，每账号缓存 5 分钟；账号 key 全程不外泄。'));
  if(!S.usage){
    append(root,loadingEl('加载额度…'));
    if(!S.usageLoading)loadUsage(false);
    return;
  }
  if(S.usage.length===0){append(root,el('p','muted','还没有账号。'));return;}
  var tbl=el('table');var thead=el('thead');var tr=el('tr');
  ['账号','套餐','状态','剩余','已用','总额','用量','到期','更新时间'].forEach(function(x){append(tr,el('th',null,x));});
  append(thead,tr);append(tbl,thead);
  var tb=el('tbody');
  S.usage.forEach(function(u){
    var r=el('tr');
    append(r,el('td',null,u.name||u.id));
    if(!u.ok){
      var td=el('td');td.colSpan=8;td.className='muted';
      td.textContent='读取失败：'+(u.error||'unknown');
      append(r,td);append(tb,r);return;
    }
    append(r,el('td',null,u.plan?u.plan.name:'—'));
    append(r,el('td',null,(u.subscription&&u.subscription.status)?u.subscription.status:'—'));
    var c=u.credits||{};
    var tdRem=el('td');
    append(tdRem,el('b',null,usageMoney(c.totalRemaining)),
      el('div','muted','月 '+usageMoney(c.monthlyRemaining)+' · 充值 '+usageMoney(c.purchasedRemaining)+' · 免费 '+usageMoney(c.freeRemaining)));
    append(r,tdRem);
    append(r,el('td',null,usageMoney(c.totalSpent)));
    append(r,el('td',null,usageMoney(c.totalPool)));
    var tdPct=el('td');
    append(tdPct,usageBar(c.usagePercent),document.createTextNode(' '+pct(c.usagePercent)));
    append(r,tdPct);
    append(r,el('td',null,(typeof u.daysLeft==='number')?(u.daysLeft+' 天'):'—'));
    append(r,el('td',null,fmtTime(u.fetchedAt)));
    append(tb,r);
  });
  append(tbl,tb);root.appendChild(tableWrap(tbl));
}

function boot(){
  byId('logout').onclick=logout;
  var tabs=byId('tabs').children;
  for(var i=0;i<tabs.length;i++){
    (function(b){b.onclick=function(){S.tab=b.getAttribute('data-tab');renderTabs();renderView();};})(tabs[i]);
  }
  setInterval(function(){if(token&&!document.hidden)refresh();},2000);
  document.addEventListener('visibilitychange',function(){if(token&&!document.hidden)refresh();});
  if(token){byId('app').hidden=false;refresh();}
  else showAuth();
}
boot();
})();
</script>
</body>
</html>`;
  res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-" + nonce + "'; connect-src 'self'; img-src 'self' data:");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store');
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

async function handleAdmin(req, res, url) {
  // 未配置令牌：admin 路径一律 404（不暴露存在），启动后仅告警一次
  if (!adminEnabled()) {
    if (!ADMIN_DISABLED_WARNED) {
      ADMIN_DISABLED_WARNED = true;
      log('warn', 'Admin API disabled (set CC_ADMIN_TOKEN to enable /admin)');
    }
    sendJSON(res, 404, { error: { message: 'Not found', type: 'not_found' } });
    return;
  }

  const pathname = url.pathname;
  if (pathname === '/admin' || pathname === '/admin/') {
    if (req.method !== 'GET') {
      adminJSON(res, 405, { error: { message: 'Method not allowed', type: 'method_not_allowed' } });
      return;
    }
    sendAdminShell(req, res);
    return;
  }

  if (!pathname.startsWith('/admin/api/')) {
    sendJSON(res, 404, { error: { message: 'Not found', type: 'not_found' } });
    return;
  }

  if (!checkAdminAuth(req)) {
    adminJSON(res, 401, { error: { message: 'Unauthorized', type: 'unauthorized' } });
    return;
  }

  const segs = pathname.slice('/admin/api/'.length).split('/').filter(Boolean);
  const method = req.method;
  const fail = (status, message, type = 'error') => adminJSON(res, status, { error: { message, type } });

  let bodyCache = null;
  const getBody = async () => { if (bodyCache === null) bodyCache = await readAdminBody(req); return bodyCache; };

  try {
    // ── /admin/api/accounts ─────────────────────────────
    if (segs[0] === 'accounts' && segs.length === 1) {
      if (method === 'GET') {
        return adminJSON(res, 200, {
          accounts: STORE.accounts.map(accountView),
          routing: STORE.routing,
          limits: { maxAccounts: MAX_ACCOUNTS },
          ...persistWarning(),
        });
      }
      if (method === 'POST') {
        const body = await getBody();
        const apiKey = typeof body.apiKey === 'string' ? body.apiKey.trim() : '';
        if (!apiKey) return fail(400, 'apiKey is required', 'invalid_request');
        if (STORE.accounts.length >= MAX_ACCOUNTS) return fail(409, 'Account limit reached (' + MAX_ACCOUNTS + ')', 'limit_reached');
        const nowIso = new Date().toISOString();
        const account = normalizeAccount({ ...body, id: newId('acc_'), apiKey, createdAt: nowIso, updatedAt: nowIso });
        STORE.accounts.push(account);
        getRuntime(account.id);
        persistAccounts();
        log('info', 'Admin: account added', { accountId: account.id, name: account.name });
        return adminJSON(res, 201, { account: accountView(account), ...persistWarning() });
      }
      return fail(405, 'Method not allowed', 'method_not_allowed');
    }

    // ── /admin/api/accounts/:id[/test|/reset-metrics] ───
    if (segs[0] === 'accounts' && segs.length >= 2) {
      const id = segs[1];
      const idx = findAccountIndex(id);
      if (idx < 0) return fail(404, 'Account not found', 'not_found');

      if (segs.length === 2) {
        if (method === 'GET') return adminJSON(res, 200, { account: accountView(STORE.accounts[idx]) });
        if (method === 'PATCH') {
          const body = await getBody();
          const merged = { ...STORE.accounts[idx] };
          if (body.name !== undefined) merged.name = body.name;
          if (body.apiKey !== undefined) {
            if (typeof body.apiKey !== 'string' || !body.apiKey.trim()) return fail(400, 'apiKey must be a non-empty string', 'invalid_request');
            merged.apiKey = body.apiKey.trim();
          }
          if (body.enabled !== undefined) merged.enabled = body.enabled !== false;
          if (body.weight !== undefined) merged.weight = body.weight;
          if (body.priority !== undefined) merged.priority = body.priority;
          if (body.maxInflight !== undefined) merged.maxInflight = body.maxInflight;
          if (body.tags !== undefined) merged.tags = body.tags;
          if (body.notes !== undefined) merged.notes = body.notes;
          merged.updatedAt = new Date().toISOString();
          const next = normalizeAccount(merged);
          STORE.accounts[idx] = next;
          usageCache.delete(next.id);   // key/名称变化后额度需重取
          persistAccounts();
          return adminJSON(res, 200, { account: accountView(next), ...persistWarning() });
        }
        if (method === 'DELETE') {
          const removed = STORE.accounts.splice(idx, 1)[0];
          runtime.delete(removed.id);
          usageCache.delete(removed.id);
          // 同步从所有 client 白名单剔除，避免指向已删账号
          for (const c of STORE.clients) {
            if (Array.isArray(c.accountIds)) c.accountIds = c.accountIds.filter(x => x !== removed.id);
          }
          persistAccounts();
          log('info', 'Admin: account removed', { accountId: removed.id, name: removed.name });
          return adminJSON(res, 200, { ok: true, id: removed.id, ...persistWarning() });
        }
        return fail(405, 'Method not allowed', 'method_not_allowed');
      }

      if (segs.length === 3 && segs[2] === 'test' && method === 'POST') {
        // 防 SSRF：只打 CFG.apiBase，不接受任何 URL 参数；不回显响应体与 key
        const account = STORE.accounts[idx];
        const startedAt = Date.now();
        try {
          const resp = await fetch(CFG.apiBase + '/provider/v1/models', {
            headers: {
              'Authorization': 'Bearer ' + account.apiKey,
              'x-cli-environment': 'production',
              'x-command-code-version': CC_VERSION,
            },
            signal: AbortSignal.timeout(10000),
          });
          let modelCount;
          try {
            const data = await resp.json();
            if (data && Array.isArray(data.data)) modelCount = data.data.length;
          } catch {}
          const out = { ok: resp.ok, status: resp.status, elapsedMs: Date.now() - startedAt };
          if (modelCount !== undefined) out.modelCount = modelCount;
          return adminJSON(res, 200, out);
        } catch (e) {
          return adminJSON(res, 200, {
            ok: false, status: 0, elapsedMs: Date.now() - startedAt,
            error: e && e.name === 'TimeoutError' ? 'timeout' : 'network_error',
          });
        }
      }

      if (segs.length === 3 && segs[2] === 'reset-metrics' && method === 'POST') {
        resetRuntime(STORE.accounts[idx].id);
        return adminJSON(res, 200, { ok: true, id: STORE.accounts[idx].id });
      }

      if (segs.length === 3 && segs[2] === 'usage' && method === 'GET') {
        // 只读上游额度；?refresh=1 强制绕过 5 分钟缓存
        const view = await getAccountUsage(STORE.accounts[idx], url.searchParams.get('refresh') === '1');
        return adminJSON(res, 200, { usage: view });
      }
      return fail(404, 'Not found', 'not_found');
    }

    // ── /admin/api/clients ──────────────────────────────
    if (segs[0] === 'clients' && segs.length === 1) {
      if (method === 'GET') {
        return adminJSON(res, 200, {
          clients: STORE.clients.map(clientView),
          limits: { maxClients: MAX_CLIENTS, maxAccounts: MAX_ACCOUNTS },
          ...persistWarning(),
        });
      }
      if (method === 'POST') {
        const body = await getBody();
        if (STORE.clients.length >= MAX_CLIENTS) return fail(409, 'Client limit reached (' + MAX_CLIENTS + ')', 'limit_reached');
        const ids = validateAccountIds(body.accountIds);
        if (!ids.ok) return fail(400, ids.error, 'invalid_request');
        const nowIso = new Date().toISOString();
        const client = normalizeClient({
          id: newId('cli_'), name: body.name, enabled: body.enabled,
          accountIds: ids.value, notes: body.notes, token: newClientToken(),
          createdAt: nowIso, updatedAt: nowIso,
        });
        STORE.clients.push(client);
        persistAccounts();
        log('info', 'Admin: client added', { clientId: client.id, name: client.name });
        // 明文令牌仅此一次返回
        return adminJSON(res, 201, { client: { ...clientView(client), token: client.token }, ...persistWarning() });
      }
      return fail(405, 'Method not allowed', 'method_not_allowed');
    }

    // ── /admin/api/clients/:id[/rotate] ─────────────────
    if (segs[0] === 'clients' && segs.length >= 2) {
      const id = segs[1];
      const idx = findClientIndex(id);
      if (idx < 0) return fail(404, 'Client not found', 'not_found');

      if (segs.length === 2) {
        if (method === 'GET') return adminJSON(res, 200, { client: clientView(STORE.clients[idx]) });
        if (method === 'PATCH') {
          const body = await getBody();
          const merged = { ...STORE.clients[idx] };
          if (body.name !== undefined) merged.name = body.name;
          if (body.enabled !== undefined) merged.enabled = body.enabled !== false;
          if (body.notes !== undefined) merged.notes = body.notes;
          if (body.accountIds !== undefined) {
            const ids = validateAccountIds(body.accountIds);
            if (!ids.ok) return fail(400, ids.error, 'invalid_request');
            merged.accountIds = ids.value;
          }
          merged.updatedAt = new Date().toISOString();
          const next = normalizeClient(merged);
          STORE.clients[idx] = next;
          persistAccounts();
          return adminJSON(res, 200, { client: clientView(next), ...persistWarning() });
        }
        if (method === 'DELETE') {
          const removed = STORE.clients.splice(idx, 1)[0];
          persistAccounts();
          log('info', 'Admin: client removed', { clientId: removed.id, name: removed.name });
          return adminJSON(res, 200, { ok: true, id: removed.id, ...persistWarning() });
        }
        return fail(405, 'Method not allowed', 'method_not_allowed');
      }

      if (segs.length === 3 && segs[2] === 'rotate' && method === 'POST') {
        const client = STORE.clients[idx];
        client.token = newClientToken();
        client.updatedAt = new Date().toISOString();
        persistAccounts();
        log('info', 'Admin: client token rotated', { clientId: client.id, name: client.name });
        return adminJSON(res, 200, { client: { ...clientView(client), token: client.token }, ...persistWarning() });
      }
      return fail(404, 'Not found', 'not_found');
    }

    // ── /admin/api/routing ──────────────────────────────
    if (segs[0] === 'routing' && segs.length === 1) {
      if (method === 'GET') return adminJSON(res, 200, { routing: STORE.routing });
      if (method === 'PUT') {
        const body = await getBody();
        if (body.weights && typeof body.weights === 'object') {
          const cur = STORE.routing.weights;
          const sum = Number(body.weights.successRate ?? cur.successRate)
            + Number(body.weights.latency ?? cur.latency)
            + Number(body.weights.load ?? cur.load);
          if (!(sum > 0)) return fail(400, 'routing weights must sum to a positive value', 'invalid_request');
        }
        const next = applyRouting(body);   // 字段级 merge + 原地赋值（热生效，不换引用）
        persistAccounts();
        return adminJSON(res, 200, { routing: next, ...persistWarning() });
      }
      return fail(405, 'Method not allowed', 'method_not_allowed');
    }

    // ── /admin/api/usage ────────────────────────────────
    if (segs[0] === 'usage' && segs.length === 1 && method === 'GET') {
      const force = url.searchParams.get('refresh') === '1';
      const usage = await allAccountsUsage(force);
      return adminJSON(res, 200, { usage, ttlMs: USAGE_TTL_MS, fetchedAt: new Date().toISOString() });
    }

    // ── /admin/api/metrics ──────────────────────────────
    if (segs[0] === 'metrics' && segs.length === 1 && method === 'GET') {
      const now = Date.now();
      const routing = STORE.routing;
      const enabledAccounts = STORE.accounts.filter(a => a.enabled);
      const maxWeight = enabledAccounts.reduce((m, a) => Math.max(m, a.weight), 0);
      let healthy = 0, cooling = 0;
      const accounts = STORE.accounts.map(a => {
        const r = getRuntime(a.id);
        const st = windowStats(r, now, routing);
        const { score, components } = scoreAccount(a, r, now, routing, maxWeight);
        if (a.enabled) { if (r.creditExhausted || r.cooldownUntil > now) cooling++; else healthy++; }
        return {
          id: a.id, name: a.name, enabled: a.enabled, weight: a.weight,
          score, components,
          totals: { ...r.totals },
          window: { ok: st.ok, fail: st.fail, n: st.n, avgTtftMs: st.ttftCount > 0 ? st.ttftSum / st.ttftCount : null },
          inFlight: r.inFlight,
          consecutiveFailures: r.consecutiveFailures,
          cooldownUntil: r.cooldownUntil,
          cooling: r.creditExhausted || r.cooldownUntil > now,
          creditExhausted: !!r.creditExhausted,
          creditResetAt: r.creditResetAt,
          creditBlocked: !!r.creditExhausted,
          creditResetUnknown: !!r.creditExhausted && r.creditResetAt === null,
          ewmaTtftMs: r.ewmaTtftMs,
          lastLatencyMs: r.lastLatencyMs,
          lastError: r.lastError,
        };
      });
      return adminJSON(res, 200, {
        uptimeMs: Date.now() - SERVER_STARTED_AT,
        startedAt: new Date(SERVER_STARTED_AT).toISOString(),
        inflight: inflightCount,
        maxInflight: MAX_INFLIGHT,
        upstreamRetryStats: { ...upstreamRetryStats },
        persistence: PERSISTENCE_OK,
        totals: {
          accounts: STORE.accounts.length,
          clients: STORE.clients.length,
          enabledAccounts: enabledAccounts.length,
          disabledAccounts: STORE.accounts.length - enabledAccounts.length,
          healthy, cooling,
        },
        routing,
        accounts,
      });
    }

    // ── /admin/api/config ───────────────────────────────
    if (segs[0] === 'config' && segs.length === 1 && method === 'GET') {
      return adminJSON(res, 200, {
        port: CFG.port, host: CFG.host, apiBase: CFG.apiBase,
        projectSlug: CFG.projectSlug, logLevel: CFG.logLevel,
        useProviderModels: CFG.useProviderModels, zdr: CFG.zdr,
        upstreamProxy: !!CFG.upstreamProxy,
        adminEnabled: true, persistence: PERSISTENCE_OK,
        accountsFile: CFG.accountsFile,
        limits: { maxAccounts: MAX_ACCOUNTS, maxClients: MAX_CLIENTS },
        version: STORE.version,
      });
    }

    return fail(404, 'Not found', 'not_found');
  } catch (e) {
    const status = e && e.statusCode ? e.statusCode : 500;
    if (status >= 500) log('error', 'Admin API error', { method, path: pathname, error: e && e.message });
    return fail(status, status >= 500 ? 'Internal error' : (e && e.message ? e.message : 'error'), status >= 500 ? 'internal_error' : 'invalid_request');
  }
}

// ── 服务器 ──────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const host = req.headers.host || 'localhost';
  const url = new URL(req.url, `http://${host}`);
  const isAdminPath = url.pathname === '/admin' || url.pathname.startsWith('/admin/');

  // CORS：仅数据面发 ACAO:*。管理面同源自定义头不触发预检，避免引入 CSRF 面。
  if (!isAdminPath) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PATCH, DELETE');
    res.setHeader('Access-Control-Allow-Headers', '*');
  }
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // 在途上限准入。/health、/ 与 admin 路径例外：探活/编排器/后台救火不该因业务繁忙而收 503。
  const isLiveness = url.pathname === '/health' || url.pathname === '/' || isAdminPath;
  if (!isLiveness) {
    if (MAX_INFLIGHT > 0 && inflightCount >= MAX_INFLIGHT) {
      log('warn', 'In-flight limit reached, rejecting request', {
        maxInflight: MAX_INFLIGHT, inflight: inflightCount, path: url.pathname,
      });
      sendJSON(res, 503, {
        error: { message: `Too many concurrent requests (limit ${MAX_INFLIGHT}), retry shortly`, type: 'server_busy' },
        retry_after: 5,
      });
      return;
    }
    inflightCount++;
    // 释放时机：响应写完（finish）或连接终止（close）—— 取先到者，且幂等，
    // 保证任何退出路径（成功/出错/客户端断连/超时）都不会泄漏槽位。
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      if (inflightCount > 0) inflightCount--;
    };
    res.once('finish', release);
    res.once('close', release);
  }

  try {
    if (url.pathname === '/v1/chat/completions' && req.method === 'POST') {
      await handleChatCompletions(req, res);
    } else if (url.pathname === '/v1/messages' && req.method === 'POST') {
      await handleMessages(req, res);
    } else if (url.pathname === '/v1/responses' && req.method === 'POST') {
      await handleResponses(req, res);
    } else if (url.pathname === '/v1/models' && req.method === 'GET') {
      await handleModels(req, res);
    } else if (url.pathname === '/health' || url.pathname === '/') {
      handleHealth(req, res);
    } else if (isAdminPath) {
      await handleAdmin(req, res, url);
    } else {
      sendJSON(res, 404, { error: { message: 'Not found', type: 'not_found' } });
    }
  } catch (e) {
    sendJSON(res, 500, { error: { message: e.message, type: 'internal_error' } });
  }
});

// 全局兜底：abort 触发的异步 rejection 不会让进程崩溃
process.on('unhandledRejection', (reason) => {
  if (reason?.name === 'AbortError' || reason?.code === 'ABORT_ERR') {
    // 客户端断连触发的 abort — 预期行为，静默处理
    log('info', 'Aborted request cleaned up');
  } else if (isRetryableUpstreamError(reason)) {
    // 上游传输层闪断造成的异步 rejection（如 socket terminated），已被重试机制或上层吸收
    log('info', 'Upstream socket terminated asynchronously (handled)');
  } else {
    log('error', 'Unhandled rejection', { message: reason?.message || String(reason), stack: reason?.stack?.split('\n')[0] });
  }
});

// ── keep-alive 时序（放在反向代理后面时是必调项） ──────────────
// 反代（nginx/OpenResty）的 upstream keepalive_timeout 必须**小于**这里的值，
// 否则反代会复用一条后端已经关掉的连接：它把请求体写过去，后端早已 FIN，
// 写这一侧就是 EPIPE —— nginx 侧表现为
//   sendfile() failed (32: Broken pipe) while sending request to upstream
// 而这条请求是 POST（非幂等），nginx 默认不会重试 → 客户端直接吃 502。
//
// Node 默认 keepAliveTimeout=5s。反代若用常见的 4s，余量只有 1 秒；一旦反代的
// 空闲判定基准与后端差一点（大响应体读完的时刻 vs 后端写完的时刻），就会踩上。
// 这里显式抬到 65s，让「谁先关」不再取决于一两秒的抖动 —— 与 Node 官方在
// 反向代理后部署的建议一致（keepAliveTimeout > 前端 idle timeout）。
// 反代侧仍建议设 keepalive_timeout 60s 以内。
const KEEPALIVE_TIMEOUT_MS = (() => {
  const ms = Number.parseInt(process.env.CC_KEEPALIVE_TIMEOUT_MS ?? '', 10);
  return Number.isFinite(ms) && ms > 0 ? ms : 65000;
})();
server.keepAliveTimeout = KEEPALIVE_TIMEOUT_MS;
server.headersTimeout = KEEPALIVE_TIMEOUT_MS + 1000;   // Node 要求 headersTimeout > keepAliveTimeout

server.listen(CFG.port, CFG.host, () => {
  log('info', 'CC Proxy started', {
    url: `http://${CFG.host}:${CFG.port}`,
    api: CFG.apiBase,
    models: MODELS.length,
    session: '12h + 1h jitter, per API key',
    zdr: CFG.zdr ? 'enabled (x-cmd-zdr: 1 on generation/init requests)' : 'off (CMD_ZDR=1 or per-request x-cmd-zdr: 1 to enable)',
    emptySystemPlaceholder: CFG.emptySystemPlaceholder ? 'on (space placeholder for requests without system prompt, issue #17)' : 'off',
    logFile: CFG.logFile || '(console only)',
    clientDrainTimeout: CLIENT_DRAIN_TIMEOUT_MS > 0 ? `${CLIENT_DRAIN_TIMEOUT_MS}ms` : 'disabled',
    keepAliveTimeout: `${KEEPALIVE_TIMEOUT_MS}ms (反代侧 keepalive_timeout 必须小于它)`,
    idleTimeouts: `stream ${STREAM_IDLE_TIMEOUT_MS}ms / nonstream ${NONSTREAM_IDLE_TIMEOUT_MS}ms`,
    maxInflight: MAX_INFLIGHT > 0 ? `${MAX_INFLIGHT} (global, /health exempt)` : 'unlimited (CC_MAX_INFLIGHT=0)',
    upstreamProxy: redactProxyUrl(UPSTREAM_PROXY),
    upstreamRetry: UPSTREAM_RETRY_MAX > 0
      ? `${UPSTREAM_RETRY_MAX} retries, base ${UPSTREAM_RETRY_BASE_MS}ms (only before first byte)`
      : 'disabled (CC_UPSTREAM_RETRY_MAX=0)',
    accounts: `${STORE.accounts.length} account(s), ${STORE.clients.length} client token(s)`,
    admin: adminEnabled() ? `/admin enabled (accountsFile: ${CFG.accountsFile})` : '/admin disabled (set CC_ADMIN_TOKEN to enable)',
    persistence: PERSISTENCE_OK ? 'ok' : 'DISABLED (memory-only; check accountsFile permissions)',
  });
  if (CLIENT_DRAIN_TIMEOUT_MS > 0) {
    log('info', 'Client drain timeout enabled', { timeoutMs: CLIENT_DRAIN_TIMEOUT_MS });
  }
  // 内存提示：body 上限隐含的最坏内存 = 上限 × 实测放大系数（见 MAX_BODY_SIZE 注释 / issue #20）
  const bodyCapMB = Math.round(MAX_BODY_SIZE / 1048576);
  const worstCaseMB = Math.round(bodyCapMB * 5.5);
  if (worstCaseMB >= 500) {
    log('warn', 'Request body limit implies high per-request worst-case memory', {
      maxBodyMB: bodyCapMB,
      worstCaseRSSPerRequestMB: worstCaseMB,
      hint: 'lower CC_MAX_BODY_MB, set CC_MAX_INFLIGHT, and/or cap in-flight requests at the reverse proxy (see README)',
    });
  }
  if (!CFG.apiKey) {
    log('info', 'No API key in config. API key must be sent in Authorization: Bearer <key> header per request.');
  }
});
