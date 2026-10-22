// POST /api/login：校验账号密码 → 签发 token
import { verifyPassword, signToken , envReady, misconfigured } from '../_lib/auth.js';

const MAX_ATTEMPTS = 10;
const WINDOW_SECONDS = 900;

export async function onRequestPost({ request, env }) {
  if (!envReady(env)) return misconfigured();   // 缺 SECRET/ACCOUNTS 时显式 500，防伪造 token
  // 按 CF 连接 IP 做 15 分钟失败计数，降低在线暴力尝试（KV 不可用时不影响登录，避免误锁）
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const attemptKey = `login_attempts:${ip}`;
  let attempts = 0;
  try {
    attempts = parseInt((await env.PRICE_DATA_KV?.get(attemptKey)) || '0', 10) || 0;
  } catch (e) { /* ignore */ }
  if (attempts >= MAX_ATTEMPTS) {
    return Response.json({ error: '尝试次数过多，请 15 分钟后再试' }, { status: 429 });
  }
  const { username, password } = await request.json().catch(() => ({}));
  const accounts = JSON.parse(env.ACCOUNTS || '{}');
  const acc = accounts[username];
  if (!acc || !(await verifyPassword(password, acc.pass))) {
    try {
      await env.PRICE_DATA_KV?.put(attemptKey, String(attempts + 1), { expirationTtl: WINDOW_SECONDS });
    } catch (e) { /* ignore */ }
    return Response.json({ error: '用户名或密码错误' }, { status: 401 });
  }
  try { await env.PRICE_DATA_KV?.delete(attemptKey); } catch (e) { /* ignore */ }
  const token = await signToken(env.SECRET, username, env.TOKEN_TTL_SECONDS);
  return Response.json({ token, expires_in: +env.TOKEN_TTL_SECONDS || 86400 });
}
