// 账号鉴权共享逻辑（Cloudflare Pages Functions _lib）
// token = base64url(payload).base64url(signature)，payload 仅 {sub, exp}，不内嵌品牌
const encoder = new TextEncoder();

const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64urlDecode = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

function ctEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  const x = new Uint8Array(a), y = new Uint8Array(b);
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(data)));
}

// stored = "pbkdf2-sha256$iterations$saltB64$hashB64"
export async function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 4) return false;
  try {
    const iters = +parts[1];
    const salt = Uint8Array.from(atob(parts[2]), c => c.charCodeAt(0));
    const want = Uint8Array.from(atob(parts[3]), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('raw', encoder.encode(String(password)),
      { name: 'PBKDF2' }, false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations: iters, hash: 'SHA-256' }, key, 256));
    return ctEqual(bits, want);
  } catch {
    return false;
  }
}

// 环境变量缺失守卫：SECRET/ACCOUNTS 未配置时必须**显式失败**，不能默默用 undefined 签名——
// TextEncoder().encode(undefined) 会编码成字面量 "undefined"，HMAC 照常工作 →
// 任何读过这段代码的人都能离线伪造管理员 token（2026-09-14 安全审查发现）。
export function envReady(env) {
  return !!(env && env.SECRET && env.ACCOUNTS);
}

export function misconfigured() {
  return Response.json({ error: '服务未正确配置（缺少 SECRET/ACCOUNTS）' }, { status: 500 });
}

export async function signToken(secret, sub, ttl) {
  if (!secret) throw new Error('SECRET missing');
  const exp = Math.floor(Date.now() / 1000) + (+ttl || 86400);
  const payload = b64url(encoder.encode(JSON.stringify({ sub, exp })));
  const sig = b64url(await hmac(secret, payload));
  return `${payload}.${sig}`;
}

export async function verifyToken(secret, token) {
  if (!secret) return null;                 // 无密钥 → 一律不通过（防 "undefined" 密钥伪造）
  const [p, s] = String(token || '').split('.');
  if (!p || !s) return null;
  const sig = b64url(await hmac(secret, p));
  if (!ctEqual(encoder.encode(sig), encoder.encode(s))) return null;
  try {
    const { sub, exp } = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
    if (exp < Date.now() / 1000) return null;
    return sub;
  } catch {
    return null;
  }
}
