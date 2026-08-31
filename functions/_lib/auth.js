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

export async function signToken(secret, sub, ttl) {
  const exp = Math.floor(Date.now() / 1000) + (+ttl || 86400);
  const payload = b64url(encoder.encode(JSON.stringify({ sub, exp })));
  const sig = b64url(await hmac(secret, payload));
  return `${payload}.${sig}`;
}

export async function verifyToken(secret, token) {
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
