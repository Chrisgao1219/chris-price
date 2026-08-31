// POST /api/login：校验账号密码 → 签发 token
import { verifyPassword, signToken } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const { username, password } = await request.json().catch(() => ({}));
  const accounts = JSON.parse(env.ACCOUNTS || '{}');
  const acc = accounts[username];
  if (!acc || !(await verifyPassword(password, acc.pass)))
    return Response.json({ error: '用户名或密码错误' }, { status: 401 });
  const token = await signToken(env.SECRET, username, env.TOKEN_TTL_SECONDS);
  return Response.json({ token, expires_in: +env.TOKEN_TTL_SECONDS || 86400 });
}
