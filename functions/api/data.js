// GET /api/data：校验 token → 从 KV 读全量 → 按账号品牌过滤返回（真隔离）
import { verifyToken } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const auth = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const sub = await verifyToken(env.SECRET, auth);
  if (!sub) return Response.json({ error: '未授权' }, { status: 401 });
  const accounts = JSON.parse(env.ACCOUNTS || '{}');
  if (!accounts[sub]) return Response.json({ error: '未授权' }, { status: 401 });

  const all = await env.PRICE_DATA_KV.get('price_data', 'json');
  if (!all) return Response.json({ error: '数据未就绪' }, { status: 503 });

  const allowed = new Set(accounts[sub].brands || []);
  const filtered = all.filter(r => allowed.has(r.brand));
  return Response.json(filtered, { headers: { 'Cache-Control': 'no-store' } });
}
