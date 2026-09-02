// GET /api/page_events：校验 token → 按账号品牌过滤页面动态 → 返回 { brands, events }。
// 主账号（多品牌）返回全部并带可用品牌列表供前端切换；子账号只见自己品牌的动态。
import { verifyToken } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const auth = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const sub = await verifyToken(env.SECRET, auth);
  if (!sub) return Response.json({ error: '未授权' }, { status: 401 });
  const accounts = JSON.parse(env.ACCOUNTS || '{}');
  const acc = accounts[sub];
  if (!acc) return Response.json({ error: '未授权' }, { status: 401 });

  const brands = new Set(acc.brands || []);
  const events = await env.PRICE_DATA_KV.get('page_events', 'json');
  const list = Array.isArray(events) ? events : [];
  const filtered = list.filter(e => !e.brand || brands.has(e.brand));
  const head = { 'Cache-Control': 'no-store' };
  return Response.json({ brands: [...brands].sort(), events: filtered }, { headers: head });
}
