// GET /api/page_events：校验 token → 从 KV 读页面动态事件列表返回。
// 页面事件无品牌维度（同公司内部可见），任一有效账号登录即可查看。
import { verifyToken } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const auth = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const sub = await verifyToken(env.SECRET, auth);
  if (!sub) return Response.json({ error: '未授权' }, { status: 401 });
  const accounts = JSON.parse(env.ACCOUNTS || '{}');
  if (!accounts[sub]) return Response.json({ error: '未授权' }, { status: 401 });

  const events = await env.PRICE_DATA_KV.get('page_events', 'json');
  if (!events) return Response.json([], { headers: { 'Cache-Control': 'no-store' } });
  return Response.json(events, { headers: { 'Cache-Control': 'no-store' } });
}
