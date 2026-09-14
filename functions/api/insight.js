// GET /api/insight：校验 token → 按账号品牌过滤洞察/促销数据 → 返回
import { verifyToken , envReady, misconfigured } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  if (!envReady(env)) return misconfigured();   // 缺 SECRET/ACCOUNTS 时显式 500，防伪造 token
  const auth = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const sub = await verifyToken(env.SECRET, auth);
  if (!sub) return Response.json({ error: '未授权' }, { status: 401 });
  const accounts = JSON.parse(env.ACCOUNTS || '{}');
  const acc = accounts[sub];
  if (!acc) return Response.json({ error: '未授权' }, { status: 401 });
  const brands = new Set(acc.brands || []);
  const kv = await env.PRICE_DATA_KV.get('insight_data', 'json');
  if (!kv) return Response.json({ brands: [...brands].sort(), modules: {} },
                                { headers: { 'Cache-Control': 'no-store' } });
  const modules = {};
  // fail-closed：缺少 brand 的行**不外发**（此前是 `!x.brand ||` 放行 → 任何品牌账号都能看到未归属数据）
  const per = (arr) => (Array.isArray(arr) ? arr.filter(x => x.brand && brands.has(x.brand)) : []);
  for (const k of Object.keys(kv.modules || {})) modules[k] = per(kv.modules[k]);
  return Response.json({ brands: [...brands].sort(), modules },
                       { headers: { 'Cache-Control': 'no-store' } });
}
