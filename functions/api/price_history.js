// GET /api/price_history：校验 token → 读 KV(price_history) → 按账号品牌过滤返回（真隔离）
// price_history.json 结构：{ "<url>|<market>|<sku>": {brand, model, site, market, sku, currency, series:[{d,p,a}], min_p,...} }
import { verifyToken , envReady, misconfigured } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  if (!envReady(env)) return misconfigured();   // 缺 SECRET/ACCOUNTS 时显式 500，防伪造 token
  const auth = (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const sub = await verifyToken(env.SECRET, auth);
  if (!sub) return Response.json({ error: '未授权' }, { status: 401 });
  const accounts = JSON.parse(env.ACCOUNTS || '{}');
  if (!accounts[sub]) return Response.json({ error: '未授权' }, { status: 401 });

  const all = await env.PRICE_DATA_KV.get('price_history', 'json');
  if (!all) return Response.json({ error: '数据未就绪' }, { status: 503 });

  const allowed = new Set(accounts[sub].brands || []);
  const out = {};
  for (const [k, v] of Object.entries(all)) {
    if (v && allowed.has(v.brand)) out[k] = v;
  }
  return Response.json(out, { headers: { 'Cache-Control': 'no-store' } });
}
