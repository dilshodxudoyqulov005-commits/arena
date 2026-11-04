// Cloudflare Worker: Telegram kanalga obunani tekshiradi.
// Sozlamalar (Settings -> Variables and Secrets):
//   BOT_TOKEN  (Secret)  - @BotFather bergan bot tokeni
//   CHANNEL    (Text)    - @arena_shaxmat
// Bot shu kanalda ADMIN bo'lishi kerak.

const enc = new TextEncoder();

async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
}

async function verifyInitData(initData, botToken) {
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');
  const dcs = [...params.entries()].map(([k, v]) => k + '=' + v).sort().join('\n');
  const secret = await hmac(enc.encode('WebAppData'), enc.encode(botToken));
  const sig = await hmac(secret, enc.encode(dcs));
  const hex = [...sig].map(b => b.toString(16).padStart(2, '0')).join('');
  if (hex !== hash) return null;
  const age = Date.now() / 1000 - Number(params.get('auth_date') || 0);
  if (age > 86400) return null;
  try { return JSON.parse(params.get('user')); } catch (e) { return null; }
}

const json = (obj, cors, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

export default {
  async fetch(req, env) {
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    try {
      const { initData } = await req.json();
      const user = await verifyInitData(initData || '', env.BOT_TOKEN);
      if (!user) return json({ member: false, error: 'bad_init' }, cors, 401);
      const url = 'https://api.telegram.org/bot' + env.BOT_TOKEN +
        '/getChatMember?chat_id=' + encodeURIComponent(env.CHANNEL) + '&user_id=' + user.id;
      const d = await (await fetch(url)).json();
      const st = d.ok && d.result && d.result.status;
      const member = ['creator', 'administrator', 'member'].includes(st) ||
        (st === 'restricted' && d.result.is_member === true);
      return json({ member }, cors);
    } catch (e) {
      return json({ member: false, error: 'server' }, cors, 500);
    }
  },
};
