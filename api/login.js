const crypto = require('crypto');

function sha256(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest();
}

function timingSafeEqualStr(a, b) {
  const ha = sha256(a);
  const hb = sha256(b);
  return crypto.timingSafeEqual(ha, hb);
}

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  const ADMIN_SECRET = process.env.ADMIN_SECRET;

  if (!ADMIN_PASSWORD || !ADMIN_SECRET) {
    res.status(500).json({ error: '서버에 ADMIN_PASSWORD / ADMIN_SECRET 환경변수가 설정되지 않았어요.' });
    return;
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { body = {}; }
  }
  const password = (body && body.password) || '';

  if (!password || !timingSafeEqualStr(password, ADMIN_PASSWORD)) {
    res.status(401).json({ error: '비밀번호가 올바르지 않아요.' });
    return;
  }

  const expiry = Date.now() + 12 * 60 * 60 * 1000; // 12 hours
  const payload = String(expiry);
  const sig = sign(payload, ADMIN_SECRET);
  const token = payload + '.' + sig;

  res.status(200).json({ token });
};
