const crypto = require('crypto');

const OWNER = 'mtleech14-dotcom';
const REPO = 'geojepangpang-site';
const FILE_PATH = 'content.json';
const BRANCH = 'main';

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

function verifyToken(token, secret) {
  if (!token || typeof token !== 'string' || token.indexOf('.') === -1) return false;
  const [payload, sig] = token.split('.');
  const expiry = Number(payload);
  if (!expiry || Date.now() > expiry) return false;
  const expected = sign(payload, secret);
  const a = Buffer.from(sig, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// Very light shape check so a malformed save can't wipe the file structure.
function isValidContent(c) {
  if (!c || typeof c !== 'object') return false;
  if (!Array.isArray(c.programs)) return false;
  if (!Array.isArray(c.marquee)) return false;
  if (typeof c.phone !== 'string' || typeof c.address !== 'string') return false;
  return true;
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  const ADMIN_SECRET = process.env.ADMIN_SECRET;
  const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

  if (!ADMIN_SECRET || !GITHUB_TOKEN) {
    res.status(500).send('서버에 ADMIN_SECRET / GITHUB_TOKEN 환경변수가 설정되지 않았어요.');
    return;
  }

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  if (!verifyToken(token, ADMIN_SECRET)) {
    res.status(401).send('로그인이 만료됐어요. 다시 로그인해주세요.');
    return;
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { body = {}; }
  }
  const content = body && body.content;

  if (!isValidContent(content)) {
    res.status(400).send('저장할 내용의 형식이 올바르지 않아요.');
    return;
  }

  const apiBase = `https://api.github.com/repos/${OWNER}/${REPO}/contents/${FILE_PATH}`;
  const ghHeaders = {
    'Authorization': `Bearer ${GITHUB_TOKEN}`,
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'geojepangpang-admin',
  };

  try {
    // 1. get current file sha
    const getRes = await fetch(`${apiBase}?ref=${BRANCH}`, { headers: ghHeaders });
    if (!getRes.ok) {
      const t = await getRes.text();
      res.status(502).send(`GitHub에서 현재 파일 정보를 가져오지 못했어요: ${getRes.status} ${t}`);
      return;
    }
    const getData = await getRes.json();
    const sha = getData.sha;

    // 2. put updated content
    const newContentB64 = Buffer.from(JSON.stringify(content), 'utf8').toString('base64');
    const putRes = await fetch(apiBase, {
      method: 'PUT',
      headers: { ...ghHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: 'Update content via admin panel',
        content: newContentB64,
        sha,
        branch: BRANCH,
      }),
    });

    if (!putRes.ok) {
      const t = await putRes.text();
      res.status(502).send(`GitHub 저장에 실패했어요: ${putRes.status} ${t}`);
      return;
    }

    res.status(200).json({ ok: true });
  } catch (err) {
    res.status(500).send('저장 중 오류가 발생했어요: ' + (err && err.message ? err.message : String(err)));
  }
};
