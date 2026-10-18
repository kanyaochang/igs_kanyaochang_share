// 分享頁加密：把 _private/ 裡的明文網頁（連同它引用的圖片）用密碼加密成可以公開放的網頁。
// 瀏覽器打開後要輸入密碼，用 WebCrypto 在本機解密顯示；repo 裡只有密文，明文從不進版控。
//
// 用法（在 repo 根目錄）：
//   SITE_PASSWORD_FILE=<存密碼的檔案> node tools/encrypt.mjs
//   或 SITE_PASSWORD=<密碼> node tools/encrypt.mjs
// 要加密哪些頁寫在 private-pages.json：[{ "src": "_private/x/index.html", "out": "x/index.html" }]
//
// 圖片：src 所在資料夾（含子資料夾）裡、有被那一頁 HTML 引用到的檔案，各自加密成 <out 資料夾>/a/<雜湊>.bin。
// 檔名是金鑰算出的雜湊，看不出原本叫什麼；沒被引用的檔不會上傳。
//
// 加密：PBKDF2-SHA256（600,000 次）導出 512 bits，前半是 AES-GCM-256 金鑰、後半是 HMAC 金鑰。
// 全站共用一組 salt（site-key.json），所以輸入一次密碼整站都打得開。
// iv 由 HMAC(內容) 決定：內容沒變，密文就一模一樣，重跑不會讓 git 出現假改動。
// 換密碼時 site-key.json 的驗證值對不上，會自動換新 salt、整站重新加密。
import { webcrypto as crypto } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, unlinkSync, statSync } from "node:fs";
import { dirname, join, relative, extname, posix } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ITER = 600000;
const KEYFILE = join(ROOT, "site-key.json");

const pw = (process.env.SITE_PASSWORD ||
  (process.env.SITE_PASSWORD_FILE ? readFileSync(process.env.SITE_PASSWORD_FILE, "utf8") : "")).trim();
if (!pw) { console.error("缺密碼：設 SITE_PASSWORD 或 SITE_PASSWORD_FILE"); process.exit(1); }

const b64 = buf => Buffer.from(buf).toString("base64");
const u8 = s => Uint8Array.from(Buffer.from(s, "base64"));
const enc = new TextEncoder();

async function deriveKeys(salt, iter) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, base, 512));
  const aes = await crypto.subtle.importKey("raw", bits.slice(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
  const mac = await crypto.subtle.importKey("raw", bits.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return { aes, mac };
}

const hmac = async (keys, label, data) =>
  new Uint8Array(await crypto.subtle.sign("HMAC", keys.mac, Buffer.concat([Buffer.from(label + "\0"), Buffer.from(data)])));

async function seal(keys, data) {
  const iv = (await hmac(keys, "iv", data)).slice(0, 12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keys.aes, data));
  return { iv, ct };
}

// 全站 salt：沿用既有的；密碼換了（驗證值解不開）就換新 salt
let site = existsSync(KEYFILE) ? JSON.parse(readFileSync(KEYFILE, "utf8")) : null;
let keys;
if (site) {
  keys = await deriveKeys(u8(site.salt), site.iter);
  try { await crypto.subtle.decrypt({ name: "AES-GCM", iv: u8(site.check.iv) }, keys.aes, u8(site.check.ct)); }
  catch { console.log("密碼和 site-key.json 對不上：換新 salt，整站重新加密"); site = null; }
}
if (!site) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  keys = await deriveKeys(salt, ITER);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keys.aes, enc.encode("ok")));
  site = { salt: b64(salt), iter: ITER, check: { iv: b64(iv), ct: b64(ct) } };
  writeFileSync(KEYFILE, JSON.stringify(site, null, 2) + "\n");
}

const MIME = { ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
  ".svg": "image/svg+xml", ".mp4": "video/mp4", ".webm": "video/webm", ".mp3": "audio/mpeg", ".pdf": "application/pdf" };

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (!/\.html?$/i.test(name)) out.push(p);
  }
  return out;
}

function shell(payload, isRoot) {
  return `<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>分享頁</title>
<style>
  :root { --bg:#0f172a; --card:#1e293b; --text:#e5e7eb; --muted:#94a3b8; --line:#334155; --accent:#38bdf8; --err:#f87171; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg); color:var(--text);
         font-family:-apple-system,"Segoe UI","Noto Sans TC","Microsoft JhengHei",sans-serif; padding:16px; }
  form { width:100%; max-width:360px; background:var(--card); border:1px solid var(--line); border-radius:16px; padding:24px; }
  h1 { font-size:20px; margin:0 0 4px; }
  p { color:var(--muted); font-size:14px; margin:0 0 16px; }
  input[type=password] { width:100%; font:inherit; font-size:18px; padding:10px 12px; border:1px solid var(--line); border-radius:10px;
                         background:var(--bg); color:var(--text); letter-spacing:.1em; }
  label.rm { display:flex; gap:8px; align-items:center; font-size:14px; color:var(--muted); margin:12px 0; }
  button { width:100%; font:inherit; font-size:16px; padding:10px; border:0; border-radius:10px; background:var(--accent); color:var(--bg); cursor:pointer; font-weight:700; }
  button:disabled { opacity:.6; cursor:default; }
  .err { color:var(--err); font-size:14px; min-height:20px; margin-top:10px; }
  a { color:var(--accent); font-size:14px; }
</style>
</head>
<body>
<form id="f">
  <h1>🔒 分享頁</h1>
  <p>請輸入密碼。</p>
  <input type="password" id="pw" autocomplete="current-password" autocapitalize="off" spellcheck="false" autofocus aria-label="密碼">
  <label class="rm"><input type="checkbox" id="rm"> 記住這台裝置</label>
  <button type="submit" id="go">打開</button>
  <div class="err" id="err" role="alert"></div>
  ${isRoot ? "" : '<a href="../">← 回目錄</a>'}
</form>
<script>
const S = ${JSON.stringify({ salt: site.salt, iter: site.iter })};
const P = ${JSON.stringify(payload)};
const KEY = "sharekey";
const u8 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const b64 = a => btoa(String.fromCharCode(...a));
const go = document.getElementById("go"), err = document.getElementById("err");
async function derive(pw) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: u8(S.salt), iterations: S.iter, hash: "SHA-256" }, base, 512)).slice(0, 32);
}
async function open(raw) {
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  const dec = async (iv, ct) => crypto.subtle.decrypt({ name: "AES-GCM", iv: u8(iv) }, key, ct);
  const doc = JSON.parse(new TextDecoder().decode(await dec(P.iv, u8(P.ct))));   // 密碼錯在這裡就會丟例外
  let html = doc.html, done = 0;
  if (doc.assets.length) go.textContent = "載入圖片 0/" + doc.assets.length;
  const urls = await Promise.all(doc.assets.map(async a => {
    const r = await fetch(a.file);
    if (!r.ok) throw new Error("load " + a.file);
    const blob = new Blob([await dec(a.iv, await r.arrayBuffer())], { type: a.type });
    go.textContent = "載入圖片 " + (++done) + "/" + doc.assets.length;
    return URL.createObjectURL(blob);
  }));
  const refs = doc.assets.flatMap((a, i) => a.refs.map(r => [r, urls[i]])).sort((x, y) => y[0].length - x[0].length);
  for (const [r, u] of refs) html = html.split(r).join(u);
  document.open(); document.write(html); document.close();
}
const get = k => { try { return localStorage.getItem(k) || sessionStorage.getItem(k); } catch (e) { return null; } };
const forget = () => { try { localStorage.removeItem(KEY); sessionStorage.removeItem(KEY); } catch (e) {} };
document.getElementById("f").addEventListener("submit", async e => {
  e.preventDefault();
  const remember = document.getElementById("rm").checked;   // 解密後整頁會換掉，要先讀
  go.disabled = true; go.textContent = "解密中…"; err.textContent = "";
  let raw;
  try { raw = await derive(document.getElementById("pw").value); }
  catch (x) { err.textContent = "這個瀏覽器不支援解密。"; return; }
  try {
    // 記住的是導出的金鑰不是密碼；整站共用，進別頁不用再輸入
    try { (remember ? localStorage : sessionStorage).setItem(KEY, b64(raw)); } catch (x) {}
    await open(raw);
  } catch (x) {
    forget();
    err.textContent = String(x.message).startsWith("load ") ? "圖片載入失敗，請重新整理。" : "密碼不對，再試一次。";
    go.disabled = false; go.textContent = "打開";
  }
});
// 這台裝置記過（或同一個分頁階段輸入過）就直接打開。
// 要等這頁載入完才換頁：記住的金鑰免 PBKDF2、解密很快，載入中呼叫 document.open() 不會清掉密碼畫面，
// 解出來的內容會接在它後面（2026-10-18 實際踩到）
const saved = get(KEY);
if (saved) {
  go.disabled = true; go.textContent = "解密中…";
  const run = () => open(u8(saved)).catch(() => { forget(); go.disabled = false; go.textContent = "打開"; });
  if (document.readyState === "complete") run(); else addEventListener("load", () => setTimeout(run), { once: true });
}
</script>
</body>
</html>
`;
}

const list = JSON.parse(readFileSync(join(ROOT, "private-pages.json"), "utf8"));
for (const p of list) {
  const srcFile = join(ROOT, p.src), out = join(ROOT, p.out);
  const srcDir = dirname(srcFile), outDir = dirname(out), assetDir = join(outDir, "a");
  const html = readFileSync(srcFile, "utf8");

  // 找出這一頁引用到的檔（相對路徑，含 ./ 前綴與 URL 編碼兩種寫法）
  const assets = [], keep = new Set();
  for (const file of walk(srcDir)) {
    const rel = relative(srcDir, file).split("\\").join(posix.sep);
    const forms = [...new Set([rel, encodeURI(rel)])].flatMap(f => ["./" + f, f]);
    const refs = forms.filter(f => html.includes(f));
    if (!refs.length) continue;
    const data = readFileSync(file);
    const name = Buffer.from(await hmac(keys, "name", data)).toString("hex").slice(0, 20) + ".bin";
    const { iv, ct } = await seal(keys, data);
    mkdirSync(assetDir, { recursive: true });
    writeFileSync(join(assetDir, name), ct);
    keep.add(name);
    assets.push({ path: rel, refs, file: "a/" + name, iv: b64(iv), type: MIME[extname(file).toLowerCase()] || "application/octet-stream" });
  }
  // 清掉這一頁不再引用的舊密文
  if (existsSync(assetDir)) for (const n of readdirSync(assetDir)) if (!keep.has(n)) unlinkSync(join(assetDir, n));

  const { iv, ct } = await seal(keys, enc.encode(JSON.stringify({ html, assets })));
  mkdirSync(outDir, { recursive: true });
  writeFileSync(out, shell({ iv: b64(iv), ct: b64(ct) }, outDir === ROOT));
  console.log(`加密 ${p.src} → ${p.out}（圖 ${assets.length} 張）`);
}
