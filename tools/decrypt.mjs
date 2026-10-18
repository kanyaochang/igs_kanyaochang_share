// 分享頁還原：encrypt.mjs 的反向。換一台電腦 clone 下來之後，用密碼把加密頁（連同圖片）解回 _private/ 的明文原稿。
// 解出來的 HTML 和圖片都和當初加密的原檔一模一樣。
//
// 用法（在 repo 根目錄）：
//   SITE_PASSWORD_FILE=<存密碼的檔案> node tools/decrypt.mjs
//   或 SITE_PASSWORD=<密碼> node tools/decrypt.mjs
//   加 --force 才會覆蓋 _private/ 裡已經存在的檔（預設跳過，免得蓋掉比 repo 新的原稿）
// 要還原哪些頁照 private-pages.json：每筆把 out（密文）解回 src（明文）。
// 救不回來的：沒登記的頁、沒被任何頁引用的圖（encrypt.mjs 不會上傳它們）、改了還沒加密 commit 的部分。
import { webcrypto as crypto } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const force = process.argv.includes("--force");

const pw = (process.env.SITE_PASSWORD ||
  (process.env.SITE_PASSWORD_FILE ? readFileSync(process.env.SITE_PASSWORD_FILE, "utf8") : "")).trim();
if (!pw) { console.error("缺密碼：設 SITE_PASSWORD 或 SITE_PASSWORD_FILE"); process.exit(1); }

const u8 = s => Uint8Array.from(Buffer.from(s, "base64"));
const site = JSON.parse(readFileSync(join(ROOT, "site-key.json"), "utf8"));
const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]);
const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: u8(site.salt), iterations: site.iter, hash: "SHA-256" }, base, 512));
const key = await crypto.subtle.importKey("raw", bits.slice(0, 32), "AES-GCM", false, ["decrypt"]);
const dec = async (iv, ct) => new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: u8(iv) }, key, ct));

try { await dec(site.check.iv, u8(site.check.ct)); }
catch { console.error("密碼不對（和 site-key.json 對不上），什麼都沒寫"); process.exit(1); }

const save = (file, data) => {
  if (existsSync(file) && !force) { console.log(`已有 ${file}，跳過（要覆蓋加 --force）`); return; }
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, data);
};

const list = JSON.parse(readFileSync(join(ROOT, "private-pages.json"), "utf8"));
let failed = 0;
for (const p of list) {
  const out = join(ROOT, p.out), src = join(ROOT, p.src);
  if (!existsSync(out)) { console.log(`沒有密文 ${p.out}，跳過`); failed++; continue; }
  const m = readFileSync(out, "utf8").match(/const P = (\{.*?\});/s);
  if (!m) { console.log(`${p.out} 不是 encrypt.mjs 產的加密頁，跳過`); failed++; continue; }
  const P = JSON.parse(m[1]);
  const doc = JSON.parse(new TextDecoder().decode(await dec(P.iv, u8(P.ct))));
  save(src, doc.html);
  for (const a of doc.assets) save(join(dirname(src), a.path), await dec(a.iv, readFileSync(join(dirname(out), a.file))));
  console.log(`還原 ${p.out} → ${p.src}（圖 ${doc.assets.length} 張）`);
}
process.exit(failed ? 1 : 0);
