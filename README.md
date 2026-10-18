# igs_kanyaochang_share

Ken 的分享目錄：https://kanyaochang.github.io/igs_kanyaochang_share/

**整站要密碼**。GitHub Pages 只能放公開檔案，所以頁面與圖片都是**加密後才上傳**，打開時在瀏覽器輸入密碼、用 WebCrypto 在本機解密。輸入一次（勾「記住這台裝置」就不用再輸）整站共用。

## 結構

| 位置 | 內容 | 進版控 |
|---|---|---|
| `_private/` | 明文原稿：`index.html`（總目錄）、`<企劃>/index.html` 與它的圖片 | ❌（`.gitignore`，只在本機） |
| `private-pages.json` | 要加密哪些頁：`{ "src": "_private/x/index.html", "out": "x/index.html" }` | ✅ |
| `site-key.json` | 全站共用的 salt 與密碼驗證值（不是密碼） | ✅ |
| `index.html`、`<企劃>/index.html` | 加密後的頁（密碼畫面＋密文） | ✅ |
| `<企劃>/a/*.bin` | 加密後的圖片，檔名是雜湊 | ✅ |

## 新增或修改企劃

1. 明文放 `_private/<企劃>/index.html`，圖片放同資料夾（例如 `pictures/`），HTML 用相對路徑引用（`./pictures/x.png`）
2. 新企劃：`_private/index.html` 加一張卡片，`private-pages.json` 加一筆
3. 加密：`SITE_PASSWORD_FILE=<密碼檔> node tools/encrypt.mjs`
4. commit、push，GitHub Pages 約一分鐘後更新

- 只有 HTML 裡**寫得出完整相對路徑**的圖會被加密上傳（`img src`、CSS、JS 字串都可以）；用程式拼出來的路徑抓不到，沒被引用的檔不會上傳
- 內容沒變，重跑加密產出的密文就一模一樣，所以可以放心整站重跑，git 只會出現真的有改的檔

## 換電腦：還原明文原稿

```
SITE_PASSWORD_FILE=<密碼檔> node tools/decrypt.mjs
```

照 `private-pages.json` 把頁面與圖片解回 `_private/`，內容和原檔一模一樣；已有的檔預設跳過，要覆蓋加 `--force`。
救不回來的：沒登記的頁、沒被引用的圖、改了還沒加密 commit 的部分，以及密碼本身。

## 換密碼

改密碼檔後照常執行 `encrypt.mjs`：它發現密碼和 `site-key.json` 對不上，會換新 salt、整站重新加密。
已勾「記住」的瀏覽器會自動退回密碼畫面。舊密文仍留在 git 歷史裡，要徹底換掉得改寫歷史。

## 限制

這是擋一般人的鎖，不是保險箱：密文公開，任何人都能下載回去離線猜密碼，所以密碼要 12 字以上、英數混合。
網址路徑（資料夾名）是公開的，命名別洩漏內容。別放真正機密的東西。
