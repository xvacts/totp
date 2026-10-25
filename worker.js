addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

function randomNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function commonSecurityHeaders() {
  return {
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };
}

function securityHeaders(nonce) {
  return {
    ...commonSecurityHeaders(),
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Security-Policy': [
      "default-src 'none'",
      `script-src 'nonce-${nonce}'`,
      `style-src 'nonce-${nonce}'`,
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
      'upgrade-insecure-requests'
    ].join('; ')
  };
}

async function handleRequest(request) {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method Not Allowed', {
      status: 405,
      headers: {
        ...commonSecurityHeaders(),
        Allow: 'GET, HEAD',
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'"
      }
    });
  }

  const nonce = randomNonce();
  const headers = securityHeaders(nonce);
  if (request.method === 'HEAD') {
    return new Response(null, { headers });
  }
  return new Response(getHTML(nonce), { headers });
}

function getHTML(nonce) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="referrer" content="no-referrer">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TOTP 6位验证码生成器</title>
  <style nonce="${nonce}">
    body { font-family: system-ui, sans-serif; max-width: 560px; margin: 60px auto; padding: 20px; text-align: center; background: #f9f9f9; }
    h1 { color: #1e40af; }
    .hint { color: #444; font-size: 14px; }
    .secret-row { display: flex; gap: 8px; margin: 15px 0; }
    input { flex: 1; width: 100%; padding: 14px; font-size: 18px; border: 2px solid #ccc; border-radius: 8px; box-sizing: border-box; }
    .totp { font-size: 68px; letter-spacing: 18px; font-weight: bold; color: #0066ff; background: white; padding: 25px; border: 4px solid #0066ff; border-radius: 16px; margin: 30px 0; min-height: 88px; }
    .countdown { margin: -12px 0 24px; text-align: left; }
    .countdown[hidden] { display: none; }
    .countdown-label { display: flex; justify-content: space-between; gap: 12px; margin-bottom: 10px; color: #475569; font-size: 14px; }
    .countdown-label strong { color: #2563eb; font-variant-numeric: tabular-nums; }
    .countdown progress { display: block; width: 100%; height: 10px; border: 0; border-radius: 999px; overflow: hidden; background: #e2e8f0; accent-color: #2563eb; }
    .countdown progress::-webkit-progress-bar { background: #e2e8f0; border-radius: 999px; }
    .countdown progress::-webkit-progress-value { background: #2563eb; border-radius: 999px; }
    .countdown progress::-moz-progress-bar { background: #2563eb; border-radius: 999px; }
    .countdown.expiring strong { color: #b45309; }
    .countdown.expiring progress { accent-color: #f59e0b; }
    .countdown.expiring progress::-webkit-progress-value { background: #f59e0b; }
    .countdown.expiring progress::-moz-progress-bar { background: #f59e0b; }
    .countdown.critical strong { color: #dc2626; }
    .countdown.critical progress { accent-color: #ef4444; }
    .countdown.critical progress::-webkit-progress-value { background: #ef4444; }
    .countdown.critical progress::-moz-progress-bar { background: #ef4444; }
    button { padding: 14px 28px; margin: 8px; font-size: 17px; border: none; border-radius: 8px; cursor: pointer; }
    .btn-generate { background: #0070f3; color: white; }
    .btn-copy { background: #10b981; color: white; }
    .btn-clear { background: #ef4444; color: white; }
    .btn-toggle { background: #64748b; color: white; padding: 14px 16px; margin: 0; }
    .status { margin: 15px 0; font-size: 16px; min-height: 24px; }
    .status.error { color: #b91c1c; }
    .status.ok { color: #047857; }
  </style>
</head>
<body>
  <h1>TOTP 6位验证码生成器</h1>
  <p>输入 TOTP 原始密钥（支持带空格）</p>
  <p class="hint">密钥仅在本机浏览器计算，不会发送到服务器。</p>

  <div class="secret-row">
    <input type="password" id="secretInput" placeholder="JBSW Y3DP EHPK 3PXP" autocomplete="new-password" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore="true">
    <button type="button" class="btn-toggle" id="toggleSecret" aria-pressed="false">显示</button>
  </div>

  <div class="totp" id="totpCode">------</div>

  <div class="countdown" id="countdown" hidden>
    <div class="countdown-label">
      <span>当前验证码剩余有效时间</span>
      <strong id="countdownText">30 秒</strong>
    </div>
    <progress id="countdownProgress" max="30000" value="0" aria-label="当前验证码剩余有效时间"></progress>
  </div>

  <div class="status" id="status">请输入密钥后点击生成</div>

  <div>
    <button type="button" class="btn-generate" id="btnGenerate">生成 / 刷新</button>
    <button type="button" class="btn-copy" id="btnCopy">复制验证码</button>
    <button type="button" class="btn-clear" id="btnClear">清除</button>
  </div>

  <script nonce="${nonce}">
    const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const PERIOD_MS = 30000;
    let generating = false;
    let generatedStep = null;
    let generatedInput = "";

    const secretInput = document.getElementById("secretInput");
    const totpCodeEl = document.getElementById("totpCode");
    const statusEl = document.getElementById("status");
    const toggleBtn = document.getElementById("toggleSecret");
    const countdownEl = document.getElementById("countdown");
    const countdownText = document.getElementById("countdownText");
    const countdownProgress = document.getElementById("countdownProgress");

    function updateCountdown() {
      const now = Date.now();
      const active = generatedStep !== null && generatedInput === secretInput.value.trim()
        && /^\\d{6}$/.test(totpCodeEl.textContent);
      countdownEl.hidden = !active;
      if (!active) return;

      // TOTP uses wall-clock boundaries, not 30 seconds from clicking Generate.
      const remaining = generatedStep === Math.floor(now / PERIOD_MS)
        ? PERIOD_MS - (now % PERIOD_MS) : 0;
      const seconds = Math.ceil(remaining / 1000);
      countdownProgress.value = remaining;
      countdownProgress.setAttribute("aria-valuetext", "剩余 " + seconds + " 秒");
      countdownText.textContent = remaining ? seconds + " 秒" : "正在刷新…";
      countdownEl.classList.toggle("expiring", remaining <= 10000);
      countdownEl.classList.toggle("critical", remaining <= 5000);
    }

    function setStatus(message, kind) {
      statusEl.textContent = message;
      statusEl.classList.remove("error", "ok");
      if (kind) statusEl.classList.add(kind);
    }

    function base32Decode(input) {
      const cleaned = input.toUpperCase().replace(/\\s+/g, "").replace(/=+$/, "");
      if (!cleaned || /[^A-Z2-7]/.test(cleaned)) {
        throw new Error("invalid-base32");
      }

      let bits = 0, value = 0, index = 0;
      const output = new Uint8Array(Math.ceil(cleaned.length * 5 / 8));

      for (let i = 0; i < cleaned.length; i++) {
        const idx = ALPHABET.indexOf(cleaned[i]);
        value = (value << 5) | idx;
        bits += 5;
        if (bits >= 8) {
          output[index++] = (value >>> (bits - 8)) & 255;
          bits -= 8;
        }
      }
      return output.slice(0, index);
    }

    async function generateTOTP() {
      if (generating) return;
      const input = secretInput.value.trim();
      if (!input) {
        setStatus("请输入 TOTP 密钥", "error");
        return;
      }

      generating = true;
      setStatus("生成中...");

      try {
        const decoded = base32Decode(input);
        if (decoded.length === 0) {
          throw new Error("empty-key");
        }

        const timeStep = Math.floor(Date.now() / PERIOD_MS);
        const buffer = new ArrayBuffer(8);
        new DataView(buffer).setBigUint64(0, BigInt(timeStep), false);

        const key = await crypto.subtle.importKey(
          "raw",
          decoded,
          { name: "HMAC", hash: "SHA-1" },
          false,
          ["sign"]
        );
        const hmac = await crypto.subtle.sign("HMAC", key, buffer);
        const hmacArray = new Uint8Array(hmac);
        if (hmacArray.length < 4) {
          throw new Error("hmac-short");
        }

        const offset = hmacArray[hmacArray.length - 1] & 0xf;
        if (offset + 3 >= hmacArray.length) {
          throw new Error("hmac-offset");
        }
        const code = ((hmacArray[offset] & 0x7f) << 24) |
                   ((hmacArray[offset + 1] & 0xff) << 16) |
                   ((hmacArray[offset + 2] & 0xff) << 8) |
                   (hmacArray[offset + 3] & 0xff);

        const totp = (code % 1000000).toString().padStart(6, "0");
        // A pending crypto operation must not restore a cleared or changed key.
        if (secretInput.value.trim() !== input) return;
        totpCodeEl.textContent = totp;
        generatedStep = timeStep;
        generatedInput = input;
        updateCountdown();
        setStatus("生成成功（每30秒自动刷新）", "ok");
      } catch (e) {
        if (secretInput.value.trim() !== input) return;
        totpCodeEl.textContent = "错误";
        generatedStep = null;
        generatedInput = "";
        updateCountdown();
        setStatus("密钥格式错误", "error");
      } finally {
        generating = false;
      }
    }

    function copyCode() {
      const code = totpCodeEl.textContent.trim();
      if (!/^\\d{6}$/.test(code)) {
        alert("没有可复制的验证码");
        return;
      }
      navigator.clipboard.writeText(code).then(() => {
        const previous = statusEl.textContent;
        const previousKind = statusEl.classList.contains("error")
          ? "error"
          : (statusEl.classList.contains("ok") ? "ok" : "");
        setStatus("已复制 " + code, "ok");
        setTimeout(() => setStatus(previous, previousKind), 2000);
      }).catch(() => {
        setStatus("复制失败，请手动选择验证码", "error");
      });
    }

    function clearAll() {
      secretInput.value = "";
      totpCodeEl.textContent = "------";
      generatedStep = null;
      generatedInput = "";
      updateCountdown();
      setStatus("已清除");
    }

    toggleBtn.addEventListener("click", () => {
      const visible = secretInput.type === "text";
      secretInput.type = visible ? "password" : "text";
      toggleBtn.textContent = visible ? "显示" : "隐藏";
      toggleBtn.setAttribute("aria-pressed", visible ? "false" : "true");
    });

    document.getElementById("btnGenerate").addEventListener("click", generateTOTP);
    document.getElementById("btnCopy").addEventListener("click", copyCode);
    document.getElementById("btnClear").addEventListener("click", clearAll);
    secretInput.addEventListener("input", updateCountdown);
    document.addEventListener("visibilitychange", () => {
      updateCountdown();
      if (!document.hidden && secretInput.value.trim()) generateTOTP();
    });
    document.addEventListener("keydown", e => {
      if (e.key === "Enter") generateTOTP();
    });

    setInterval(() => {
      if (secretInput.value.trim()) generateTOTP();
    }, 1000);
    setInterval(updateCountdown, 250);
  </script>
</body>
</html>`;
}
