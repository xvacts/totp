addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  return new Response(getHTML(), {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function getHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>TOTP 6位验证码生成器</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 560px; margin: 60px auto; padding: 20px; text-align: center; background: #f9f9f9; }
    h1 { color: #1e40af; }
    input { width: 100%; padding: 14px; font-size: 18px; margin: 15px 0; border: 2px solid #ccc; border-radius: 8px; box-sizing: border-box; }
    .totp { font-size: 68px; letter-spacing: 18px; font-weight: bold; color: #0066ff; background: white; padding: 25px; border: 4px solid #0066ff; border-radius: 16px; margin: 30px 0; min-height: 88px; }
    button { padding: 14px 28px; margin: 8px; font-size: 17px; border: none; border-radius: 8px; cursor: pointer; }
    .btn-generate { background: #0070f3; color: white; }
    .btn-copy { background: #10b981; color: white; }
    .btn-clear { background: #ef4444; color: white; }
    .status { margin: 15px 0; font-size: 16px; min-height: 24px; }
  </style>
</head>
<body>
  <h1>TOTP 6位验证码生成器</h1>
  <p>输入 TOTP 原始密钥（支持带空格）</p>
  
  <input type="text" id="secretInput" placeholder="JBSW Y3DP EHPK 3PXP" autocomplete="off">

  <div class="totp" id="totpCode">------</div>
  
  <div class="status" id="status">请输入密钥后点击生成</div>

  <div>
    <button class="btn-generate" onclick="generateTOTP()">生成 / 刷新</button>
    <button class="btn-copy" onclick="copyCode()">复制验证码</button>
    <button class="btn-clear" onclick="clearAll()">清除</button>
  </div>

  <script>
    let currentSecret = "";

    async function base32Decode(input) {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      let bits = 0, value = 0, index = 0;
      const output = new Uint8Array(Math.ceil(input.length * 5 / 8));
      
      input = input.toUpperCase().replace(/\s+/g, '');   // 已修复

      for (let i = 0; i < input.length; i++) {
        const idx = alphabet.indexOf(input[i]);
        if (idx === -1) continue;
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
      let input = document.getElementById("secretInput").value.trim();
      if (!input) {
        document.getElementById("status").innerHTML = '<span style="color:red;">请输入 TOTP 密钥</span>';
        return;
      }

      currentSecret = input;
      document.getElementById("status").textContent = "生成中...";

      try {
        const decoded = await base32Decode(input);
        const timeStep = Math.floor(Date.now() / 1000 / 30);
        const buffer = new ArrayBuffer(8);
        new DataView(buffer).setBigUint64(0, BigInt(timeStep), false);

        const key = await crypto.subtle.importKey("raw", decoded, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
        const hmac = await crypto.subtle.sign("HMAC", key, buffer);
        const hmacArray = new Uint8Array(hmac);

        const offset = hmacArray[19] & 0xf;
        let code = ((hmacArray[offset] & 0x7f) << 24) |
                   ((hmacArray[offset + 1] & 0xff) << 16) |
                   ((hmacArray[offset + 2] & 0xff) << 8) |
                   (hmacArray[offset + 3] & 0xff);

        const totp = (code % 1000000).toString().padStart(6, '0');
        
        document.getElementById("totpCode").textContent = totp;
        document.getElementById("status").innerHTML = '✅ 生成成功（每30秒自动刷新）';
      } catch (e) {
        document.getElementById("totpCode").textContent = "错误";
        document.getElementById("status").innerHTML = '<span style="color:red;">密钥格式错误</span>';
      }
    }

    function copyCode() {
      const code = document.getElementById("totpCode").textContent.trim();
      if (code.length !== 6) {
        alert("没有可复制的验证码");
        return;
      }
      navigator.clipboard.writeText(code).then(() => {
        const status = document.getElementById("status");
        const old = status.innerHTML;
        status.innerHTML = \`✅ 已复制 \${code}\`;
        setTimeout(() => status.innerHTML = old, 2000);
      });
    }

    function clearAll() {
      document.getElementById("secretInput").value = "";
      document.getElementById("totpCode").textContent = "------";
      document.getElementById("status").innerHTML = "已清除";
      currentSecret = "";
    }

    // 回车快速生成
    document.addEventListener("keydown", e => { if (e.key === "Enter") generateTOTP(); });

    // 自动刷新
    setInterval(() => {
      if (currentSecret) generateTOTP();
    }, 1000);
  </script>
</body>
</html>`;
}
