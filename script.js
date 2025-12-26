document.addEventListener("DOMContentLoaded", function() {
	/* ========= TimeSeed Book ========= */

function loadBook() {
  try {
    return JSON.parse(localStorage.getItem("timeseed-book")) || {};
  } catch {
    return {};
  }
}

function saveBook(book) {
  localStorage.setItem("timeseed-book", JSON.stringify(book));
}

function renderBook() {
  const list = document.getElementById("ts-book-list");
  const book = loadBook();
  list.innerHTML = "";

  for (const name in book) {
    const row = document.createElement("div");
    row.className = "ts-book-entry";

    const label = document.createElement("span");
    label.textContent = name;

    const loadBtn = document.createElement("button");
    loadBtn.textContent = "Load";
    loadBtn.className = "btn btn-secondary";
    loadBtn.onclick = () => {
      document.getElementById("timeseed-seed").value = book[name];
      document.getElementById("ts-book-modal").classList.add("hidden");
    };

    const delBtn = document.createElement("button");
    delBtn.textContent = "✕";
    delBtn.className = "btn btn-secondary";
    delBtn.onclick = () => {
      const b = loadBook();
      delete b[name];
      saveBook(b);
      renderBook();
    };

    row.append(label, loadBtn, delBtn);
    list.appendChild(row);
  }
}

document.getElementById("open-ts-book").onclick = () => {
  document.getElementById("ts-book-modal").classList.remove("hidden");
  renderBook();
};

document.getElementById("ts-book-close").onclick = () => {
  document.getElementById("ts-book-modal").classList.add("hidden");
};

document.getElementById("ts-book-save").onclick = () => {
  const name = document.getElementById("ts-book-name").value.trim();
  const seed = document.getElementById("timeseed-seed").value.trim();

  if (!/^[\w\- ]{2,18}$/.test(name)) return;
  if (!/^[0-9a-zA-Z]{50}$/.test(seed)) return;

  const book = loadBook();
  book[name] = seed;
  saveBook(book);

  document.getElementById("ts-book-name").value = "";
  renderBook();
};


/* ========= Logging ========= */
const logEl = document.getElementById("log-box");
function logEvent(msg) {
  const time = new Date().toISOString().slice(11,23);
  logEl.textContent += `[${time}] ${msg}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

function maskKey(key) {
  if (key.length <= 16) return key;
  return key.slice(0,8) + "..." + key.slice(-8);
}

function getLongTermDate(dateStr) {
  const [y,m,d] = dateStr.split('-').map(Number);
  const month = m - 1;
  const semester = month < 6 ? 0 : 6;
  return `${y}-${String(semester+1).padStart(2,'0')}-01`;
}

/* ========= Byte helpers ========= */
function concatBytes(...arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) throw new Error("Invalid hex key");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/* ========= Random Seed ========= */
document.getElementById("generate-seed-btn").onclick = () => {
document.getElementById("generate-seed-btn")
  .classList.remove("first-step-glow");
  const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const bytes = new Uint8Array(50);
  crypto.getRandomValues(bytes);
  let seed = "";
  for (let i = 0; i < 50; i++) seed += alphabet[bytes[i] % alphabet.length];
  document.getElementById("timeseed-seed").value = seed;
  const pepper = document.getElementById("timeseed-pepper");
pepper.classList.add("soft-focus");
  logEvent("Generated random 50-char Base62 TimeSeed.");
};

/* ========= TimeSeed v2 HKDF (matches your intended behavior) ========= */
const tsKdfEnc = new TextEncoder();

async function deriveTSv2Key(seed, pepper, infoLabel) {
  const ikm = tsKdfEnc.encode(seed + ":" + (pepper || ""));
  const salt = tsKdfEnc.encode("TimeSeed-v2-HKDF");

  const baseKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: tsKdfEnc.encode(infoLabel) },
    baseKey,
    256
  );

  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function deriveDailyKey(seedStr, dateISO, pepper = "") {
  return deriveTSv2Key(seedStr, pepper, `TSv2/daily/${dateISO}`);
}

async function deriveLongTermKey(seedStr, dateISO, pepper = "") {
  const year = dateISO.split("-")[0];
  const month = parseInt(dateISO.split("-")[1], 10);
  const half = month <= 6 ? "H1" : "H2";
  return deriveTSv2Key(seedStr, pepper, `TSv2/long/${year}-${half}`);
}

/* ========= Generate Keys ========= */
document.getElementById("gen-keys-btn").onclick = async () => {
  const statusEl = document.getElementById("timeseed-status");
  statusEl.textContent = "";
  statusEl.className = "status-line";

  const seedStr = document.getElementById("timeseed-seed").value.trim();
  const pepper = document.getElementById("timeseed-pepper").value.trim();
  const date = document.getElementById("timeseed-date").value;

  if (!/^[0-9a-zA-Z]{50}$/.test(seedStr)) {
    statusEl.textContent = "TimeSeed must be exactly 50 characters (0–9, a–z, A–Z).";
    statusEl.classList.add("err");
    logEvent("TimeSeed error: invalid seed format.");
    return;
  }

  if (!date) {
    statusEl.textContent = "Please select a date.";
    statusEl.classList.add("err");
    logEvent("TimeSeed error: date missing.");
    return;
  }

  const longDate = getLongTermDate(date);
  logEvent(`Generating keys for date=${date}, longTerm=${longDate}`);

  try {
    const [daily, longKey] = await Promise.all([
      deriveDailyKey(seedStr, date, pepper),
      deriveLongTermKey(seedStr, date, pepper)
    ]);

    document.getElementById("key-daily").value = daily;
    document.getElementById("key-long").value = longKey;

    document.getElementById("key-outputs").classList.remove("hidden");

    statusEl.textContent = `Keys generated for daily=${date} and semester anchored at ${longDate}.`;
    statusEl.classList.add("ok");

    document.querySelectorAll(".use-lockit-btn").forEach(btn => btn.classList.add("next-step-glow"));
  } catch(e) {
    statusEl.textContent = "Key derivation failed.";
    statusEl.classList.add("err");
    logEvent("Key derivation FAILED: " + (e?.message || e));
  }
};

/* ========= LockItCrypto ========= */
const LockItCrypto = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const DEFAULTS = Object.freeze({
    argon2: Object.freeze({
      t: 5,
      m: 131072,   // KiB = 128 MiB
      p: 1,
      hashLen: 32
    }),
    aes: Object.freeze({
      ivLen: 12,
      saltLen: 16
    })
  });

  function isHex64(s) { return /^[0-9a-f]{64}$/i.test(String(s || "")); }

  // ─────────────────────────────────────────────
  // TS4-TEXT-v4 — FROZEN KDF
  // Argon2id(t=5, m=131072 KiB, p=1, hashLen=32)
  // Password = 64-char hex string (passed as the string itself)
  // AES-256-GCM, salt=16, iv=12
  // Do NOT modify without bumping version byte
  // ─────────────────────────────────────────────
  async function deriveKeyBytes(lockitKeyHex, saltBytes) {
    if (!isHex64(lockitKeyHex)) throw new Error("LockIt key must be 64 hex characters.");
    if (!(saltBytes instanceof Uint8Array) || saltBytes.length !== DEFAULTS.aes.saltLen) {
      throw new Error(`Invalid salt (expected ${DEFAULTS.aes.saltLen} bytes).`);
    }
    if (!window.argon2 || typeof argon2.hash !== "function") {
      throw new Error("Argon2id is required for TS4-TEXT-v4.");
    }

    // Argon2id primary (pass is the hex string itself, by design)
    const res = await argon2.hash({
      pass: lockitKeyHex,
      salt: saltBytes,
      time: DEFAULTS.argon2.t,
      mem: DEFAULTS.argon2.m,
      parallelism: DEFAULTS.argon2.p,
      hashLen: DEFAULTS.argon2.hashLen,
      type: argon2.ArgonType.Argon2id
    });

    return {
      keyBytes: res.hash,
      kdf: "argon2id",
      params: { t: DEFAULTS.argon2.t, m: DEFAULTS.argon2.m, p: DEFAULTS.argon2.p, pass: "hex-string" }
    };
  }

  async function encryptText(plaintext, lockitKeyHex) {
    if (typeof plaintext !== "string" || plaintext.length === 0) throw new Error("Plaintext is empty.");

    const iv = crypto.getRandomValues(new Uint8Array(DEFAULTS.aes.ivLen));
    const salt = crypto.getRandomValues(new Uint8Array(DEFAULTS.aes.saltLen));
    const { keyBytes } = await deriveKeyBytes(lockitKeyHex, salt);

    const aesKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
    const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(plaintext));

    // TS4-TEXT-v4 format:
    // [TS4][0x04][kdfId=0x01][salt16][iv12][ct...]
    const magic = new Uint8Array([0x54, 0x53, 0x34]); // "TS4"
    const ver = new Uint8Array([0x04]);
    const kdfId = new Uint8Array([0x01]); // Argon2id only
    const outBytes = concatBytes(magic, ver, kdfId, salt, iv, new Uint8Array(ctBuf));
    return bytesToHex(outBytes);
  }

  async function decryptText(ciphertext, lockitKeyHex) {
    if (typeof ciphertext !== "string" || ciphertext.length === 0) throw new Error("Ciphertext is empty.");
    if (ciphertext.startsWith("TS4:")) throw new Error("Legacy TS4 JSON ciphertext detected (not supported).");

    const hex = ciphertext.trim().replace(/^0x/i, "").toLowerCase();
    if (!/^[0-9a-f]+$/.test(hex) || (hex.length % 2) !== 0) throw new Error("Ciphertext must be hex.");

    const all = hexToBytes(hex);
    if (all.length < (3 + 1 + 1 + DEFAULTS.aes.saltLen + DEFAULTS.aes.ivLen + 1)) throw new Error("Ciphertext too short.");
    if (all[0] !== 0x54 || all[1] !== 0x53 || all[2] !== 0x34) throw new Error("Unsupported format (missing TS4 magic).");
    if (all[3] !== 0x04) throw new Error("Unsupported TS4 version (only v4 supported).");

    const kdfId = all[4];
    if (kdfId !== 0x01) throw new Error("Unsupported KDF (only Argon2id supported).");

    const saltOff = 5;
    const ivOff = saltOff + DEFAULTS.aes.saltLen;
    const ctOff = ivOff + DEFAULTS.aes.ivLen;

    const salt = all.slice(saltOff, ivOff);
    const iv = all.slice(ivOff, ctOff);
    const ctBytes = all.slice(ctOff);

    const { keyBytes } = await deriveKeyBytes(lockitKeyHex, salt);

    const aesKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
    const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ctBytes);
    return dec.decode(ptBuf);
  }

  return {
    DEFAULTS,
    _deriveKeyBytes: deriveKeyBytes, // used by file mode
    encryptText,
    decryptText
  };
})();

/* ========= Today button ========= */
function updateTodayFields() {
  const now = new Date();
  const todayUTC = now.toISOString().split("T")[0];
  const timeUTC  = now.toISOString().split("T")[1].slice(0,8);
  document.getElementById("timeseed-date").value = todayUTC;
  document.getElementById("timeseed-time").value = timeUTC;
}
document.getElementById("today-btn").onclick = updateTodayFields;

/* ========= Copy / Use ========= */
document.getElementById("copy-daily").onclick = () => {
  const val = document.getElementById("key-daily").value;
  if (val) navigator.clipboard.writeText(val).catch(()=>{});
  logEvent("Daily key copied to clipboard.");
};

document.getElementById("copy-long").onclick = () => {
  const val = document.getElementById("key-long").value;
  if (val) navigator.clipboard.writeText(val).catch(()=>{});
  logEvent("Long-term key copied to clipboard.");
};

document.querySelectorAll(".use-lockit-btn").forEach(btn => {
  btn.onclick = () => {
    const src = btn.getAttribute("data-src");
    const val = document.getElementById(src === "daily" ? "key-daily" : "key-long").value;
    if (!val) return;
    document.getElementById("lockit-key").value = val;
    btn.classList.remove("next-step-glow");
    logEvent(`Loaded ${src} key into LockIt: ${maskKey(val)}`);
    document.getElementById("lockit-result").textContent = `Loaded ${src} key into LockIt.`;
  };
});

/* ========= Theme + Tabs ========= */
logEvent("TimeSeed v2 — Ready.");

(() => {
  const saved = localStorage.getItem("ts-theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
  document.getElementById("theme-toggle").textContent = saved === "dark" ? "☀️" : "🌙";
})();

document.getElementById("theme-toggle").addEventListener("click", () => {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("ts-theme", next);
  document.getElementById("theme-toggle").textContent = next === "dark" ? "☀️" : "🌙";
});

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('timeseed-tab').classList.toggle('hidden', btn.dataset.tab !== 'timeseed');
    document.getElementById('lockit-tab').classList.toggle('hidden', btn.dataset.tab !== 'lockit');
  });
});

document.querySelectorAll(".use-lockit-btn").forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelector('.tab-btn[data-tab="lockit"]').click();
    document.getElementById('lockit-key').scrollIntoView({behavior: "smooth"});
  });
});

/* ========= Guided focus ========= */
document.addEventListener("DOMContentLoaded", function () {
  const seedInput = document.getElementById("timeseed-seed");
  const pepperInput = document.getElementById("timeseed-pepper");
  const dateInput = document.getElementById("timeseed-date");
  const genKeysBtn = document.getElementById("gen-keys-btn");
  const keyDaily = document.getElementById("key-daily");
  const keyLong = document.getElementById("key-long");
  const useDailyBtn = document.querySelector('.use-lockit-btn[data-src="daily"]');
  const useLongBtn = document.querySelector('.use-lockit-btn[data-src="long"]');
  const lockitKey = document.getElementById("lockit-key");
  const lockitMsg = document.getElementById("lockit-message");

  function clearAll() {
    const els = [seedInput, pepperInput, dateInput, genKeysBtn, useDailyBtn, useLongBtn, lockitMsg].filter(Boolean);
    els.forEach(el => el.classList.remove("guided-focus", "soft-focus"));
  }

  function focusEl(el) {
    if (!el) return;
    clearAll();
    el.classList.add("guided-focus");
    el.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function updateGuide() {
    if (seedInput.value.trim().length !== 50) { focusEl(seedInput); return; }
	pepperInput.classList.add("soft-focus");
    if (pepperInput.value.trim().length < 0) { focusEl(pepperInput); return; } // pepper optional
    if (dateInput && !dateInput.value) { focusEl(dateInput); return; }
    if ((!keyDaily?.value || keyDaily.value.trim() === '') && (!keyLong?.value || keyLong.value.trim() === '')) { focusEl(genKeysBtn); return; }
    if (lockitKey.value.trim().length < 64) {
      if (useLongBtn && keyLong?.value) { focusEl(useLongBtn); return; }
      if (useDailyBtn && keyDaily?.value) { focusEl(useDailyBtn); return; }
    }
    focusEl(lockitMsg);
  }

  seedInput.addEventListener("input", updateGuide);
  pepperInput.addEventListener("input", updateGuide);
  if (dateInput) dateInput.addEventListener("change", updateGuide);
  genKeysBtn.addEventListener("click", () => setTimeout(updateGuide, 100));
  if (useDailyBtn) useDailyBtn.addEventListener("click", () => setTimeout(updateGuide, 100));
  if (useLongBtn) useLongBtn.addEventListener("click", () => setTimeout(updateGuide, 100));
  lockitKey.addEventListener("input", updateGuide);

  updateGuide();
});

/* ========= Text encrypt/decrypt UI ========= */
document.getElementById("lockit-encrypt").onclick = async () => {
  const keyHex = document.getElementById("lockit-key").value.trim();
  const msgEl = document.getElementById("lockit-message");
  const working = document.getElementById("working-indicator");
  if (!msgEl.value.trim()) return;

  working.classList.add("active");
  try {
    const out = await LockItCrypto.encryptText(msgEl.value, keyHex);
    msgEl.value = out;
    logEvent("Text encrypted (TS4).");
  } catch (e) {
    logEvent("Encrypt FAILED: " + (e?.message || e));
  } finally {
    working.classList.remove("active");
  }
};

document.getElementById("lockit-decrypt").onclick = async () => {
  const keyHex = document.getElementById("lockit-key").value.trim();
  const msgEl = document.getElementById("lockit-message");
  const working = document.getElementById("working-indicator");
  if (!msgEl.value.trim()) return;

  if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
    logEvent("Decrypt FAILED: LockIt key must be 64 hex chars.");
    return;
  }

  working.classList.add("active");
  try {
    const out = await LockItCrypto.decryptText(msgEl.value.trim(), keyHex);
    msgEl.value = out;
    logEvent("Text decrypted.");
  } catch (e) {
    logEvent("Decrypt FAILED: " + (e?.message || e));
  } finally {
    working.classList.remove("active");
  }
};

/* ========= File Mode (.locked) ========= */
(function initFileMode(){
  const fileInput = document.getElementById("lockit-file");
  const fileNameEl = document.getElementById("file-name-display");
  const encBtn = document.getElementById("lockit-encrypt-file");
  const decBtn = document.getElementById("lockit-decrypt-file");

  const progLabel = document.getElementById("file-progress-label");
  const progWrap  = document.getElementById("file-progress");
  const progBar   = document.getElementById("file-progress-bar");
  const shimmer   = document.getElementById("file-shimmer");

  function resetProgress(){
    if (progLabel) progLabel.style.display = "none";
    if (progWrap) progWrap.style.display = "none";
    if (shimmer) shimmer.style.display = "none";
    if (progBar) progBar.style.width = "0%";
  }

  function setProgress(label, pct, indeterminate=false){
    if (!progLabel || !progWrap || !progBar || !shimmer) return;
    progLabel.textContent = label || "";
    progLabel.style.display = "block";
    if (indeterminate){
      progWrap.style.display = "none";
      shimmer.style.display = "block";
    } else {
      shimmer.style.display = "none";
      progWrap.style.display = "block";
      progBar.style.width = `${Math.max(0, Math.min(100, pct||0))}%`;
    }
  }

  function downloadBlob(blob, filename){
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(()=>URL.revokeObjectURL(url), 1000);
  }

  function stripLockedName(name){
    if (!name) return "decrypted.bin";
    return name.endsWith(".locked") ? name.slice(0, -7) : (name + ".decrypted");
  }

  // ----- TS2 armored file helpers -----
  function _b64Lines(b64, width = 64) {
    const out = [];
    for (let i = 0; i < b64.length; i += width) out.push(b64.slice(i, i + width));
    return out.join("\n");
  }

  function _packTS4FileBlob({ kdfId, saltBytes, ivBytes, cipherBytes }) {
    // [TS4][mode=0x02][kdfId][saltLen][ivLen][salt][iv][cipher]
    const saltLen = saltBytes.length;
    const ivLen = ivBytes.length;
    const header = new Uint8Array(7);
    header[0]=0x54; header[1]=0x53; header[2]=0x34; // TS4
    header[3]=0x02; // file-mode marker
    header[4]=kdfId & 0xff;
    header[5]=saltLen & 0xff;
    header[6]=ivLen & 0xff;

    const out = new Uint8Array(header.length + saltLen + ivLen + cipherBytes.length);
    out.set(header, 0);
    out.set(saltBytes, header.length);
    out.set(ivBytes, header.length + saltLen);
    out.set(cipherBytes, header.length + saltLen + ivLen);
    return out;
  }

  function _unpackTS4FileBlob(blobBytes) {
    if (!(blobBytes instanceof Uint8Array)) blobBytes = new Uint8Array(blobBytes);
    if (blobBytes.length < 7) throw new Error("Invalid locked file body (too short).");
    if (blobBytes[0]!==0x54 || blobBytes[1]!==0x53 || blobBytes[2]!==0x34) throw new Error("Invalid locked file body (missing TS4 magic).");
    if (blobBytes[3] !== 0x02) throw new Error("Invalid locked file body (not file mode).");

    const kdfId = blobBytes[4];
    const saltLen = blobBytes[5];
    const ivLen = blobBytes[6];
    const need = 7 + saltLen + ivLen + 1;
    if (blobBytes.length < need) throw new Error("Invalid locked file body (truncated).");

    const saltBytes = blobBytes.slice(7, 7 + saltLen);
    const ivBytes = blobBytes.slice(7 + saltLen, 7 + saltLen + ivLen);
    const cipherBytes = blobBytes.slice(7 + saltLen + ivLen);
    return { kdfId, saltBytes, ivBytes, cipherBytes };
  }

  function _buildTS2Armor({ saltHex, filename, fileSize, bodyB64 }) {
    const lines = [
      "-----BEGIN TS2 LOCKED FILE-----",
      `Salt-hex: ${saltHex}`,
      `File-name: ${filename}`,
      `File-size: ${fileSize}`,
      "",
      _b64Lines(bodyB64, 64),
      "-----END TS2 LOCKED FILE-----"
    ];
    return lines.join("\n");
  }

  function _parseTS2Armor(txt) {
    const raw = (txt || "").replace(/\r/g, "").trim();
    if (!raw.startsWith("-----BEGIN TS2 LOCKED FILE-----")) return null;

    const lines = raw.split("\n");
    const endIdx = lines.indexOf("-----END TS2 LOCKED FILE-----");
    if (endIdx === -1) throw new Error("Invalid .locked armor (missing END line).");

    let saltHex = "";
    let filename = "";
    let fileSize = 0;

    let i = 1;
    for (; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line === "") { i++; break; }
      const m = line.match(/^([^:]+):\s*(.*)$/);
      if (!m) continue;
      const k = m[1].toLowerCase();
      const v = m[2] || "";
      if (k === "salt-hex") saltHex = v.trim();
      else if (k === "file-name") filename = v;
      else if (k === "file-size") fileSize = parseInt(v, 10) || 0;
    }

    const bodyLines = lines.slice(i, endIdx).map(s => s.trim()).filter(Boolean);
    const bodyB64 = bodyLines.join("");
    if (!bodyB64) throw new Error("Invalid .locked armor (empty body).");
    return { saltHex, filename, fileSize, bodyB64 };
  }

  function parseLockedText(txt){
    // (A) TS2 armored format (preferred)
    const armor = _parseTS2Armor(txt);
    if (armor){
      const blob = base64ToBytes(armor.bodyB64);         // FIX: was b64ToBytes()
      const { saltBytes, ivBytes, cipherBytes } = _unpackTS4FileBlob(blob);

      return {
        filename: armor.filename || null,
        mime: "application/octet-stream",
        saltHex: bytesToHex(saltBytes),
        ivHex: bytesToHex(ivBytes),
        cipherB64: bytesToBase64(cipherBytes)            // FIX: was bytesToB64()
      };
    }

    // (B) Legacy "TimeSeed v2\n..." format
    const lines = (txt || "").replace(/\r\n/g,"\n").split("\n");
    const out = { filename:null, mime:"application/octet-stream", saltHex:null, ivHex:null, cipherB64:null };
    let inCipher = false;
    const cipherLines = [];

    for (const line0 of lines){
      const line = (line0 || "").trim();
      if (!line) continue;
      if (inCipher){ cipherLines.push(line); continue; }

      let m;
      if ((m = line.match(/^filename:\s*(.+)$/i))) out.filename = m[1].trim();
      else if ((m = line.match(/^mime:\s*(.+)$/i))) out.mime = m[1].trim();
      else if ((m = line.match(/^salt:\s*([0-9a-f]+)$/i))) out.saltHex = m[1].toLowerCase();
      else if ((m = line.match(/^iv:\s*([0-9a-f]+)$/i))) out.ivHex = m[1].toLowerCase();
      else if (/^cipher:\s*$/i.test(line)) inCipher = true;
    }

    if (cipherLines.length) out.cipherB64 = cipherLines.join("").trim();
    return out;
  }

  if (!fileInput || !encBtn || !decBtn) return;
  resetProgress();

  fileInput.addEventListener("change", () => {
    const f = fileInput.files && fileInput.files[0];
    if (!f){
      if (fileNameEl) fileNameEl.textContent = "";
      logEvent("File cleared.");
      return;
    }
    if (fileNameEl) fileNameEl.textContent = `${f.name} (${Math.round(f.size/1024)} KB)`;
    logEvent(`File selected: ${f.name} (${f.size} bytes)`);
    resetProgress();
  });

  encBtn.addEventListener("click", async () => {
    const keyHex = (document.getElementById("lockit-key")?.value || "").trim();
    const f = fileInput.files && fileInput.files[0];
    if (!f){ logEvent("Encrypt file FAILED: no file selected."); return; }
    if (!/^[0-9a-fA-F]{64}$/.test(keyHex)){ logEvent("Encrypt file FAILED: LockIt key must be 64 hex chars."); return; }
    if (!LockItCrypto?._deriveKeyBytes){ logEvent("Encrypt file FAILED: internal KDF missing."); return; }

    try{
      resetProgress();
      setProgress("1/3 Reading file…", 0, true);
      const plainBuf = await f.arrayBuffer();
      const plainBytes = new Uint8Array(plainBuf);

      setProgress("2/3 Encrypting…", 33, true);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv   = crypto.getRandomValues(new Uint8Array(12));
      const { keyBytes, kdf } = await LockItCrypto._deriveKeyBytes(keyHex, salt, {});
      const aesKey = await crypto.subtle.importKey("raw", keyBytes, {name:"AES-GCM"}, false, ["encrypt"]);
      const ctBuf = await crypto.subtle.encrypt({name:"AES-GCM", iv}, aesKey, plainBytes);

      setProgress("3/3 Saving…", 66, false);

      const cipherBytes = new Uint8Array(ctBuf);
      const kdfId = 0x01; // Argon2id only

      const blobBytes = _packTS4FileBlob({ kdfId, saltBytes: salt, ivBytes: iv, cipherBytes });
      const saltHex = bytesToHex(salt);
      const armored = _buildTS2Armor({
        saltHex,
        filename: f.name,
        fileSize: f.size,
        bodyB64: bytesToBase64(blobBytes)
      });

      const outBlob = new Blob([armored + "\n"], { type: "text/plain" });
      downloadBlob(outBlob, `${f.name}.locked`);

      logEvent("File encrypted (.locked, armored).");
      setProgress("Done.", 100, false);
      logEvent(`File encrypted → ${f.name}.locked`);
    }catch(e){
      resetProgress();
      logEvent("Encrypt file FAILED: " + (e?.message || e));
      console.error(e);
    }
  });

  decBtn.addEventListener("click", async () => {
    const keyHex = (document.getElementById("lockit-key")?.value || "").trim();
    const f = fileInput.files && fileInput.files[0];
    if (!f){ logEvent("Decrypt file FAILED: no file selected."); return; }
    if (!/^[0-9a-fA-F]{64}$/.test(keyHex)){ logEvent("Decrypt file FAILED: LockIt key must be 64 hex chars."); return; }
    if (!LockItCrypto?._deriveKeyBytes){ logEvent("Decrypt file FAILED: internal KDF missing."); return; }

    try{
      resetProgress();
      setProgress("1/3 Reading .locked…", 0, true);
      const txt = await f.text();
      const meta = parseLockedText(txt);

      if (!meta.saltHex || !meta.ivHex || !meta.cipherB64){
        throw new Error("Invalid .locked structure (missing salt/iv/cipher).");
      }

      const salt = hexToBytes(meta.saltHex);
      const iv   = hexToBytes(meta.ivHex);
      const ctBytes = base64ToBytes(meta.cipherB64);

      setProgress("2/3 Decrypting…", 33, true);
      const { keyBytes } = await LockItCrypto._deriveKeyBytes(keyHex, salt, {});
      const aesKey = await crypto.subtle.importKey("raw", keyBytes, {name:"AES-GCM"}, false, ["decrypt"]);
      const ptBuf = await crypto.subtle.decrypt({name:"AES-GCM", iv}, aesKey, ctBytes);

      setProgress("3/3 Saving…", 66, false);
      const outName = meta.filename || stripLockedName(f.name);
      const outMime = meta.mime || "application/octet-stream";
      downloadBlob(new Blob([ptBuf], {type: outMime}), outName);

      setProgress("Done.", 100, false);
      logEvent(`File decrypted → ${outName}`);
    }catch(e){
      resetProgress();
      logEvent("Decrypt file FAILED: " + (e?.message || e));
      console.error(e);
    }
  });
})();
document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".ts-icon-btn");
  if (!btn) return;

  const action = btn.dataset.action;
  const targetId = btn.dataset.target;
  const field = document.getElementById(targetId);
  if (!field) return;

  try {
    if (action === "copy") {
      if (!field.value) return;
      await navigator.clipboard.writeText(field.value);
    }

    if (action === "paste") {
      const text = await navigator.clipboard.readText();
      field.value = text || "";
      field.dispatchEvent(new Event("input", { bubbles: true }));
    }

    if (action === "clear") {
      field.value = "";
      field.dispatchEvent(new Event("input", { bubbles: true }));
    }
  } catch (err) {
    console.warn("TS icon action failed:", err);
  }
});

(function () {
  try {
    // Legacy-safe iOS detection (works on iOS 11)
    var isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);

    if (isIOS) {
      var banner = document.getElementById("ios-warning");
      if (banner) {
        banner.style.display = "block";
      }
    }
  } catch (e) {
    // Fail closed: do nothing
  }
})();
});

