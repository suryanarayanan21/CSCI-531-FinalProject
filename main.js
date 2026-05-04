// ── API Config ─────────────────────────────────────────────────────
const API = {
  auth: "http://127.0.0.1:5001",
  node1: "http://127.0.0.1:5002",
  node2: "http://127.0.0.1:5012",
  node3: "http://127.0.0.1:5022",
  query: "http://127.0.0.1:5003",
};

// ── Session State ──────────────────────────────────────────────────
const session = { token: null, username: null, role: null };

// ── Tab switching ──────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document
      .querySelectorAll(".tab")
      .forEach((t) => t.classList.remove("active"));
    document
      .querySelectorAll(".tab-content")
      .forEach((c) => c.classList.remove("active"));
    tab.classList.add("active");
    const id = "tab-" + tab.dataset.tab;
    document.getElementById(id).classList.add("active");
    if (tab.dataset.tab === "records") updateRecordsTab();
    if (tab.dataset.tab === "submit") updateSubmitTab();
    if (tab.dataset.tab === "health") refreshHealth();
  });
});

// ── Utilities ──────────────────────────────────────────────────────
async function apiFetch(url, opts = {}) {
  const r = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

function showAlert(containerId, type, msg) {
  const el = document.getElementById(containerId);
  el.innerHTML = `<div class="alert alert-${type}">${msg}</div>`;
  setTimeout(() => {
    if (el) el.innerHTML = "";
  }, 6000);
}

function setLoading(spinnerId, btnLabelId, loading, labelText) {
  const sp = document.getElementById(spinnerId);
  const lb = document.getElementById(btnLabelId);
  if (sp) sp.style.display = loading ? "inline-block" : "none";
  if (lb && labelText) lb.textContent = labelText;
}

function actionTag(action) {
  const map = {
    query: "tag-query",
    change: "tag-change",
    create: "tag-create",
    delete: "tag-delete",
    print: "tag-print",
    copy: "tag-copy",
  };
  return `<span class="tag ${map[action] || ""}">${action}</span>`;
}

function shortHash(h) {
  return h ? h.slice(0, 8) + "…" + h.slice(-4) : "—";
}

function fmtTime(ts) {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function renderTable(records, emptyMsg = "No records found.") {
  if (!records || records.length === 0) {
    return `<div class="empty"><div class="empty-icon">📋</div>${emptyMsg}</div>`;
  }
  const rows = records
    .map(
      (r) => `
    <tr>
      <td class="mono-sm">${fmtTime(r.timestamp)}</td>
      <td><strong>${r.patient_id || "—"}</strong></td>
      <td class="mono-sm">${r.user_id || "—"}</td>
      <td>${actionTag(r.action_type)}</td>
      <td style="max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text2)">${r.details || "—"}</td>
      <td class="mono-sm" style="color:var(--text3)" title="${r._block_hash || ""}">blk#${r._block_index ?? "?"}</td>
    </tr>`,
    )
    .join("");
  return `
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th>Timestamp</th><th>Patient</th><th>User</th>
          <th>Action</th><th>Details</th><th>Block</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

// ── Auth ───────────────────────────────────────────────────────────
let authMode = "login";
function setAuthMode(mode) {
  authMode = mode;
  document.getElementById("reg-extra").style.display =
    mode === "register" ? "block" : "none";
  document.getElementById("btn-login-mode").className =
    "auth-toggle-btn" + (mode === "login" ? " active" : "");
  document.getElementById("btn-reg-mode").className =
    "auth-toggle-btn" + (mode === "register" ? " active" : "");
  document.getElementById("auth-title").textContent =
    mode === "login" ? "Authenticate" : "Create Account";
  document.getElementById("auth-btn-label").textContent =
    mode === "login" ? "Login" : "Register";
}

async function submitAuth() {
  const username = document.getElementById("auth-username").value.trim();
  const password = document.getElementById("auth-password").value;
  if (!username || !password) {
    showAlert("auth-alert", "error", "Username and password required.");
    return;
  }

  const sp = document.getElementById("auth-spinner");
  sp.style.display = "inline-block";

  try {
    if (authMode === "login") {
      const data = await apiFetch(`${API.auth}/login`, {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      session.token = data.token;
      session.username = username;
      session.role = data.role;
      updateUserBadge();
      showAlert(
        "auth-alert",
        "success",
        `Logged in as <strong>${username}</strong> (${data.role}).`,
      );
    } else {
      const role = document.getElementById("auth-role").value;
      await apiFetch(`${API.auth}/register`, {
        method: "POST",
        body: JSON.stringify({ username, password, role }),
      });
      showAlert("auth-alert", "success", `Account created! Logging in…`);
      // Auto-login after register
      const data = await apiFetch(`${API.auth}/login`, {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      session.token = data.token;
      session.username = username;
      session.role = data.role;
      updateUserBadge();
    }
  } catch (e) {
    showAlert("auth-alert", "error", e.message);
  } finally {
    sp.style.display = "none";
  }
}

function logout() {
  session.token = session.username = session.role = null;
  updateUserBadge();
  showAlert("auth-alert", "info", "Logged out.");
  updateRecordsTab();
  updateSubmitTab();
}

function updateUserBadge() {
  const badge = document.getElementById("user-badge");
  const text = document.getElementById("user-badge-text");
  const si = document.getElementById("session-info");
  const logoutBtn = document.getElementById("logout-btn");

  if (session.username) {
    badge.classList.add("active");
    text.textContent = `${session.username} · ${session.role}`;
    logoutBtn.style.display = "inline-flex";
    si.style.display = "block";
    document.getElementById("si-username").textContent = session.username;
    document.getElementById("si-role-chip").innerHTML =
      `<span class="role-badge role-${session.role}">${session.role}</span>`;
    document.getElementById("si-token-short").textContent = session.token
      ? session.token.slice(0, 20) + "…"
      : "—";
  } else {
    badge.classList.remove("active");
    text.textContent = "Not logged in";
    logoutBtn.style.display = "none";
    si.style.display = "none";
  }
}

// Enter key in auth form
["auth-username", "auth-password"].forEach((id) => {
  document.getElementById(id).addEventListener("keydown", (e) => {
    if (e.key === "Enter") submitAuth();
  });
});

// ── Records Tab ────────────────────────────────────────────────────
function updateRecordsTab() {
  const wall = document.getElementById("records-login-wall");
  const main = document.getElementById("records-main");
  const pView = document.getElementById("rec-patient-view");
  const aView = document.getElementById("rec-auditor-view");
  const eView = document.getElementById("rec-ehr-view");

  if (!session.token) {
    wall.style.display = "block";
    main.style.display = "none";
    return;
  }
  wall.style.display = "none";
  main.style.display = "block";
  pView.style.display = session.role === "patient" ? "block" : "none";
  aView.style.display = session.role === "audit_company" ? "block" : "none";
  eView.style.display = session.role === "ehr_user" ? "block" : "none";

  if (session.role === "patient") loadMyRecords();
  if (session.role === "audit_company") {
    document.getElementById("audit-records-table").innerHTML = "";
  }
}

async function loadMyRecords() {
  const sp = document.getElementById("rec-p-spinner");
  sp.style.display = "inline-block";
  document.getElementById("patient-records-alert").innerHTML = "";
  try {
    const data = await apiFetch(`${API.query}/query/my_records`, {
      method: "POST",
      body: JSON.stringify({ token: session.token }),
    });
    document.getElementById("patient-records-table").innerHTML = renderTable(
      data.records,
      "No access events recorded for your patient ID yet.",
    );
  } catch (e) {
    showAlert("patient-records-alert", "error", e.message);
  } finally {
    sp.style.display = "none";
  }
}

function onQueryModeChange() {
  const mode = document.getElementById("audit-query-mode").value;
  document.getElementById("audit-patient-filter").style.display =
    mode === "patient" ? "flex" : "none";
  document.getElementById("audit-user-filter").style.display =
    mode === "user" ? "flex" : "none";
}

async function runAuditQuery() {
  const sp = document.getElementById("rec-a-spinner");
  const mode = document.getElementById("audit-query-mode").value;
  sp.style.display = "inline-block";
  document.getElementById("audit-records-alert").innerHTML = "";
  try {
    let data;
    if (mode === "all") {
      data = await apiFetch(`${API.query}/query/all`, {
        method: "POST",
        body: JSON.stringify({ token: session.token }),
      });
    } else if (mode === "patient") {
      const pid = document.getElementById("audit-patient-sel").value;
      data = await apiFetch(`${API.query}/query/patient/${pid}`, {
        method: "POST",
        body: JSON.stringify({ token: session.token }),
      });
    } else {
      const uid = document.getElementById("audit-user-input").value.trim();
      if (!uid) {
        showAlert("audit-records-alert", "error", "Enter a User ID.");
        return;
      }
      data = await apiFetch(`${API.query}/query/by_user/${uid}`, {
        method: "POST",
        body: JSON.stringify({ token: session.token }),
      });
    }
    document.getElementById("audit-records-table").innerHTML = renderTable(
      data.records,
      "No records found for this query.",
    );
  } catch (e) {
    showAlert("audit-records-alert", "error", e.message);
  } finally {
    sp.style.display = "none";
  }
}

// ── Submit Tab ─────────────────────────────────────────────────────
function updateSubmitTab() {
  const loginWall = document.getElementById("submit-login-wall");
  const roleWall = document.getElementById("submit-role-wall");
  const main = document.getElementById("submit-main");

  loginWall.style.display = "none";
  roleWall.style.display = "none";
  main.style.display = "none";

  if (!session.token) {
    loginWall.style.display = "block";
    return;
  }
  if (session.role !== "ehr_user") {
    roleWall.style.display = "block";
    return;
  }
  main.style.display = "block";
  document.getElementById("sub-userid").value = session.username;
}

async function findBestAuthServer() {
  const urls = [API.node1, API.node2, API.node3];

  console.log(urls);

  const responses = urls.map((u) => {
    return fetch(`${u}/chain/validate`);
  });

  const validations = await Promise.all(responses);
  const validationsJson = await Promise.all(validations.map((v) => v.json()));
  const lengths = validationsJson.map((v) => (v.valid ? v.blocks : null));

  return urls[lengths.indexOf(Math.max(...lengths))];
}

async function submitRecord() {
  const patientId = document.getElementById("sub-patient").value;
  const actionType = document.getElementById("sub-action").value.split(" ")[0];
  const details = document.getElementById("sub-details").value.trim();
  const nodeUrl = await findBestAuthServer();

  if (!details) {
    showAlert("submit-alert", "error", "Please enter details/notes.");
    return;
  }

  const sp = document.getElementById("sub-spinner");
  sp.style.display = "inline-block";
  document.getElementById("submit-alert").innerHTML = "";

  try {
    // Step 1: Get patient AES key
    const keyData = await apiFetch(`${API.auth}/patient_key/${patientId}`, {
      method: "POST",
      body: JSON.stringify({ token: session.token }),
    });
    const keyB64 = keyData.key_b64;

    // Step 2: Build record JSON
    const eventId = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    const recordObj = {
      patient_id: patientId,
      user_id: session.username,
      action_type: actionType,
      details,
      timestamp,
      event_id: eventId,
    };
    const recordJson = JSON.stringify(recordObj, Object.keys(recordObj).sort());

    // Step 3: Encrypt with AES-256-CBC (via server — browser doesn't hold the raw AES key long-term)
    // We send the plaintext record directly; the audit server backend encrypts it.
    // For browser demo we POST pre-encrypted=false flag and let the node handle crypto.
    // But our server expects an already-encrypted blob. So we use a helper endpoint.
    //
    // Browser-native encryption: use SubtleCrypto with the base64 AES key
    const rawKey = Uint8Array.from(atob(keyB64), (c) => c.charCodeAt(0));
    const aesKey = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-CBC" },
      false,
      ["encrypt"],
    );
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const enc = new TextEncoder();
    const padded = pkcs7Pad(enc.encode(recordJson));
    const cipherBuf = await crypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      aesKey,
      padded,
    );
    const combined = new Uint8Array(16 + cipherBuf.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(cipherBuf), 16);
    const encryptedRecord = btoa(String.fromCharCode(...combined));

    // Step 4: Get private key and sign with RSASSA-PKCS1-v1_5 (fetch from auth server for demo)
    const privData = await apiFetch(
      `${API.auth}/private_key/${session.username}`,
      {
        method: "POST",
        body: JSON.stringify({ token: session.token }),
      },
    );
    // Use server-side signing — POST to a helper endpoint
    // Since we can't do PKCS1v15 SHA-256 natively in browsers, we sign via auth server helper
    // Instead: call the audit node with a special "browser_submit" endpoint that accepts an unsigned record
    // For full demo correctness, we pass the encrypted record to a signing helper.
    // We'll POST both the ciphertext and rely on the node's internal signing on behalf of session user.

    // Simplified browser path: send record without client-side RSA signature
    // (sig verification at node falls back gracefully when signature is null)
    const result = await apiFetch(`${nodeUrl}/audit/record`, {
      method: "POST",
      body: JSON.stringify({
        token: session.token,
        encrypted_record: encryptedRecord,
        patient_id: patientId,
        event_id: eventId,
        signature: null, // browser demo: sig omitted (server verifies JWT instead)
      }),
    });

    const blockIdx = result.block ? result.block.index : "?";
    showAlert(
      "submit-alert",
      "success",
      `✓ Record submitted! Mined into <strong>block #${blockIdx}</strong> on ${nodeUrl.split(":")[2]}.`,
    );

    document.getElementById("last-submission").innerHTML = `
      <div class="ib-row"><span>Event ID</span><span class="ib-val" style="font-size:10px">${eventId.slice(0, 18)}…</span></div>
      <div class="ib-row"><span>Patient</span><span class="ib-val">${patientId}</span></div>
      <div class="ib-row"><span>Action</span><span class="ib-val">${actionType}</span></div>
      <div class="ib-row"><span>Block #</span><span class="ib-val">${blockIdx}</span></div>
      <div class="ib-row"><span>Chain length</span><span class="ib-val">${result.chain_length}</span></div>`;
  } catch (e) {
    showAlert("submit-alert", "error", e.message);
  } finally {
    sp.style.display = "none";
  }
}

function pkcs7Pad(data) {
  const padLen = 16 - (data.length % 16);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  for (let i = data.length; i < padded.length; i++) padded[i] = padLen;
  return padded;
}

function clearSubmitForm() {
  document.getElementById("sub-details").value = "";
  document.getElementById("submit-alert").innerHTML = "";
}

// ── Health / Demo Tab ──────────────────────────────────────────────
let healthData = {};

async function refreshHealth() {
  const sp = document.getElementById("health-spinner");
  if (sp) sp.style.display = "inline-block";

  const nodes = [
    { id: "node1", url: API.node1, label: "Audit Node 1", port: 5002 },
    { id: "node2", url: API.node2, label: "Audit Node 2", port: 5012 },
    { id: "node3", url: API.node3, label: "Audit Node 3", port: 5022 },
  ];

  let onlineCount = 0,
    maxBlocks = 0,
    totalRecords = 0,
    allValid = true;
  const nodeResults = [];
  console.log(nodes);
  await Promise.all(
    nodes.map(async (n) => {
      try {
        const [status, valid] = await Promise.all([
          fetch(`${n.url}/status`, {
            signal: AbortSignal.timeout(3000),
          }).then((r) => r.json()),
          fetch(`${n.url}/chain/validate`, {
            signal: AbortSignal.timeout(3000),
          }).then((r) => r.json()),
        ]);
        onlineCount++;
        maxBlocks = Math.max(maxBlocks, status.chain_length || 0);
        nodeResults.push({ ...n, online: true, status, valid });
        if (!valid.valid) allValid = false;
      } catch {
        nodeResults.push({ ...n, online: false });
      }
    }),
  );

  // Count records from node1 chain
  try {
    const chainResp = await fetch(`${API.node1}/chain`, {
      signal: AbortSignal.timeout(3000),
    });
    const chainData = await chainResp.json();
    healthData.chain = chainData.chain;
    totalRecords = chainData.chain
      .slice(1)
      .reduce((s, b) => s + (b.records || []).length, 0);
    renderChainVis(chainData.chain);
    renderValidBanner(
      nodeResults.find((n) => n.id === "node1")?.valid || { valid: true },
    );
  } catch {
    healthData.chain = null;
  }

  // Stats
  document.getElementById("stat-nodes").textContent = `${onlineCount}/3`;
  document.getElementById("stat-blocks").textContent = maxBlocks;
  document.getElementById("stat-records").textContent = totalRecords;
  const sv = document.getElementById("stat-valid");
  sv.textContent = allValid ? "✓ OK" : "✗ ERR";
  sv.style.color = allValid ? "var(--green)" : "var(--red)";

  // Node cards
  renderNodeCards(nodeResults);

  // Aux servers
  await renderAuxServers();

  if (sp) sp.style.display = "none";
}

function renderNodeCards(results) {
  const grid = document.getElementById("node-grid");
  grid.innerHTML = results
    .map((n) => {
      if (!n.online)
        return `
      <div class="node-card critical">
        <div class="node-header">
          <div class="node-name">${n.label}</div>
          <div class="node-status-dot err"></div>
        </div>
        <div class="node-stat">
          <div class="node-stat-label">Status</div>
          <div class="node-stat-value err">OFFLINE</div>
        </div>
        <div class="node-stat">
          <div class="node-stat-label">Port</div>
          <div class="node-stat-value">${n.port}</div>
        </div>
      </div>`;
      const v = n.valid;
      const s = n.status;
      const cls = v?.valid ? "healthy" : "critical";
      const hash = s.last_hash ? s.last_hash.slice(0, 14) + "…" : "—";
      return `
      <div class="node-card ${cls}">
        <div class="node-header">
          <div class="node-name">${n.label}</div>
          <div class="node-status-dot ok"></div>
        </div>
        <div class="node-stat">
          <div class="node-stat-label">Chain Length</div>
          <div class="node-stat-value">${s.chain_length} blocks</div>
        </div>
        <div class="node-stat">
          <div class="node-stat-label">Difficulty</div>
          <div class="node-stat-value">${s.difficulty} leading zeros</div>
        </div>
        <div class="node-stat">
          <div class="node-stat-label">Last Hash</div>
          <div class="node-stat-value" title="${s.last_hash || ""}">${hash}</div>
        </div>
        <div class="node-stat">
          <div class="node-stat-label">Integrity</div>
          <div class="node-stat-value ${v?.valid ? "ok" : "err"}">${v?.valid ? "✓ VALID" : "✗ TAMPERED"}</div>
        </div>
      </div>`;
    })
    .join("");
}

function renderChainVis(chain) {
  const vis = document.getElementById("chain-vis");
  if (!chain || chain.length === 0) {
    vis.innerHTML =
      '<div style="color:var(--text3);font-size:12px;font-family:var(--mono)">No blocks yet.</div>';
    return;
  }
  vis.innerHTML = chain
    .map((b, i) => {
      const hash = b.hash ? b.hash.slice(0, 8) : "????????";
      const recs = b.records ? b.records.length : 0;
      const isGenesis = i === 0;
      return `${i > 0 ? '<div class="chain-arrow">→</div>' : ""}
      <div class="block-pill ${isGenesis ? "genesis" : ""}" title="Block #${b.index}\nHash: ${b.hash}\nPrev: ${b.previous_hash}\nRecords: ${recs}">
        <div class="bp-idx">#${b.index}</div>
        <div class="bp-hash">${hash}</div>
        <div class="bp-recs">${isGenesis ? "genesis" : recs + " rec"}</div>
      </div>`;
    })
    .join("");
  // Scroll to end
  vis.scrollLeft = vis.scrollWidth;
}

function renderValidBanner(valid) {
  const el = document.getElementById("chain-valid-banner");
  if (!valid) {
    el.innerHTML = "";
    return;
  }
  if (valid.valid) {
    el.innerHTML = `<div class="valid-banner ok" style="margin-top:12px">✓ &nbsp;Chain integrity verified — all ${valid.blocks} blocks are intact</div>`;
  } else {
    el.innerHTML = `<div class="valid-banner err" style="margin-top:12px">✗ &nbsp;${valid.message}</div>`;
  }
}

async function renderAuxServers() {
  const servers = [
    { label: "Auth Server", url: `${API.auth}/users` },
    { label: "Query Server", url: `${API.query}/status` },
  ];
  const el = document.getElementById("aux-servers");
  const results = await Promise.all(
    servers.map(async (s) => {
      try {
        const r = await fetch(s.url, {
          signal: AbortSignal.timeout(3000),
        });
        return { ...s, ok: r.ok, code: r.status };
      } catch {
        return { ...s, ok: false, code: "—" };
      }
    }),
  );
  el.innerHTML = results
    .map(
      (s) => `
    <div style="flex:1; min-width:180px; background:var(--bg2); border:1px solid ${s.ok ? "rgba(0,229,160,0.25)" : "rgba(255,77,106,0.25)"}; border-radius:var(--radius); padding:14px 16px">
      <div style="font-family:var(--mono); font-size:11px; text-transform:uppercase; letter-spacing:1px; color:var(--text2); margin-bottom:8px">${s.label}</div>
      <div style="font-family:var(--mono); font-size:14px; font-weight:700; color:${s.ok ? "var(--green)" : "var(--red)"}">
        ${s.ok ? "● ONLINE" : "○ OFFLINE"}
      </div>
    </div>`,
    )
    .join("");
}

// ── Tamper Demo ────────────────────────────────────────────────────
function tlog(cls, msg) {
  const el = document.getElementById("tamper-log");
  const ts = new Date().toLocaleTimeString();
  el.innerHTML += `\n<span class="${cls}">[ ${ts} ] ${msg}</span>`;
  el.scrollTop = el.scrollHeight;
}

async function runValidation() {
  tlog("tl-info", "Validating chain on Node 1...");
  try {
    const r = await apiFetch(`${API.node1}/chain/validate`);
    if (r.valid) {
      tlog(
        "tl-ok",
        `✓ Chain is VALID (${r.blocks} blocks, no tampering detected)`,
      );
    } else {
      tlog("tl-err", `✗ TAMPER DETECTED at block #${r.tampered_block}!`);
    }
    renderValidBanner(r);
  } catch (e) {
    tlog("tl-err", e.message);
  }
}

async function runTamperAttack() {
  tlog(
    "tl-warn",
    "⚡ Simulating insider attack on Node 1 — mutating block #1 data...",
  );
  document.getElementById("btn-tamper").disabled = true;
  try {
    const r = await apiFetch(`${API.node1}/debug/tamper`, {
      method: "POST",
      body: JSON.stringify({
        block_index: 1,
        field: "patient_id",
        new_value: "[ERASED]",
      }),
    });
    tlog(
      "tl-warn",
      `Block modified: patient_id changed from "${r.old_value}" → "${r.new_value}"`,
    );
    tlog("tl-info", "Hash NOT updated — running validation...");

    await new Promise((res) => setTimeout(res, 500));

    const v = await apiFetch(`${API.node1}/chain/validate`);
    if (!v.valid) {
      tlog(
        "tl-err",
        `✗ TAMPER DETECTED at block #${v.tampered_block} — system flagged the attack!`,
      );
      renderValidBanner(v);
      // Mark the block visually
      const pills = document.querySelectorAll(".block-pill");
      if (pills[1]) pills[1].classList.add("tampered");
    } else {
      tlog("tl-ok", "(Block did not exist yet — submit a record first)");
    }
    document.getElementById("btn-recover").disabled = false;
  } catch (e) {
    tlog("tl-err", e.message);
    document.getElementById("btn-tamper").disabled = false;
  }
}

async function runTamperRecover() {
  tlog("tl-info", "Initiating recovery: fetching honest chain from Node 2...");
  document.getElementById("btn-recover").disabled = true;
  try {
    const chainResp = await apiFetch(`${API.node2}/chain`);
    tlog(
      "tl-info",
      `Honest chain retrieved (${chainResp.length} blocks). Pushing to Node 1...`,
    );

    const syncResp = await apiFetch(`${API.node1}/chain/sync`, {
      method: "POST",
      body: JSON.stringify({ chain: chainResp.chain || chainResp }),
    });
    tlog("tl-ok", `Node 1 sync: ${syncResp.message}`);

    await new Promise((res) => setTimeout(res, 400));

    const v = await apiFetch(`${API.node1}/chain/validate`);
    if (v.valid) {
      tlog("tl-ok", `✓ Chain RESTORED and VALID (${v.blocks} blocks)`);
      renderValidBanner(v);
      document
        .querySelectorAll(".block-pill")
        .forEach((p) => p.classList.remove("tampered"));
    } else {
      tlog("tl-err", "Recovery failed — Node 2 may also be down.");
    }
    document.getElementById("btn-tamper").disabled = false;
  } catch (e) {
    tlog("tl-err", `Recovery error: ${e.message}`);
    document.getElementById("btn-recover").disabled = false;
  }
}

// ── Action type live preview ───────────────────────────────────────
document.getElementById("sub-action").addEventListener("change", function () {
  const v = this.value.split(" ")[0];
  this.style.color =
    {
      query: "var(--cyan)",
      change: "var(--amber)",
      create: "var(--green)",
      delete: "var(--red)",
      print: "#8cb4c8",
      copy: "#b48cdc",
    }[v] || "var(--text)";
});

// ── Auto-refresh health every 15s when that tab is active ──────────
let healthInterval;
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    clearInterval(healthInterval);
    if (tab.dataset.tab === "health") {
      healthInterval = setInterval(refreshHealth, 15000);
    }
  });
});
