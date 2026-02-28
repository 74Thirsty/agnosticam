let token = "";
let cameras = [];
let shodanHosts = [];

const headers = () => ({ "Content-Type": "application/json", Authorization: `Bearer ${token}` });

async function api(path, options = {}) {
  const resp = await fetch(path, options);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || `HTTP ${resp.status}`);
  return data;
}

function byId(id) { return document.getElementById(id); }

function renderSummary(summary) {
  const target = byId("summary");
  target.innerHTML = "";
  Object.entries(summary).forEach(([k, v]) => {
    const div = document.createElement("div");
    div.className = "stat";
    div.innerHTML = `<div class='small'>${k}</div><div>${v}</div>`;
    target.appendChild(div);
  });
}

function renderCameras() {
  const tbody = byId("cameraRows");
  tbody.innerHTML = "";
  cameras.forEach((camera) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${camera.name}</td>
      <td>${camera.location}</td>
      <td>${camera.ip_address}</td>
      <td>${camera.status}</td>
      <td>${camera.tags.join(", ")}</td>
      <td class='small'>${camera.health_message || "n/a"}</td>
      <td>
        <button onclick="runHealth(${camera.id})">Health</button>
        <button onclick="removeCamera(${camera.id})">Delete</button>
      </td>`;
    tbody.appendChild(tr);
  });
  renderMultiview();
}

function renderMultiview() {
  const box = byId("multiview");
  box.innerHTML = "";
  cameras.slice(0, 9).forEach((c) => {
    const tile = document.createElement("div");
    tile.className = "tile";
    tile.innerHTML = `<strong>${c.name}</strong><div class='small'>${c.location} · ${c.stream_url}</div>`;
    box.appendChild(tile);
  });
}

function renderShodanHosts() {
  const tbody = byId("shodanRows");
  tbody.innerHTML = "";
  shodanHosts.forEach((host, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td><input type="checkbox" class="pick-host" data-idx="${idx}" checked /></td>
    <td>${host.ip_address}</td><td>${host.port}</td><td>${host.transport}</td><td>${host.product || "-"}</td><td>${host.org || host.isp || "-"}</td><td>${host.location || "-"}</td>`;
    tbody.appendChild(tr);
  });
}

async function loadCameras() {
  const query = new URLSearchParams();
  const q = byId("query").value.trim();
  const location = byId("locationFilter").value.trim();
  const tag = byId("tagFilter").value.trim();
  if (q) query.set("query", q);
  if (location) query.set("location", location);
  if (tag) query.append("tags", tag);
  const data = await api(`/api/cameras?${query.toString()}`, { headers: headers() });
  cameras = data.items;
  renderCameras();
}

async function loadSummary() { renderSummary(await api("/api/summary", { headers: headers() })); }

async function loadLayouts() {
  const data = await api("/api/layouts", { headers: headers() });
  const ul = byId("layoutList");
  ul.innerHTML = "";
  data.items.forEach((l) => {
    const li = document.createElement("li");
    li.textContent = `${l.name} (${l.grid}) cameras=${l.camera_ids.join(",")}`;
    ul.appendChild(li);
  });
}

async function loadScans() {
  const ul = byId("scanList");
  ul.innerHTML = "";
  try {
    const data = await api("/api/scans", { headers: headers() });
    data.items.forEach((run) => {
      const li = document.createElement("li");
      li.textContent = `#${run.id} ${run.source} query=\"${run.query}\" imported=${run.imported_count} (${run.created_at})`;
      ul.appendChild(li);
    });
  } catch (err) {
    ul.innerHTML = `<li class='small'>${err.message}</li>`;
  }
}

async function loadScans() {
  const ul = byId("scanList");
  ul.innerHTML = "";
  try {
    const data = await api("/api/scans", { headers: headers() });
    data.items.forEach((run) => {
      const li = document.createElement("li");
      li.textContent = `#${run.id} ${run.source} query=\"${run.query}\" imported=${run.imported_count} (${run.created_at})`;
      ul.appendChild(li);
    });
  } catch (err) {
    ul.innerHTML = `<li class='small'>${err.message}</li>`;
  }
}

async function runHealth(id) {
  await api(`/api/cameras/${id}/health-check`, { method: "POST", headers: headers(), body: "{}" });
  await refreshAll();
}
window.runHealth = runHealth;

async function removeCamera(id) {
  await api(`/api/cameras/${id}`, { method: "DELETE", headers: headers() });
  await refreshAll();
}
window.removeCamera = removeCamera;

async function refreshAll() {
  await Promise.all([loadSummary(), loadCameras(), loadLayouts()]);
  await Promise.all([loadSummary(), loadCameras(), loadLayouts(), loadScans()]);
}

byId("loginBtn").addEventListener("click", async () => {
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: byId("email").value, password: byId("password").value }),
    });
    token = data.token;
    byId("me").textContent = `${data.user.email} (${data.user.role})`;
    await refreshAll();
  } catch (err) { alert(err.message); }
});

byId("cameraForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const payload = Object.fromEntries(form.entries());
  payload.tags = (payload.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
  try {
    await api("/api/cameras", { method: "POST", headers: headers(), body: JSON.stringify(payload) });
    e.target.reset();
    await refreshAll();
  } catch (err) { alert(err.message); }
});

byId("refreshBtn").addEventListener("click", () => refreshAll().catch((e) => alert(e.message)));

byId("saveLayoutBtn").addEventListener("click", async () => {
  const payload = {
    name: byId("layoutName").value || "Default Layout",
    grid: byId("gridType").value,
    camera_ids: cameras.slice(0, 9).map((c) => c.id),
  };
  try {
    await api("/api/layouts", { method: "POST", headers: headers(), body: JSON.stringify(payload) });
    await loadLayouts();
  } catch (err) { alert(err.message); }
});

byId("runShodanBtn").addEventListener("click", async () => {
  const payload = {
    query: byId("shodanQuery").value.trim(),
    limit: Number(byId("scanLimit").value || "10"),
  };
  if (!payload.query) {
    alert("Enter a Shodan query.");
    return;
  }
  try {
    const res = await api("/api/scans/shodan", { method: "POST", headers: headers(), body: JSON.stringify(payload) });
    byId("scanStatus").textContent = `Imported ${res.imported}, updated ${res.updated}, skipped ${res.skipped}`;
    await refreshAll();
  } catch (err) {
    byId("scanStatus").textContent = err.message;
  }
});
byId("loginBtn").addEventListener("click", async () => {
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: byId("email").value, password: byId("password").value }),
    });
    token = data.token;
    byId("me").textContent = `${data.user.email} (${data.user.role})`;
    await refreshAll();
  } catch (err) { alert(err.message); }
});

byId("cameraForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  const payload = Object.fromEntries(form.entries());
  payload.tags = (payload.tags || "").split(",").map((t) => t.trim()).filter(Boolean);
  try {
    await api("/api/cameras", { method: "POST", headers: headers(), body: JSON.stringify(payload) });
    e.target.reset();
    await refreshAll();
  } catch (err) { alert(err.message); }
});

byId("refreshBtn").addEventListener("click", () => refreshAll().catch((e) => alert(e.message)));

byId("saveLayoutBtn").addEventListener("click", async () => {
  const payload = {
    name: byId("layoutName").value || "Default Layout",
    grid: byId("gridType").value,
    camera_ids: cameras.slice(0, 9).map((c) => c.id),
  };
  try {
    await api("/api/layouts", { method: "POST", headers: headers(), body: JSON.stringify(payload) });
    await loadLayouts();
  } catch (err) { alert(err.message); }
});

byId("shodanSearchBtn").addEventListener("click", async () => {
  try {
    const res = await api("/api/shodan/search", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ query: byId("shodanQuery").value || "webcam" }),
    });
    byId("shodanTotal").textContent = `${res.total} total matches`;
    shodanHosts = res.hosts;
    renderShodanHosts();
  } catch (err) { alert(err.message); }
});

byId("shodanImportBtn").addEventListener("click", async () => {
  const selected = [...document.querySelectorAll(".pick-host:checked")].map((n) => shodanHosts[Number(n.dataset.idx)]);
  try {
    const res = await api("/api/shodan/import", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ hosts: selected, default_location: byId("shodanLocation").value || "Internet" }),
    });
    alert(`Imported ${res.count} hosts`);
    await refreshAll();
  } catch (err) { alert(err.message); }
});
