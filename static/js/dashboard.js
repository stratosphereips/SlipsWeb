const REFRESH_MS = 15000;
let evidenceDataset = [];
let timelineChart;
let activeIp = null;

const severityClass = (sev) => `sev-chip sev-${sev}`;

const formatDate = (iso) => {
  if (!iso) return "--";
  const date = new Date(iso);
  return `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
};

async function fetchDashboard() {
  try {
    const response = await fetch("/api/dashboard");
    if (!response.ok) throw new Error("Failed to load dashboard data");
    const payload = await response.json();
    evidenceDataset = payload.evidences || [];
    document.getElementById("lastUpdated").textContent = formatDate(
      payload.generated_at,
    );
    document.getElementById("collectionName").textContent =
      payload.summary?.collection || "Collection";

    updateStats(payload.summary || {});
    updateTimeline(payload.timeline || []);
    renderIpList(payload.ip_summary || []);
    renderEvidenceTable(evidenceDataset);
    document.getElementById("refreshInterval").textContent = `${Math.round(
      REFRESH_MS / 1000,
    )}s`;
  } catch (error) {
    console.error(error);
  }
}

function updateStats(summary) {
  document.getElementById("statTotal").textContent =
    summary.total_evidences ?? 0;
  document.getElementById("statCritical").textContent = summary.critical ?? 0;
  document.getElementById("statHigh").textContent = summary.high ?? 0;
  document.getElementById("statIPs").textContent = summary.unique_ips ?? 0;
}

function updateTimeline(points) {
  const ctx = document.getElementById("timelineChart");
  const labels = points.map((p) => new Date(p.timestamp).toLocaleTimeString());
  const data = points.map((p) => p.count);
  if (!timelineChart) {
    timelineChart = new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: [
          {
            label: "Evidences",
            data,
            borderColor: "#38bdf8",
            backgroundColor: "rgba(56, 189, 248, 0.2)",
            tension: 0.4,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#94a3b8" } },
          y: { ticks: { color: "#94a3b8" }, beginAtZero: true },
        },
      },
    });
  } else {
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = data;
    timelineChart.update();
  }
}

function renderIpList(list) {
  const container = document.getElementById("ipList");
  container.innerHTML = "";
  if (!list.length) {
    container.innerHTML = "<li class=\"muted\">No data yet</li>";
    return;
  }
  list.forEach((item) => {
    const li = document.createElement("li");
    li.className = `ip-item${item.ip === activeIp ? " active" : ""}`;
    li.innerHTML = `
      <h4>${item.ip}</h4>
      <p>${item.count} evidences • ${
        item.top_severity || "unknown"
      } • Victim ${item.victim || "?"}</p>`;
    li.addEventListener("click", () => {
      activeIp = item.ip;
      highlightIp();
      showIpDetails(item.ip);
    });
    container.appendChild(li);
  });
}

function highlightIp() {
  document.querySelectorAll(".ip-item").forEach((node) => {
    if (node.querySelector("h4")?.textContent === activeIp) {
      node.classList.add("active");
    } else {
      node.classList.remove("active");
    }
  });
}

function renderEvidenceTable(evidences) {
  const tbody = document.querySelector("#evidenceTable tbody");
  tbody.innerHTML = "";
  evidences.forEach((ev) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="${severityClass(ev.severity)}">${
      ev.severity
    }</span></td>
      <td>${formatDate(ev.valid_from || ev.created)}</td>
      <td>${ev.name || "Unnamed"}</td>
      <td>${ev.profile_ip || "--"}</td>
      <td>${ev.victim || "--"}</td>
      <td>${ev.src_port || "?"} → ${ev.dst_port || "?"}</td>`;
    tr.addEventListener("click", () => showEvidence(ev));
    tbody.appendChild(tr);
  });
}

function showIpDetails(ip) {
  const related = evidenceDataset.filter((ev) => ev.profile_ip === ip);
  const detail = document.getElementById("detailContent");
  if (!related.length) {
    detail.innerHTML = `<p>No evidences associated with ${ip}.</p>`;
    return;
  }
  const items = related
    .map(
      (ev) => `
        <div class="detail-card">
          <h4>${ev.name || "Unnamed"}</h4>
          <p>${ev.description || "No description"}</p>
          <p><strong>Victim:</strong> ${ev.victim || "--"} • <strong>Severity:</strong> ${
        ev.severity
      }</p>
        </div>`,
    )
    .join("\n");
  detail.innerHTML = `
    <h4>Evidence linked to ${ip}</h4>
    <div class="detail-stack">${items}</div>`;
}

function showEvidence(ev) {
  const detail = document.getElementById("detailContent");
  const flows = ev.flow_uids?.length
    ? ev.flow_uids.map((uid) => `<span class="flow-pill">${uid}</span>`).join(" ")
    : "<p class=\"muted\">No flow IDs available</p>";
  detail.innerHTML = `
    <h4>${ev.name || "Evidence"}</h4>
    <p>${ev.description || "No description provided."}</p>
    <p><strong>Responsible IP:</strong> ${ev.profile_ip || "--"} (${ev.direction || "?"})</p>
    <p><strong>Victim:</strong> ${ev.victim || "--"}</p>
    <p><strong>Ports:</strong> ${ev.src_port || "?"} → ${ev.dst_port || "?"}</p>
    <p><strong>Severity:</strong> ${ev.severity}</p>
    <div>
      <strong>Flow UIDs:</strong>
      <div class="flow-list">${flows}</div>
    </div>`;
}

function init() {
  fetchDashboard();
  setInterval(fetchDashboard, REFRESH_MS);
}

document.addEventListener("DOMContentLoaded", init);
