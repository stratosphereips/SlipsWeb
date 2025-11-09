const REFRESH_MS = 15000;
const state = {
  evidences: [],
  filtered: [],
  ipSummary: [],
  calendarMonths: [],
  calendarIndex: 0,
  sort: { key: "severity_rank", dir: "desc" },
  ipFilter: null,
  dayFilter: null,
};

let timelineChart;

const pad = (num) => num.toString().padStart(2, "0");
const localDateKey = (date) =>
  `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
const severityClass = (sev) => `sev-chip sev-${sev}`;

const formatDateTime = (dateObj) => {
  if (!(dateObj instanceof Date) || Number.isNaN(dateObj.getTime())) return "--";
  return `${dateObj.toLocaleDateString()} ${dateObj.toLocaleTimeString()}`;
};

const formatBadgeDate = (key) => {
  if (!key) return "--";
  const [y, m, d] = key.split("-").map(Number);
  return new Date(y, m - 1, d).toLocaleDateString();
};

async function fetchDashboard() {
  try {
    const response = await fetch("/api/dashboard");
    if (!response.ok) throw new Error("Failed to load dashboard data");
    const payload = await response.json();

    state.evidences = decorateEvidences(payload.evidences || []);
    state.ipSummary = payload.ip_summary || [];
    rebuildCalendar();
    state.calendarIndex = state.calendarMonths.length
      ? state.calendarMonths.length - 1
      : 0;

    document.getElementById("lastUpdated").textContent = formatDateTime(
      new Date(payload.generated_at),
    );
    document.getElementById("collectionName").textContent =
      payload.summary?.collection || "Collection";
    document.getElementById("refreshInterval").textContent = `${Math.round(
      REFRESH_MS / 1000,
    )}s`;

    updateStats(payload.summary || {});
    updateTimelineChart(buildTimelineFromEvidences(state.evidences));
    renderIpList(state.ipSummary);
    renderCalendar();
    applyFilters();
  } catch (error) {
    console.error(error);
  }
}

function decorateEvidences(raw) {
  return raw.map((ev) => {
    const timestamp = ev.timestamp || ev.valid_from || ev.created;
    const timestampDate = timestamp ? new Date(timestamp) : null;
    return {
      ...ev,
      timestamp,
      timestampDate,
      localDate: timestampDate ? localDateKey(timestampDate) : null,
    };
  });
}

function updateStats(summary) {
  document.getElementById("statTotal").textContent =
    summary.total_evidences ?? 0;
  document.getElementById("statCritical").textContent = summary.critical ?? 0;
  document.getElementById("statHigh").textContent = summary.high ?? 0;
  document.getElementById("statIPs").textContent = summary.unique_ips ?? 0;
}

function buildTimelineFromEvidences(evidences) {
  const bucket = new Map();
  evidences.forEach((ev) => {
    const dateObj = ev.timestampDate;
    if (!(dateObj instanceof Date) || Number.isNaN(dateObj.getTime())) return;
    const minute = new Date(dateObj);
    minute.setSeconds(0, 0);
    const key = minute.getTime();
    bucket.set(key, (bucket.get(key) || 0) + 1);
  });
  return Array.from(bucket.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([time, count]) => ({
      label: new Date(time),
      count,
    }));
}

function updateTimelineChart(points) {
  const ctx = document.getElementById("timelineChart");
  const labels = points.map((p) => p.label.toLocaleTimeString());
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
            backgroundColor: "rgba(56,189,248,0.2)",
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

function applyFilters() {
  let filtered = [...state.evidences];
  if (state.ipFilter) {
    filtered = filtered.filter((ev) => ev.profile_ip === state.ipFilter);
  }
  if (state.dayFilter) {
    filtered = filtered.filter((ev) => ev.localDate === state.dayFilter);
  }
  state.filtered = sortData(filtered);
  renderEvidenceTable(state.filtered);
  updateTimelineChart(buildTimelineFromEvidences(state.filtered.length ? state.filtered : state.evidences));
  updateFilterBadge();
}

function sortData(data) {
  const { key, dir } = state.sort;
  const direction = dir === "asc" ? 1 : -1;
  const getValue = (ev) => {
    switch (key) {
      case "severity_rank":
        return ev.severity_rank;
      case "when":
        return ev.timestampDate?.getTime() || 0;
      case "name":
        return ev.name || "";
      case "profile_ip":
        return ev.profile_ip || "";
      case "victim":
        return ev.victim || "";
      case "ports":
        return `${ev.src_port || ""}-${ev.dst_port || ""}`;
      default:
        return ev[key] || 0;
    }
  };

  return [...data].sort((a, b) => {
    const valA = getValue(a);
    const valB = getValue(b);
    if (valA < valB) return -1 * direction;
    if (valA > valB) return 1 * direction;
    return 0;
  });
}

function setSort(key) {
  if (state.sort.key === key) {
    state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
  } else {
    state.sort = { key, dir: key === "severity_rank" ? "desc" : "asc" };
  }
  document.querySelectorAll("th[data-sort]").forEach((th) => {
    th.classList.toggle("active", th.dataset.sort === state.sort.key);
    if (th.dataset.sort === state.sort.key) {
      th.dataset.direction = state.sort.dir === "asc" ? "▲" : "▼";
    } else {
      th.dataset.direction = "";
    }
  });
  applyFilters();
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
    li.className = `ip-item${item.ip === state.ipFilter ? " active" : ""}`;
    li.innerHTML = `
      <h4>${item.ip}</h4>
      <p>${item.count} evidences • ${item.top_severity || "unknown"}</p>`;
    li.addEventListener("click", () => {
      state.ipFilter = state.ipFilter === item.ip ? null : item.ip;
      renderIpList(state.ipSummary);
      applyFilters();
      openDrawer("Host Details", buildIpDetail(item));
    });
    container.appendChild(li);
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
      <td>${formatDateTime(ev.timestampDate)}</td>
      <td>${ev.name || "Unnamed"}</td>
      <td>${ev.profile_ip || "--"}</td>
      <td>${ev.victim || "--"}</td>
      <td>${ev.src_port || "?"} → ${ev.dst_port || "?"}</td>`;
    tr.addEventListener("click", () => {
      openDrawer(ev.name || "Evidence", buildEvidenceDetail(ev));
    });
    tbody.appendChild(tr);
  });
}

function rebuildCalendar() {
  const months = new Map();
  state.evidences.forEach((ev) => {
    const dateObj = ev.timestampDate;
    if (!(dateObj instanceof Date) || Number.isNaN(dateObj.getTime())) return;
    const monthKey = `${dateObj.getFullYear()}-${pad(dateObj.getMonth() + 1)}`;
    if (!months.has(monthKey)) {
      months.set(monthKey, {
        year: dateObj.getFullYear(),
        month: dateObj.getMonth(),
        label: dateObj.toLocaleString(undefined, { month: "long", year: "numeric" }),
        days: new Map(),
      });
    }
    const monthEntry = months.get(monthKey);
    const dateKey = localDateKey(dateObj);
    const dayEntry = monthEntry.days.get(dateKey) || { total: 0 };
    dayEntry.total += 1;
    const sev = ev.severity || "info";
    dayEntry[sev] = (dayEntry[sev] || 0) + 1;
    monthEntry.days.set(dateKey, dayEntry);
  });

  state.calendarMonths = Array.from(months.values())
    .sort((a, b) =>
      a.year === b.year ? a.month - b.month : a.year - b.year,
    )
    .map((month) => {
      const totalDays = new Date(month.year, month.month + 1, 0).getDate();
      const days = [];
      for (let day = 1; day <= totalDays; day += 1) {
        const dateObj = new Date(month.year, month.month, day);
        const key = localDateKey(dateObj);
        const data = month.days.get(key) || { total: 0 };
        days.push({
          ...data,
          dateKey: key,
          label: day,
        });
      }
      return {
        label: month.label,
        startWeekday: new Date(month.year, month.month, 1).getDay(),
        days,
      };
    });
}

function renderCalendar() {
  const grid = document.getElementById("calendarGrid");
  const label = document.getElementById("calendarLabel");
  const prevBtn = document.getElementById("prevMonth");
  const nextBtn = document.getElementById("nextMonth");
  grid.innerHTML = "";

  if (!state.calendarMonths.length) {
    label.textContent = "No data";
    grid.innerHTML = "<div class='muted'>No activity</div>";
    prevBtn.disabled = true;
    nextBtn.disabled = true;
    return;
  }

  state.calendarIndex = Math.min(
    Math.max(state.calendarIndex, 0),
    state.calendarMonths.length - 1,
  );
  const month = state.calendarMonths[state.calendarIndex];
  label.textContent = month.label;
  prevBtn.disabled = state.calendarIndex === 0;
  nextBtn.disabled = state.calendarIndex === state.calendarMonths.length - 1;

  for (let i = 0; i < month.startWeekday; i += 1) {
    const empty = document.createElement("div");
    empty.className = "calendar-cell empty";
    grid.appendChild(empty);
  }

  month.days.forEach((day) => {
    const cell = document.createElement("div");
    cell.className = `calendar-cell${
      day.dateKey === state.dayFilter ? " active" : ""
    }`;
    const tone = deriveCalendarTone(day);
    cell.style.background = tone.background;
    cell.style.color = tone.color;
    cell.textContent = day.label;
    cell.title = `${day.total || 0} evidences`;
    cell.addEventListener("click", () => {
      state.dayFilter = state.dayFilter === day.dateKey ? null : day.dateKey;
      renderCalendar();
      applyFilters();
    });
    grid.appendChild(cell);
  });
}

function deriveCalendarTone(day) {
  const palette = {
    critical: "rgba(248,113,113,0.35)",
    high: "rgba(251,191,36,0.35)",
    medium: "rgba(52,211,153,0.35)",
    low: "rgba(34,211,238,0.35)",
  };
  for (const sev of ["critical", "high", "medium", "low"]) {
    if (day[sev]) {
      return { background: palette[sev], color: "#fff" };
    }
  }
  return { background: "rgba(148,163,184,0.15)", color: "var(--muted)" };
}

function updateFilterBadge() {
  const badge = document.getElementById("activeFilters");
  const filters = [];
  if (state.ipFilter) filters.push(`Host: ${state.ipFilter}`);
  if (state.dayFilter) filters.push(`Day: ${formatBadgeDate(state.dayFilter)}`);
  badge.textContent = filters.length ? filters.join(" • ") : "All activity";
}

function buildIpDetail(ipEntry) {
  if (!ipEntry) return "<p>No details</p>";
  const related = state.evidences.filter((ev) => ev.profile_ip === ipEntry.ip);
  const evidences = related
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
  return `
    <p><strong>Responsible IP:</strong> ${ipEntry.ip}</p>
    <p><strong>Total evidences:</strong> ${ipEntry.count}</p>
    <div class="detail-stack">${evidences}</div>`;
}

function buildEvidenceDetail(ev) {
  const flows = ev.flow_uids?.length
    ? ev.flow_uids.map((uid) => `<span class="flow-pill">${uid}</span>`).join(" ")
    : "<span class='muted'>No Flow IDs</span>";
  return `
    <div class="detail-card">
      <h4>${ev.name || "Evidence"}</h4>
      <p>${ev.description || "No description provided."}</p>
    </div>
    <p><strong>Responsible IP:</strong> ${ev.profile_ip || "--"} (${ev.direction || "?"})</p>
    <p><strong>Victim:</strong> ${ev.victim || "--"}</p>
    <p><strong>Ports:</strong> ${ev.src_port || "?"} → ${ev.dst_port || "?"}</p>
    <p><strong>Observed:</strong> ${formatDateTime(ev.timestampDate)}</p>
    <p><strong>Severity:</strong> ${ev.severity}</p>
    <div>
      <strong>Flow UIDs:</strong>
      <div class="flow-list">${flows}</div>
    </div>`;
}

function openDrawer(title, content) {
  document.getElementById("drawerTitle").textContent = title;
  document.getElementById("drawerBody").innerHTML = content;
  document.getElementById("detailDrawer").classList.add("open");
  document.getElementById("drawerBackdrop").classList.add("open");
}

function closeDrawer() {
  document.getElementById("detailDrawer").classList.remove("open");
  document.getElementById("drawerBackdrop").classList.remove("open");
}

function initSorting() {
  document.querySelectorAll("th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => setSort(th.dataset.sort));
  });
  setSort("severity_rank");
}

function init() {
  document
    .getElementById("clearIpFilter")
    ?.addEventListener("click", () => {
      state.ipFilter = null;
      renderIpList(state.ipSummary);
      applyFilters();
    });
  document
    .getElementById("clearDayFilter")
    ?.addEventListener("click", () => {
      state.dayFilter = null;
      renderCalendar();
      applyFilters();
    });
  document
    .getElementById("prevMonth")
    ?.addEventListener("click", () => {
      state.calendarIndex = Math.max(state.calendarIndex - 1, 0);
      renderCalendar();
    });
  document
    .getElementById("nextMonth")
    ?.addEventListener("click", () => {
      state.calendarIndex = Math.min(
        state.calendarIndex + 1,
        state.calendarMonths.length - 1,
      );
      renderCalendar();
    });
  document.getElementById("drawerClose").addEventListener("click", closeDrawer);
  document
    .getElementById("drawerBackdrop")
    .addEventListener("click", closeDrawer);

  initSorting();
  fetchDashboard();
  setInterval(fetchDashboard, REFRESH_MS);
}

document.addEventListener("DOMContentLoaded", init);
