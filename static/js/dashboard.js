const REFRESH_MS = 15000;
const SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"];
const DEFAULT_PAGE_SIZE = 100;

const state = {
  evidences: [],
  filtered: [],
  ipSummary: [],
  calendarMonths: [],
  calendarIndex: 0,
  sort: { key: "severity_rank", dir: "desc" },
  ipFilter: null,
  dayFilter: null,
  severityFilter: new Set(),
  searchQuery: "",
  groupByIp: false,
  pageSize: DEFAULT_PAGE_SIZE,
  pageIndex: 0,
  pageTokens: [null],
  timelinePoints: [],
};

let timelineChart;
let chartRetryTimer = null;

const pad = (num) => num.toString().padStart(2, "0");
const localDateKey = (date) =>
  `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
const severityClass = (sev) => `sev-chip sev-${sev}`;

const formatDateTime = (dateObj) => {
  if (!(dateObj instanceof Date) || Number.isNaN(dateObj.getTime())) return "--";
  return `${dateObj.toLocaleDateString()} ${dateObj.toLocaleTimeString()}`;
};

const formatField = (value, fallback = "--") => {
  if (value === null || value === undefined) return fallback;
  if (Array.isArray(value)) {
    const joined = value.filter(Boolean).join(", ");
    return joined || fallback;
  }
  if (typeof value === "object") {
    if ("value" in value && value.value !== undefined) {
      return String(value.value);
    }
    if ("ip" in value && value.ip !== undefined) {
      return String(value.ip);
    }
    try {
      return JSON.stringify(value);
    } catch (err) {
      return fallback;
    }
  }
  const text = String(value);
  return text.trim() ? text : fallback;
};

const formatPort = (value, fallback = "?") => {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "object") {
    if (Object.prototype.hasOwnProperty.call(value, "value")) {
      return String(value.value);
    }
    if (Object.prototype.hasOwnProperty.call(value, "port")) {
      return String(value.port);
    }
    try {
      return JSON.stringify(value);
    } catch (err) {
      return fallback;
    }
  }
  return String(value);
};

const DESCRIPTION_DST_PORT_RE = /destination\\s+port\\s+(\\d+)/i;
const DESCRIPTION_PORT_RE = /port\\s+(\\d+)/i;
const DESCRIPTION_SRC_PORT_RE = /src(?:\\s*|_)?port\\s*(\\d+)/i;
const DESCRIPTION_DST_IP_RE = /destination\\s+ip\\s+([0-9a-fA-F:.]+)/i;
const DESCRIPTION_VICTIM_RE = /victim\\s+([0-9a-fA-F:.]+)/i;

function normalizeEvidence(ev) {
  let victim = ev.victim;
  if (victim && typeof victim === "object") {
    if (Object.prototype.hasOwnProperty.call(victim, "value")) {
      victim = victim.value;
    } else if (Object.prototype.hasOwnProperty.call(victim, "ip")) {
      victim = victim.ip;
    } else {
      try {
        victim = JSON.stringify(victim);
      } catch (err) {
        victim = null;
      }
    }
  }

  let srcPort = ev.src_port;
  let dstPort = ev.dst_port;
  const description = ev.description || "";
  if (!victim && description) {
    const ipMatch = DESCRIPTION_DST_IP_RE.exec(description);
    if (ipMatch) {
      victim = ipMatch[1];
    } else {
      const victimMatch = DESCRIPTION_VICTIM_RE.exec(description);
      if (victimMatch) victim = victimMatch[1];
    }
  }
  if ((!srcPort || !dstPort) && description) {
    const srcMatch = DESCRIPTION_SRC_PORT_RE.exec(description);
    if (!srcPort && srcMatch) srcPort = Number.parseInt(srcMatch[1], 10);
    const dstMatch = DESCRIPTION_DST_PORT_RE.exec(description);
    if (!dstPort && dstMatch) dstPort = Number.parseInt(dstMatch[1], 10);
    if (!dstPort) {
      const portMatch = DESCRIPTION_PORT_RE.exec(description);
      if (portMatch) dstPort = Number.parseInt(portMatch[1], 10);
    }
  }

  return {
    ...ev,
    victim: victim ?? ev.victim,
    src_port: srcPort ?? ev.src_port,
    dst_port: dstPort ?? ev.dst_port,
  };
}

const formatBadgeDate = (key) => {
  if (!key) return "--";
  const [y, m, d] = key.split("-").map(Number);
  return new Date(y, m - 1, d).toLocaleDateString();
};

function buildDashboardUrl() {
  const params = new URLSearchParams();
  params.set("limit", state.pageSize);
  const token = state.pageTokens[state.pageIndex];
  if (token) {
    params.set("next", token);
  }
  const qs = params.toString();
  return qs ? `/api/dashboard?${qs}` : "/api/dashboard";
}

function updatePaginationControls() {
  const prev = document.getElementById("pagePrev");
  const next = document.getElementById("pageNext");
  const indicator = document.getElementById("pageIndicator");
  if (indicator) {
    const count = state.evidences.length || 0;
    indicator.textContent = `Page ${state.pageIndex + 1} • ${count} items`;
  }
  if (prev) prev.disabled = state.pageIndex === 0;
  if (next) {
    const nextToken = state.pageTokens[state.pageIndex + 1];
    next.disabled = !nextToken;
  }
}

function resetPaging() {
  state.pageIndex = 0;
  state.pageTokens = [null];
  updatePaginationControls();
}

async function fetchDashboard() {
  try {
    const response = await fetch(buildDashboardUrl(), { cache: "no-store" });
    if (!response.ok) throw new Error("Failed to load dashboard data");
    const payload = await response.json();

    state.evidences = decorateEvidences(payload.evidences || []);
    state.ipSummary = payload.ip_summary || [];
    rebuildCalendar();
    state.calendarIndex = state.calendarMonths.length
      ? state.calendarMonths.length - 1
      : 0;

    if (payload.page?.limit && payload.page.limit !== state.pageSize) {
      state.pageSize = payload.page.limit;
      const pageSelect = document.getElementById("pageSizeSelect");
      if (pageSelect) pageSelect.value = String(state.pageSize);
    }

    document.getElementById("lastUpdated").textContent = formatDateTime(
      new Date(payload.generated_at),
    );
    document.getElementById("collectionName").textContent =
      payload.summary?.collection || "Collection";
    document.getElementById("refreshInterval").textContent = `${Math.round(
      REFRESH_MS / 1000,
    )}s`;
    const clearButton = document.getElementById("clearMedallion");
    if (clearButton) {
      if (payload.backend === "opentaxii") {
        clearButton.disabled = true;
        clearButton.textContent = "Clear Alerts (N/A)";
      } else {
        clearButton.disabled = false;
        clearButton.textContent = "Clear Alerts";
      }
    }

    updateStats(payload.summary || {});
    renderIpList(state.ipSummary);
    renderCalendar();
    applyFilters();

    const nextToken = payload.page?.next || null;
    if (nextToken) {
      state.pageTokens[state.pageIndex + 1] = nextToken;
    } else {
      state.pageTokens = state.pageTokens.slice(0, state.pageIndex + 1);
    }
    updatePaginationControls();
  } catch (error) {
    console.error(error);
  }
}

function decorateEvidences(raw) {
  return raw.map((ev) => {
    const normalized = normalizeEvidence(ev);
    const timestamp =
      normalized.timestamp || normalized.valid_from || normalized.created;
    const timestampDate = timestamp ? new Date(timestamp) : null;
    const createdDate = normalized.created
      ? new Date(normalized.created)
      : null;
    const modifiedDate = normalized.modified
      ? new Date(normalized.modified)
      : null;
    const allowFallback = normalized.time_diff_ok !== false;
    const timeDiffSeconds =
      typeof normalized.time_diff_seconds === "number" &&
      Number.isFinite(normalized.time_diff_seconds)
        ? normalized.time_diff_seconds
        : allowFallback && createdDate && timestampDate
          ? Math.round(Math.abs((createdDate - timestampDate) / 1000))
          : null;
    return {
      ...normalized,
      timestamp,
      timestampDate,
      createdDate,
      modifiedDate,
      time_diff_seconds: timeDiffSeconds,
      localDate: timestampDate ? localDateKey(timestampDate) : null,
    };
  });
}

function updateStats(summary) {
  document.getElementById("statTotal").textContent =
    summary.total_evidences ?? 0;
  document.getElementById("statCritical").textContent = summary.critical ?? 0;
  document.getElementById("statHigh").textContent = summary.high ?? 0;
  const uniqueIps =
    summary.unique_ips ?? (state.ipSummary ? state.ipSummary.length : 0);
  document.getElementById("statIPs").textContent = uniqueIps;
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
  state.timelinePoints = points;
  if (typeof window.Chart === "undefined") {
    if (!chartRetryTimer) {
      chartRetryTimer = setTimeout(() => {
        chartRetryTimer = null;
        updateTimelineChart(state.timelinePoints || []);
      }, 200);
    }
    return;
  }
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

function matchesSearch(ev, query) {
  const tokens = query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
  if (!tokens.length) return true;
  const { text, numericTokens } = buildSearchIndex(ev);
  return tokens.every((token) => {
    if (/^\d+$/.test(token)) {
      return numericTokens.has(token);
    }
    return text.includes(token);
  });
}

function buildSearchIndex(ev) {
  const src = ev.src_port != null ? String(ev.src_port) : "";
  const dst = ev.dst_port != null ? String(ev.dst_port) : "";
  const ports = src || dst ? `${src}:${dst}` : "";
  const parts = [
    ev.id,
    ev.stix_id,
    ev.name,
    ev.description,
    ev.evidence_signal,
    ev.profile_ip,
    formatField(ev.victim, ""),
    ev.direction,
    ev.severity,
    ev.ti_source,
    ev.pattern,
    ev.timestamp,
    ev.created,
    ev.modified,
    ev.labels?.join(" "),
    ev.flow_uids?.join(" "),
    src,
    dst,
    ports,
    ev.time_diff_seconds != null ? String(ev.time_diff_seconds) : "",
    ev.createdDate ? formatDateTime(ev.createdDate) : "",
    ev.timestampDate ? formatDateTime(ev.timestampDate) : "",
    ev.modifiedDate ? formatDateTime(ev.modifiedDate) : "",
  ].filter(Boolean);
  const text = parts.join(" ").toLowerCase();
  const numericTokens = new Set();
  const numericParts = [
    ev.profile_ip,
    formatField(ev.victim, ""),
    src,
    dst,
    ports,
    ev.timestamp,
    ev.created,
    ev.modified,
    ev.createdDate ? formatDateTime(ev.createdDate) : "",
    ev.timestampDate ? formatDateTime(ev.timestampDate) : "",
    ev.modifiedDate ? formatDateTime(ev.modifiedDate) : "",
    ev.time_diff_seconds != null ? String(ev.time_diff_seconds) : "",
  ].filter(Boolean);
  numericParts.forEach((part) => {
    const matches = String(part).match(/\d+/g);
    if (matches) {
      matches.forEach((match) => numericTokens.add(match));
    }
  });
  return { text, numericTokens };
}

function applyFilters() {
  let filtered = [...state.evidences];
  if (state.ipFilter) {
    filtered = filtered.filter((ev) => ev.profile_ip === state.ipFilter);
  }
  if (state.dayFilter) {
    filtered = filtered.filter((ev) => ev.localDate === state.dayFilter);
  }
  if (state.severityFilter.size) {
    filtered = filtered.filter((ev) => state.severityFilter.has(ev.severity));
  }
  if (state.searchQuery) {
    filtered = filtered.filter((ev) => matchesSearch(ev, state.searchQuery));
  }
  state.filtered = sortData(filtered);
  renderEvidenceTable(state.filtered);
  updateTimelineChart(buildTimelineFromEvidences(state.filtered));
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
      case "created":
        return ev.createdDate?.getTime() || 0;
      case "modified":
        return ev.modifiedDate?.getTime() || 0;
      case "name":
        return ev.name || "";
      case "profile_ip":
        return ev.profile_ip || "";
      case "victim":
        return ev.victim || "";
      case "ports":
        return `${ev.src_port || ""}-${ev.dst_port || ""}`;
      case "time_diff": {
        const diff = getTimeDiffSeconds(ev);
        return Number.isFinite(diff) ? diff : Number.MAX_SAFE_INTEGER;
      }
      case "ti_source":
        return ev.ti_source || "";
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
  const columnCount =
    document.querySelectorAll("#evidenceTable thead th").length || 1;

  if (!evidences.length) {
    const empty = document.createElement("tr");
    empty.innerHTML = `<td colspan="${columnCount}" class="muted">No evidences match the current filters.</td>`;
    tbody.appendChild(empty);
    return;
  }

  const addRow = (ev) => {
    const victimText = formatField(ev.victim);
    const srcPortText = formatPort(ev.src_port);
    const dstPortText = formatPort(ev.dst_port);
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="${severityClass(ev.severity)}">${
        ev.severity
      }</span></td>
      <td>${formatDateTime(ev.createdDate)}</td>
      <td>${formatDateTime(ev.timestampDate)}</td>
      <td class="name-cell">${ev.name || "Unnamed"}</td>
      <td>${ev.profile_ip || "--"}</td>
      <td>${victimText}</td>
      <td>${srcPortText} → ${dstPortText}</td>
      <td>${formatTimeDiff(ev)}</td>
      <td>${ev.ti_source || "—"}</td>`;
    tr.addEventListener("click", () => {
      openDrawer(ev.name || "Evidence", buildEvidenceDetail(ev));
    });
    tbody.appendChild(tr);
  };

  if (!state.groupByIp) {
    evidences.forEach(addRow);
    return;
  }

  const groups = new Map();
  evidences.forEach((ev) => {
    const key = ev.profile_ip || "Unassigned";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(ev);
  });

  const ordered = Array.from(groups.entries()).sort(
    (a, b) => b[1].length - a[1].length,
  );

  ordered.forEach(([ip, list]) => {
    const header = document.createElement("tr");
    header.className = "group-row";
    header.innerHTML = `<td colspan="${columnCount}">
      ${ip} • ${list.length} evidence${list.length === 1 ? "" : "s"}
    </td>`;
    tbody.appendChild(header);
    list.forEach(addRow);
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
    info: "rgba(96,165,250,0.35)",
  };
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
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
  if (state.severityFilter.size) {
    filters.push(
      `Severity: ${Array.from(state.severityFilter)
        .map((sev) => sev[0].toUpperCase() + sev.slice(1))
        .join(", ")}`,
    );
  }
  if (state.searchQuery) {
    filters.push(`Search: ${state.searchQuery}`);
  }
  badge.textContent = filters.length ? filters.join(" • ") : "All activity";
}

async function clearMedallionData() {
  const button = document.getElementById("clearMedallion");
  if (!button || button.disabled) return;
  const confirmed = window.confirm(
    "Clear all alerts from the TAXII server? This cannot be undone.",
  );
  if (!confirmed) return;

  const originalText = button.textContent;
  button.disabled = true;
  button.textContent = "Clearing...";

  try {
    const response = await fetch("/api/alerts/clear", { method: "POST" });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || "Failed to clear alerts");
    }
    const deleted = payload.deleted ?? 0;
    button.textContent = `Cleared ${deleted}`;
    await fetchDashboard();
    setTimeout(() => {
      button.textContent = originalText;
      button.disabled = false;
    }, 2000);
  } catch (error) {
    console.error(error);
    button.textContent = originalText;
    button.disabled = false;
    alert(error.message || "Failed to clear alerts");
  }
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
          <p><strong>Victim:</strong> ${formatField(ev.victim)} • <strong>Severity:</strong> ${
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
  const victimText = formatField(ev.victim);
  const srcPortText = formatPort(ev.src_port);
  const dstPortText = formatPort(ev.dst_port);
  const flows = ev.flow_uids?.length
    ? ev.flow_uids.map((uid) => `<span class="flow-pill">${uid}</span>`).join(" ")
    : "<span class='muted'>No Flow IDs</span>";
  const tiMarkup = ev.ti_source
    ? `<p><strong>Threat Intel Source:</strong> ${ev.ti_source}</p>`
    : "";
  const signalMarkup = `<p><strong>Evidence Signal:</strong> ${
    ev.evidence_signal || "PAMP"
  }</p>`;
  return `
    <div class="detail-card">
      <h4>${ev.name || "Evidence"}</h4>
      <p>${ev.description || "No description provided."}</p>
    </div>
    <p><strong>Responsible IP:</strong> ${ev.profile_ip || "--"} (${ev.direction || "?"})</p>
    <p><strong>Victim:</strong> ${victimText}</p>
    <p><strong>Ports:</strong> ${srcPortText} → ${dstPortText}</p>
    <p><strong>Created:</strong> ${formatDateTime(ev.createdDate)}</p>
    <p><strong>Updated:</strong> ${formatDateTime(ev.modifiedDate)}</p>
    <p><strong>Observed:</strong> ${formatDateTime(ev.timestampDate)}</p>
    <p><strong>Severity:</strong> ${ev.severity}</p>
    ${signalMarkup}
    <p><strong>Time Diff:</strong> ${formatTimeDiff(ev)} (flow vs. evidence)</p>
    ${tiMarkup}
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

function updateSeverityButtons() {
  const buttons = document.querySelectorAll("#severityFilters button");
  if (!buttons.length) return;
  buttons.forEach((btn) => {
    const sev = btn.dataset.severity;
    const active =
      sev === "all"
        ? state.severityFilter.size === 0
        : state.severityFilter.has(sev);
    btn.classList.toggle("active", active);
  });
}

function initSeverityFilters() {
  const buttons = document.querySelectorAll("#severityFilters button");
  if (!buttons.length) return;
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const sev = btn.dataset.severity;
      if (sev === "all") {
        state.severityFilter.clear();
      } else {
        if (state.severityFilter.has(sev)) {
          state.severityFilter.delete(sev);
        } else {
          state.severityFilter.add(sev);
        }
      }
      updateSeverityButtons();
      applyFilters();
    });
  });
  updateSeverityButtons();
}

function initGroupToggle() {
  const toggle = document.getElementById("groupByIpToggle");
  if (!toggle) return;
  toggle.addEventListener("click", () => {
    state.groupByIp = !state.groupByIp;
    toggle.classList.toggle("active", state.groupByIp);
    toggle.textContent = state.groupByIp ? "Ungroup" : "Group by IP";
    renderEvidenceTable(state.filtered);
  });
}

function getTimeDiffSeconds(ev) {
  if (typeof ev.time_diff_seconds === "number" && Number.isFinite(ev.time_diff_seconds)) {
    return ev.time_diff_seconds;
  }
  const createdValid =
    ev.createdDate instanceof Date && !Number.isNaN(ev.createdDate.getTime());
  const observedValid =
    ev.timestampDate instanceof Date && !Number.isNaN(ev.timestampDate.getTime());
  if (createdValid && observedValid) {
    return Math.round(
      Math.abs(ev.createdDate.getTime() - ev.timestampDate.getTime()) / 1000,
    );
  }
  return null;
}

function formatTimeDiff(ev) {
  const seconds = getTimeDiffSeconds(ev);
  if (!Number.isFinite(seconds)) return "—";
  if (seconds === 0) return "0s";
  const units = [
    { label: "d", value: 86400 },
    { label: "h", value: 3600 },
    { label: "m", value: 60 },
    { label: "s", value: 1 },
  ];
  const parts = [];
  let remaining = seconds;
  units.forEach(({ label, value }) => {
    if (remaining >= value) {
      const count = Math.floor(remaining / value);
      remaining %= value;
      parts.push(`${count}${label}`);
    }
  });
  return parts.slice(0, 2).join(" ") || "0s";
}

function init() {
  const observedHeader = document.querySelector('th[data-sort="when"]');
  if (observedHeader) {
    observedHeader.textContent = "Observed";
    observedHeader.title = "Flow observed timestamp";
  }
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
  document
    .getElementById("clearMedallion")
    ?.addEventListener("click", clearMedallionData);

  const pageSelect = document.getElementById("pageSizeSelect");
  if (pageSelect) {
    pageSelect.value = String(state.pageSize);
    pageSelect.addEventListener("change", () => {
      const value = Number.parseInt(pageSelect.value, 10);
      if (Number.isFinite(value) && value > 0) {
        state.pageSize = value;
        resetPaging();
        fetchDashboard();
      }
    });
  }

  const searchInput = document.getElementById("searchInput");
  if (searchInput) {
    searchInput.value = state.searchQuery;
    searchInput.addEventListener("input", () => {
      state.searchQuery = searchInput.value.trim();
      applyFilters();
    });
  }

  document.getElementById("pagePrev")?.addEventListener("click", () => {
    if (state.pageIndex === 0) return;
    state.pageIndex -= 1;
    fetchDashboard();
  });

  document.getElementById("pageNext")?.addEventListener("click", () => {
    const nextToken = state.pageTokens[state.pageIndex + 1];
    if (!nextToken) return;
    state.pageIndex += 1;
    fetchDashboard();
  });

  updatePaginationControls();

  initSorting();
  initSeverityFilters();
  initGroupToggle();
  fetchDashboard();
  setInterval(fetchDashboard, REFRESH_MS);
}

document.addEventListener("DOMContentLoaded", init);
