const $ = (selector) => document.querySelector(selector);

const formatBytes = (value) => {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
  const bytes = Number(value);
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = bytes;
  let unit = -1;
  do { size /= 1024; unit += 1; } while (size >= 1024 && unit < units.length - 1);
  const digits = size >= 100 ? 1 : 2;
  return `${size.toFixed(digits)} ${units[unit]}`;
};

const formatDuration = (value) => {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "—";
  const seconds = Math.max(0, Math.round(Number(value)));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes < 60) return `${minutes}:${String(remainder).padStart(2, "0")}`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
};

const formatTokens = (value) => {
  const tokens = Number(value);
  if (!Number.isFinite(tokens)) return "—";
  if (tokens >= 1_000_000) return `${(tokens / 1_000_000).toFixed(tokens >= 10_000_000 ? 1 : 2)}M`;
  if (tokens >= 1_000) return `${(tokens / 1_000).toFixed(tokens >= 100_000 ? 0 : 1)}k`;
  return Math.round(tokens).toLocaleString();
};

const shortPath = (value) => {
  if (!value) return "No promoted artifact yet";
  const parts = String(value).split("/");
  return parts.slice(-2).join("/");
};

const emptyState = () => $("#empty-template").content.cloneNode(true);

const renderSlots = (slots) => {
  const target = $("#slots");
  target.replaceChildren();
  slots.forEach((slot, index) => {
    const article = document.createElement("article");
    article.className = "slot";
    article.dataset.state = slot.status;

    const head = document.createElement("div");
    head.className = "slot-head";
    const slotIndex = document.createElement("span");
    slotIndex.className = "slot-index";
    slotIndex.textContent = `SLOT ${String(index + 1).padStart(2, "0")}`;
    const status = document.createElement("span");
    status.className = "status-pill";
    status.textContent = slot.status || "waiting";
    head.append(slotIndex, status);

    const title = document.createElement("h3");
    title.textContent = slot.label;
    const lens = document.createElement("p");
    lens.className = "slot-lens";
    lens.textContent = slot.lens;

    const bottom = document.createElement("div");
    bottom.className = "slot-bottom";
    const timer = document.createElement("strong");
    timer.className = "timer";
    timer.textContent = slot.remaining_seconds === null ? "—" : formatDuration(slot.remaining_seconds);
    const summary = document.createElement("p");
    summary.className = "slot-summary";
    summary.textContent = slot.tokens_used === null || slot.tokens_used === undefined
      ? (slot.summary || (slot.iteration ? `Iteration ${slot.iteration}` : "Awaiting assignment"))
      : `${formatTokens(slot.tokens_used)} tokens${slot.cpu === null || slot.cpu === undefined ? "" : ` · CPU ${slot.cpu}`}`;
    bottom.append(timer, summary);

    article.append(head, title, lens, bottom);
    target.append(article);
  });
};

const SVG_NS = "http://www.w3.org/2000/svg";
let progressState = { points: [], attempts: [], tracked_tokens: 0, complete: true };
let chartTooltipState = { key: null, clientX: null, clientY: null, input: null };

const svgElement = (name, attributes = {}, text = null) => {
  const element = document.createElementNS(SVG_NS, name);
  Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
  if (text !== null) element.textContent = text;
  return element;
};

const tooltipMetric = (label, value, tone = "") => {
  const cell = document.createElement("div");
  cell.className = "tooltip-metric";
  const caption = document.createElement("span");
  caption.textContent = label;
  const result = document.createElement("strong");
  result.className = tone;
  result.textContent = value;
  cell.append(caption, result);
  return cell;
};

const tooltipCopy = (label, value) => {
  const paragraph = document.createElement("p");
  paragraph.className = "tooltip-copy";
  const title = document.createElement("strong");
  title.textContent = `${label}: `;
  paragraph.append(title, document.createTextNode(value));
  return paragraph;
};

const formatPointChange = (value) => {
  const bytes = Number(value);
  if (!Number.isFinite(bytes)) return { text: "Starting point", tone: "" };
  if (bytes > 0) return { text: `↓ ${formatBytes(bytes)}`, tone: "good" };
  if (bytes < 0) return { text: `↑ ${formatBytes(Math.abs(bytes))}`, tone: "bad" };
  return { text: "No change", tone: "" };
};

const positionChartTooltip = (anchor, clientX, clientY) => {
  const tooltip = $("#chart-tooltip");
  const wrap = $("#progress-chart-wrap");
  const wrapRect = wrap.getBoundingClientRect();
  const anchorRect = anchor.getBoundingClientRect();
  const x = Number.isFinite(clientX) ? clientX : anchorRect.left + anchorRect.width / 2;
  const y = Number.isFinite(clientY) ? clientY : anchorRect.top + anchorRect.height / 2;
  let left = x - wrapRect.left + 14;
  let top = y - wrapRect.top + 14;
  const width = tooltip.offsetWidth;
  const height = tooltip.offsetHeight;
  if (left + width > wrapRect.width - 8) left = x - wrapRect.left - width - 14;
  if (top + height > wrapRect.height - 8) top = y - wrapRect.top - height - 14;
  tooltip.style.left = `${Math.max(8, Math.min(left, wrapRect.width - width - 8))}px`;
  tooltip.style.top = `${Math.max(8, Math.min(top, wrapRect.height - height - 8))}px`;
};

const showChartTooltip = (point, kind, key, anchor, clientX = null, clientY = null, input = "mouse") => {
  const tooltip = $("#chart-tooltip");
  const experiment = point.experiment || {};
  const phase = experiment.phase || point.phase || point.kind || kind;
  const candidate = experiment.candidate_id || point.candidate_id || "—";
  const slot = experiment.slot && experiment.slot !== "—" ? ` · slot ${experiment.slot}` : "";
  const change = kind === "frontier" ? formatPointChange(point.drop_bytes) : null;
  const tokenText = point.token_gap
    ? `${Number(point.tokens).toLocaleString()} inferred`
    : Number(point.tokens).toLocaleString();

  const head = document.createElement("div");
  head.className = "tooltip-head";
  const badge = document.createElement("span");
  badge.className = "tooltip-badge";
  badge.textContent = kind === "frontier" ? `${phase} · best frontier` : phase;
  const id = document.createElement("span");
  id.className = "tooltip-id";
  id.textContent = `${candidate}${slot}`;
  head.append(badge, id);

  const title = document.createElement("h3");
  title.textContent = experiment.hypothesis
    || point.hypothesis
    || (kind === "frontier" ? "Validated best checkpoint" : "Recorded attempt");
  const metrics = document.createElement("div");
  metrics.className = "tooltip-metrics";
  metrics.append(
    tooltipMetric("File size", `${(Number(point.size_bytes) / 1_048_576).toFixed(3)} MiB`),
    tooltipMetric("Exact bytes", Number(point.size_bytes).toLocaleString()),
    tooltipMetric("Tokens", tokenText),
  );
  if (change) metrics.append(tooltipMetric("Frontier change", change.text, change.tone));
  if (experiment.elapsed_seconds !== null && experiment.elapsed_seconds !== undefined) {
    metrics.append(tooltipMetric("Writer time", `${Number(experiment.elapsed_seconds).toFixed(2)}s`));
  }
  if (kind === "attempt") {
    metrics.append(tooltipMetric("Gate result", experiment.accepted || point.accepted ? "Accepted" : phase));
  }

  const children = [head, title, metrics];
  if (experiment.tested_scope) children.push(tooltipCopy("Tested", experiment.tested_scope));
  if (experiment.observation) children.push(tooltipCopy("Result", experiment.observation));
  tooltip.replaceChildren(...children);
  tooltip.hidden = false;
  positionChartTooltip(anchor, clientX, clientY);
  chartTooltipState = { key, clientX, clientY, input };
};

const hideChartTooltip = (key = null, force = false) => {
  if (!force && key !== null && chartTooltipState.key !== key) return;
  $("#chart-tooltip").hidden = true;
  chartTooltipState = { key: null, clientX: null, clientY: null, input: null };
};

const bindChartPoint = (group, point, kind, key) => {
  group.addEventListener("mouseenter", (event) => {
    showChartTooltip(point, kind, key, group, event.clientX, event.clientY, "mouse");
  });
  group.addEventListener("mousemove", (event) => {
    showChartTooltip(point, kind, key, group, event.clientX, event.clientY, "mouse");
  });
  group.addEventListener("mouseleave", () => hideChartTooltip(key));
  group.addEventListener("focus", () => showChartTooltip(point, kind, key, group, null, null, "keyboard"));
  group.addEventListener("blur", () => hideChartTooltip(key));
};

const renderProgressChart = () => {
  const wrap = $("#progress-chart-wrap");
  const svg = $("#progress-chart");
  const empty = $("#progress-empty");
  const points = (progressState.points || [])
    .map((point) => ({ ...point, tokens: Number(point.tokens), size_bytes: Number(point.size_bytes) }))
    .filter((point) => Number.isFinite(point.tokens) && Number.isFinite(point.size_bytes))
    .sort((left, right) => left.tokens - right.tokens);
  const attempts = (progressState.attempts || [])
    .map((point) => ({ ...point, tokens: Number(point.tokens), size_bytes: Number(point.size_bytes) }))
    .filter((point) => Number.isFinite(point.tokens) && Number.isFinite(point.size_bytes))
    .sort((left, right) => left.tokens - right.tokens);
  const plotted = [...points, ...attempts];

  svg.replaceChildren();
  if (!plotted.length) {
    hideChartTooltip(null, true);
    svg.hidden = true;
    empty.hidden = false;
    return;
  }
  svg.hidden = false;
  empty.hidden = true;

  const width = Math.max(300, Math.floor(wrap.clientWidth));
  const compact = width < 540;
  const height = compact ? 300 : 340;
  const margin = compact
    ? { top: 25, right: 18, bottom: 58, left: 66 }
    : { top: 28, right: 24, bottom: 60, left: 76 };
  const frame = {
    x: margin.left,
    y: margin.top,
    width: width - margin.left - margin.right,
    height: height - margin.top - margin.bottom,
  };
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

  const maxTokens = Math.max(...plotted.map((point) => point.tokens), 1);
  const sizes = plotted.map((point) => point.size_bytes);
  const rawMinSize = Math.min(...sizes);
  const rawMaxSize = Math.max(...sizes);
  const sizeSpan = Math.max(rawMaxSize - rawMinSize, rawMaxSize * 0.01, 1);
  const minSize = rawMinSize - sizeSpan * 0.1;
  const maxSize = rawMaxSize + sizeSpan * 0.1;
  const x = (tokens) => frame.x + 6 + (tokens / (maxTokens * 1.06)) * (frame.width - 12);
  const y = (bytes) => frame.y + 6 + ((maxSize - bytes) / (maxSize - minSize)) * (frame.height - 12);

  svg.append(svgElement("rect", {
    class: "chart-frame", x: frame.x, y: frame.y, width: frame.width, height: frame.height,
  }));

  const tickCount = compact ? 3 : 4;
  for (let index = 0; index <= tickCount; index += 1) {
    const ratio = index / tickCount;
    const gridY = frame.y + frame.height * ratio;
    const size = maxSize - (maxSize - minSize) * ratio;
    svg.append(svgElement("line", {
      class: "chart-grid", x1: frame.x, y1: gridY, x2: frame.x + frame.width, y2: gridY,
    }));
    svg.append(svgElement("text", {
      class: "chart-tick", x: frame.x - 9, y: gridY + 4, "text-anchor": "end",
    }, (size / 1_048_576).toFixed(1)));

    const gridX = frame.x + frame.width * ratio;
    const tokens = maxTokens * 1.06 * ratio;
    svg.append(svgElement("line", {
      class: "chart-tick-line", x1: gridX, y1: frame.y + frame.height, x2: gridX, y2: frame.y + frame.height + 5,
    }));
    svg.append(svgElement("text", {
      class: "chart-tick", x: gridX, y: frame.y + frame.height + 20, "text-anchor": "middle",
    }, formatTokens(tokens)));
  }

  svg.append(svgElement("text", {
    class: "chart-axis-title", x: frame.x + frame.width / 2, y: height - 8, "text-anchor": "middle",
  }, "Cumulative tracked tokens"));
  svg.append(svgElement("text", {
    class: "chart-axis-title",
    transform: `translate(15 ${frame.y + frame.height / 2}) rotate(-90)`,
    "text-anchor": "middle",
  }, "File size (MiB)"));

  if (points.length) {
    let path = `M ${x(points[0].tokens)} ${y(points[0].size_bytes)}`;
    points.slice(1).forEach((point) => {
      path += ` H ${x(point.tokens)} V ${y(point.size_bytes)}`;
    });
    svg.append(svgElement("path", { class: "progress-line", d: path }));
  }

  const renderedPoints = new Map();
  attempts.forEach((point, index) => {
    const key = `attempt:${point.candidate_id}:${point.tokens}:${point.size_bytes}:${index}`;
    const group = svgElement("g", {
      class: "chart-point", tabindex: 0, role: "img",
      "aria-label": `${point.hypothesis || "Experiment"}, ${point.size_bytes.toLocaleString()} bytes`,
      "data-point-key": key,
    });
    group.append(svgElement("circle", {
      class: "chart-hit", cx: x(point.tokens), cy: y(point.size_bytes), r: 10,
    }));
    const marker = svgElement("circle", {
      class: point.accepted ? "attempt-mark accepted" : "attempt-mark",
      cx: x(point.tokens), cy: y(point.size_bytes), r: point.accepted ? 4.5 : 3,
    });
    group.append(marker);
    bindChartPoint(group, point, "attempt", key);
    renderedPoints.set(key, { group, point, kind: "attempt" });
    svg.append(group);
  });

  points.forEach((point, index) => {
    const key = `frontier:${point.candidate_id}:${point.tokens}:${point.size_bytes}:${index}`;
    const group = svgElement("g", {
      class: "chart-point", tabindex: 0, role: "img",
      "aria-label": `${point.experiment?.hypothesis || "Validated best"}, ${point.size_bytes.toLocaleString()} bytes`,
      "data-point-key": key,
    });
    group.append(svgElement("circle", {
      class: "chart-hit", cx: x(point.tokens), cy: y(point.size_bytes), r: 12,
    }));
    const marker = svgElement("circle", {
      class: point.token_gap ? "progress-mark gap" : (point.live ? "progress-mark live" : "progress-mark"),
      cx: x(point.tokens), cy: y(point.size_bytes), r: 5,
    });
    group.append(marker);
    bindChartPoint(group, point, "frontier", key);
    renderedPoints.set(key, { group, point, kind: "frontier" });
    svg.append(group);
    if (index === 0 || index === points.length - 1) {
      const first = index === 0;
      svg.append(svgElement("text", {
        class: "chart-value",
        x: x(point.tokens) + (first ? 9 : -9),
        y: y(point.size_bytes) - 12,
        "text-anchor": first ? "start" : "end",
      }, `${(point.size_bytes / 1_048_576).toFixed(3)} MiB`));
    }
  });

  if (chartTooltipState.key && renderedPoints.has(chartTooltipState.key)) {
    const active = renderedPoints.get(chartTooltipState.key);
    showChartTooltip(
      active.point, active.kind, chartTooltipState.key, active.group,
      chartTooltipState.clientX, chartTooltipState.clientY, chartTooltipState.input,
    );
  } else if (chartTooltipState.key) {
    hideChartTooltip(null, true);
  }
};

const renderProgress = (progress) => {
  progressState = progress || { points: [], attempts: [], tracked_tokens: 0, complete: true };
  const meta = $("#progress-meta");
  if (!progressState.points?.length) {
    meta.textContent = "Waiting for token telemetry";
  } else {
    meta.textContent = `${progressState.attempt_count || 0} sized attempts · ${formatTokens(progressState.tracked_tokens)} tracked${progressState.complete ? "" : " · partial history"}`;
  }
  renderProgressChart();
};

const renderSubmissions = (records) => {
  const target = $("#submissions");
  target.replaceChildren();
  $("#gate-state").textContent = `${window.dashboardGateStatus || "idle"} · ${records.length}`;
  if (!records.length) {
    target.append(emptyState());
    return;
  }
  [...records].reverse().slice(0, 10).forEach((record) => {
    const row = document.createElement("article");
    row.className = "submission";
    const slot = document.createElement("span");
    slot.className = "record-slot";
    slot.textContent = record.slot === "—" ? "gate" : `slot ${record.slot}`;
    const main = document.createElement("div");
    main.className = "record-main";
    const title = document.createElement("strong");
    title.textContent = record.hypothesis;
    const detail = document.createElement("span");
    detail.textContent = record.reason || record.id;
    main.append(title, detail);
    const size = document.createElement("span");
    size.className = "record-size";
    size.textContent = formatBytes(record.size_bytes);
    const status = document.createElement("span");
    status.className = `gate-status ${record.status}`;
    status.textContent = record.status;
    row.append(slot, main, size, status);
    target.append(row);
  });
};

const renderTrials = (records) => {
  const target = $("#trials");
  target.replaceChildren();
  $("#trial-count").textContent = records.length;
  if (!records.length) {
    target.append(emptyState());
    return;
  }
  [...records].reverse().slice(0, 10).forEach((record) => {
    const row = document.createElement("article");
    row.className = "trial";
    const slot = document.createElement("span");
    slot.className = "record-slot";
    slot.textContent = record.slot === "—" ? "trial" : `slot ${record.slot}`;
    const main = document.createElement("div");
    main.className = "record-main";
    const title = document.createElement("strong");
    title.textContent = record.hypothesis;
    const detail = document.createElement("span");
    detail.textContent = record.observation;
    main.append(title, detail);
    const size = document.createElement("span");
    size.className = "record-size";
    size.textContent = formatBytes(record.size_bytes);
    row.append(slot, main, size);
    target.append(row);
  });
};

const render = (state) => {
  window.dashboardGateStatus = state.gate_status || "idle";
  $("#system-status").textContent = state.system_status || "waiting";
  $("#updated").textContent = `updated ${new Date(state.generated_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}`;
  $("#cohort").textContent = state.cohort ?? "—";

  $("#best-size").textContent = state.best.size_bytes === null ? "Waiting" : formatBytes(state.best.size_bytes);
  $("#best-artifact").textContent = shortPath(state.best.artifact);
  $("#candidate-id").textContent = state.best.candidate_id || "—";
  $("#baseline-size").textContent = formatBytes(state.baseline.size_bytes);
  $("#baseline-runtime").textContent = state.baseline.write_seconds === null ? "Awaiting bootstrap" : `${formatDuration(state.baseline.write_seconds)} measured write`;
  $("#runtime-cap").textContent = formatDuration(state.baseline.runtime_cap_seconds);

  const change = $("#improvement");
  const delta = state.best.improvement_bytes;
  change.className = "change neutral";
  if (delta === null) {
    change.textContent = "No comparison yet";
  } else if (delta > 0) {
    change.className = "change good";
    change.textContent = `↓ ${formatBytes(delta)} · ${state.best.improvement_percent.toFixed(2)}%`;
  } else if (delta < 0) {
    change.className = "change bad";
    change.textContent = `↑ ${formatBytes(Math.abs(delta))} from baseline`;
  } else {
    change.textContent = "Matches baseline";
  }

  renderSlots(state.slots);
  $("#slot-count-note").textContent = `${state.slots.length} CPU-pinned slots · 15-minute maximum · immediate refill`;
  renderProgress(state.progress);
  renderSubmissions(state.submissions);
  renderTrials(state.trials);

  const warning = $("#warning");
  if (state.warnings?.length) {
    warning.hidden = false;
    warning.textContent = state.warnings.join(" · ");
  } else {
    warning.hidden = true;
    warning.textContent = "";
  }
};

let loading = false;
const refresh = async () => {
  if (loading) return;
  loading = true;
  try {
    const response = await fetch("/api/state", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
    $(".pulse").classList.remove("offline");
  } catch (error) {
    $("#system-status").textContent = "offline";
    $(".pulse").classList.add("offline");
    const warning = $("#warning");
    warning.hidden = false;
    warning.textContent = `Dashboard connection lost: ${error.message}`;
  } finally {
    loading = false;
  }
};

refresh();
window.setInterval(refresh, 2000);
new ResizeObserver(renderProgressChart).observe($("#progress-chart-wrap"));
