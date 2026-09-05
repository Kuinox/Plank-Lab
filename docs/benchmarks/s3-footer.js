(function () {
  "use strict";
  const colors = ["#128c7e", "#c88723", "#687ed5", "#be6ca7"];
  const integer = value => Number.isSafeInteger(value) && value >= 0;
  const finite = value => Number.isFinite(value) && value >= 0;

  function validateReport(data) {
    const d = data?.dataset;
    if (data?.schemaVersion !== 1 || !d || typeof d.name !== "string" ||
        !integer(d.fileSizeBytes) || !integer(d.footerOffset) || !integer(d.footerLengthBytes) ||
        d.fileSizeBytes < 12 || d.footerOffset < 4 || d.footerLengthBytes < 1 ||
        d.footerOffset + d.footerLengthBytes + 8 !== d.fileSizeBytes ||
        !Array.isArray(data.runs) || data.runs.length === 0)
      throw new Error("This is not a valid S3 footer result (schema version 1).");
    const runs = new Set();
    for (const r of data.runs) {
      const key = JSON.stringify([r.library, r.iteration]);
      if (typeof r.library !== "string" || !r.library || !integer(r.iteration) || r.iteration < 1 ||
          !finite(r.elapsedMs) || !Array.isArray(r.requests) || runs.has(key) ||
          (r.error != null && typeof r.error !== "string"))
        throw new Error("The result contains an invalid or duplicate trial.");
      runs.add(key);
      const ids = new Set();
      for (const q of r.requests) {
        if (!integer(q.id) || ids.has(q.id) || !["HEAD", "GET"].includes(q.method) ||
            !finite(q.startMs) || !finite(q.durationMs) || !integer(q.bytesReceived) ||
            (q.range != null && typeof q.range !== "string") ||
            (q.statusCode != null && (!integer(q.statusCode) || q.statusCode < 100 || q.statusCode > 599)) ||
            (q.error != null && typeof q.error !== "string") ||
            ((q.startByte != null || q.endByte != null) &&
             (!integer(q.startByte) || !integer(q.endByte) || q.endByte < q.startByte || q.endByte >= d.fileSizeBytes)))
          throw new Error("The result contains an invalid HTTP request trace.");
        ids.add(q.id);
      }
    }
    return data;
  }

  function median(values) {
    if (!values.length) return null;
    const sorted = [...values].sort((a, b) => a - b), mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
  }

  function uniqueBytes(requests) {
    const ranges = requests.filter(q => q.method === "GET" && q.statusCode === 206 && !q.error &&
        q.startByte != null && q.endByte != null && q.bytesReceived === q.endByte - q.startByte + 1)
      .map(q => [q.startByte, q.endByte + 1]).sort((a, b) => a[0] - b[0]);
    let count = 0, end = 0;
    for (const range of ranges) {
      count += Math.max(0, range[1] - Math.max(end, range[0]));
      end = Math.max(end, range[1]);
    }
    return count;
  }

  // Coordinates are half-open, even though HTTP range ends are inclusive.
  function clipRange(start, endExclusive, windowStart, windowEnd) {
    const a = Math.max(start, windowStart), b = Math.min(endExclusive, windowEnd);
    if (a >= b || windowEnd <= windowStart) return null;
    return { left: 100 * (a - windowStart) / (windowEnd - windowStart),
      width: 100 * (b - a) / (windowEnd - windowStart) };
  }

  if (typeof module !== "undefined" && module.exports)
    module.exports = { validateReport, median, uniqueBytes, clipRange };
  if (typeof document === "undefined") return;

  const $ = id => document.getElementById(id);
  const number = value => value.toLocaleString("en-US");
  const ms = value => value == null ? "—" : `${value.toLocaleString("en-US", { maximumFractionDigits: 3 })} ms`;
  const bytes = value => `${number(value)} B`;
  function el(tag, value, className) {
    const node = document.createElement(tag);
    if (value != null) node.textContent = value;
    if (className) node.className = className;
    return node;
  }
  let report, libraries = [], selected = null;
  const requestKey = (r, q) => JSON.stringify([r.library, r.iteration, q.id]);
  const color = name => colors[libraries.indexOf(name) % colors.length];
  const swatch = name => { const s = el("span", null, "swatch"); s.style.setProperty("--color", color(name)); return s; };
  const description = (r, q) => `${r.library} #${q.id} · ${q.method} ${q.range ?? "(object metadata)"} · ${ms(q.startMs)} + ${ms(q.durationMs)} · HTTP ${q.statusCode ?? "failed"} · ${bytes(q.bytesReceived)}${q.error ? ` · ${q.error}` : ""}`;

  function setSelection(r, q) {
    selected = requestKey(r, q);
    document.querySelectorAll("[data-request]").forEach(node => {
      node.classList.toggle("selected", node.dataset.request === selected);
      if (node.tagName === "BUTTON") node.setAttribute("aria-pressed", String(node.dataset.request === selected));
    });
    $("selection-details").textContent = description(r, q) +
      (q.startByte == null ? " · No file range." : ` · File bytes ${number(q.startByte)}–${number(q.endByte)} (inclusive).`);
  }

  function linkRequest(node, r, q) {
    node.dataset.request = requestKey(r, q);
    node.title = description(r, q);
    node.setAttribute("aria-label", description(r, q));
    node.setAttribute("aria-pressed", String(node.dataset.request === selected));
    node.addEventListener("click", () => setSelection(r, q));
  }

  function bar(track, r, q, coordinates) {
    if (!coordinates) return;
    const b = el("button", null, `bar${q.method === "HEAD" ? " head" : ""}`);
    b.type = "button";
    b.style.left = `min(${coordinates.left}%, calc(100% - 2px))`;
    b.style.width = `${coordinates.width}%`;
    b.style.maxWidth = "100%";
    b.style.setProperty("--color", color(r.library));
    linkRequest(b, r, q);
    track.append(b);
  }

  function row(container, r, subtitle) {
    const line = el("div", null, "plot-row"), label = el("div", null, "plot-label");
    label.append(swatch(r.library), document.createTextNode(r.library), el("small", subtitle));
    const track = el("div", null, "track");
    line.append(label, track); container.append(line);
    return track;
  }

  function axis(container, from, to, formatter) {
    const a = el("div", null, "axis"), ticks = el("div", null, "ticks");
    for (let i = 0; i <= 4; i++) ticks.append(el("span", formatter(from + (to - from) * i / 4)));
    a.append(el("span"), ticks); container.append(a);
  }

  function region(track, start, end, from, to, className) {
    const c = clipRange(start, end, from, to);
    if (!c) return;
    const node = el("span", null, className);
    node.style.left = `${c.left}%`; node.style.width = `${c.width}%`;
    track.append(node);
  }

  function render() {
    selected = null;
    $("selection-details").textContent = "Select a request in either view or the table.";
    const iteration = Number($("iteration").value), runs = report.runs.filter(r => r.iteration === iteration);
    const tbody = $("summary").querySelector("tbody"), requests = $("requests").querySelector("tbody");
    tbody.replaceChildren(); requests.replaceChildren();
    const timeline = $("timeline"), ranges = $("ranges");
    timeline.replaceChildren(); ranges.replaceChildren();
    const maxMs = Math.max(.001, ...runs.flatMap(r => [r.elapsedMs, ...r.requests.map(q => q.startMs + q.durationMs)]));
    const d = report.dataset, to = d.fileSizeBytes;
    const from = $("range-window").value === "full" ? 0 : Math.max(0, d.footerOffset - 131072);
    $("range-caption").textContent = `Byte ${number(from)} to ${number(to - 1)} · ${bytes(to - from)}`;
    for (const r of runs) {
      const series = report.runs.filter(x => x.library === r.library);
      const first = series.find(x => x.iteration === 1), later = series.filter(x => x.iteration > 1 && !x.error);
      const bodyBytes = r.requests.reduce((sum, q) => sum + q.bytesReceived, 0);
      const heads = r.requests.filter(q => q.method === "HEAD").length;
      const gets = r.requests.filter(q => q.method === "GET").length;
      const tr = el("tr"), name = el("td");
      name.append(swatch(r.library), document.createTextNode(r.library), el("small", r.version));
      tr.append(name);
      const elapsed = el("td", r.error ? "Failed" : ms(r.elapsedMs), r.error ? "failed" : "");
      if (r.error) elapsed.title = r.error;
      tr.append(elapsed, el("td", `${r.requests.length} (${heads} HEAD / ${gets} GET)`),
        el("td", bytes(bodyBytes)), el("td", bytes(uniqueBytes(r.requests))),
        el("td", first && !first.error ? ms(first.elapsedMs) : "—"),
        el("td", `${ms(median(later.map(x => x.elapsedMs)))}${later.length ? ` (n=${later.length})` : ""}`));
      tbody.append(tr);
      const timeTrack = row(timeline, r, r.error ? "Failed" : ms(r.elapsedMs));
      const total = el("span", null, "operation"); total.style.width = `${100 * r.elapsedMs / maxMs}%`; timeTrack.append(total);
      const fileTrack = row(ranges, r, `${bytes(bodyBytes)} transferred`);
      region(fileTrack, d.footerOffset, to - 8, from, to, "region");
      region(fileTrack, to - 8, to, from, to, "region trailer");
      let outside = 0;
      for (const q of r.requests) {
        // Zero-duration events remain selectable as minimum-width markers.
        bar(timeTrack, r, q, { left: 100 * q.startMs / maxMs, width: 100 * q.durationMs / maxMs });
        if (q.method === "GET" && q.startByte != null) {
          const c = clipRange(q.startByte, q.endByte + 1, from, to);
          if (!c) outside++;
          bar(fileTrack, r, q, c);
        }
        const trq = el("tr"), cell = el("td"), select = el("button", `${r.library} / #${q.id}`);
        select.type = "button"; linkRequest(select, r, q); cell.append(select);
        trq.dataset.request = requestKey(r, q);
        trq.append(cell, el("td", q.method), el("td", ms(q.startMs)), el("td", ms(q.durationMs)),
          el("td", String(q.statusCode ?? "Failed"), q.error ? "failed" : ""), el("td", q.range ?? "—"),
          el("td", q.startByte == null ? "—" : `${number(q.startByte)}–${number(q.endByte)}`), el("td", bytes(q.bytesReceived)));
        if (q.error) trq.title = q.error;
        requests.append(trq);
      }
      if (outside) ranges.append(el("p", `${r.library}: ${outside} request(s) outside this window. Choose Entire file to see them.`, "plot-note"));
      if (r.error) timeline.append(el("p", `${r.library}: ${r.error}`, "plot-note failed"));
    }
    axis(timeline, 0, maxMs, ms);
    axis(ranges, from, to, value => number(Math.round(value)));
  }

  function load(data, label) {
    report = validateReport(data);
    libraries = [...new Set(report.runs.map(r => r.library))];
    $("iteration").replaceChildren();
    [...new Set(report.runs.map(r => r.iteration))].sort((a,b) => a-b).forEach(i => {
      const option = el("option", `${i}${i === 1 ? " · first use" : ""}`); option.value = i; $("iteration").append(option);
    });
    const d = report.dataset;
    $("dataset-name").textContent = d.name;
    $("dataset-details").textContent = `${bytes(d.fileSizeBytes)} object · ${bytes(d.footerLengthBytes)} footer · Offset ${number(d.footerOffset)}`;
    $("dataset-mode").textContent = d.mode === "metadata-only"
      ? "Metadata-only fixture: original header, footer and file size; data-page bytes are zero-filled. Read-ahead bytes still count as transferred."
      : "Full-file fixture: all served bytes come from the supplied Parquet file.";
    $("dataset-source").replaceChildren();
    if (d.sourceUrl) {
      const url = new URL(d.sourceUrl);
      if (["https:", "http:"].includes(url.protocol)) {
        const a = el("a", "Dataset source"); a.href = url.href; a.rel = "noreferrer";
        $("dataset-source").append(a);
      }
    }
    const p = report.protocol ?? {}, e = report.environment ?? {};
    $("environment").hidden = !report.environment;
    $("revisions").hidden = !e.labCommit && !e.plankCommit;
    $("fixture-hash").hidden = !d.footerSha256;
    $("protocol").textContent = `${p.description ?? ""} ${p.iterations ?? "?"} iterations per library; ${p.latencyMs ?? 0} ms configured emulator delay per request. Request counts include HEAD, GET and failed requests. Body bytes exclude HTTP headers and transport overhead. Unique file bytes count the union of fully successful GET ranges. Failed samples are excluded from medians.`;
    $("environment").textContent = `${e.operatingSystem ?? ""} · ${e.architecture ?? ""} · ${e.runtime ?? ""} · ${e.processorCount ?? "?"} logical processors · ${report.generatedAt ?? ""}`;
    const revision = (commit, dirty) => `${commit ?? "unknown"}${dirty === true ? " (modified working tree)" : dirty == null ? " (working-tree state unknown)" : ""}`;
    $("revisions").textContent = `Lab: ${revision(e.labCommit, e.labDirty)} · Plank: ${revision(e.plankCommit, e.plankDirty)}`;
    $("fixture-hash").textContent = `Footer SHA-256: ${d.footerSha256 ?? "unknown"}`;
    const failures = report.runs.filter(r => r.error).length;
    $("status").textContent = `${label} · ${report.runs.length} trials · ${p.latencyMs ?? 0} ms added per request${failures ? ` · ${failures} failed` : ""}`;
    $("report").hidden = false; $("empty").hidden = true;
    render();
  }

  $("iteration").addEventListener("change", render);
  $("range-window").addEventListener("change", render);
  $("clear-selection").addEventListener("click", render);
  let loadGeneration = 0;
  $("file-input").addEventListener("change", async event => {
    const file = event.target.files[0]; if (!file) return;
    ++loadGeneration;
    try { load(JSON.parse(await file.text()), file.name); }
    catch (error) { $("status").textContent = `Could not open result: ${error.message}`; }
    event.target.value = "";
  });
  (async () => {
    const generation = loadGeneration;
    try {
      const source = new URLSearchParams(location.search).get("data") ?? "benchmarks/s3-footer.json";
      const response = await fetch(source);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (generation === loadGeneration) load(data, "Saved benchmark result");
    } catch (error) {
      if (generation !== loadGeneration) return;
      $("status").textContent = `No saved result loaded (${error.message}). Open a benchmark JSON file to inspect it.`;
      $("empty").hidden = false;
    }
  })();
})();
