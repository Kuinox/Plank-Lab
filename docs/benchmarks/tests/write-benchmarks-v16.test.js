const assert = require("node:assert/strict");
const { createServer } = require("node:http");
const { once } = require("node:events");
const { readFileSync } = require("node:fs");
const { execFile, execFileSync } = require("node:child_process");
const { promisify } = require("node:util");
const { normalize, resolve } = require("node:path");
const { test } = require("node:test");

const testsDirectory = __dirname;
const docsDirectory = resolve(testsDirectory, "../..");
const runFile = promisify(execFile);

function findBrowser() {
  const candidates = process.env.BENCHMARK_BROWSER
    ? [process.env.BENCHMARK_BROWSER]
    : ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"];
  return candidates.find(candidate => {
    try {
      execFileSync("which", [candidate], { stdio: "ignore" });
      return true;
    } catch {
      return false;
    }
  });
}

function serveDocs() {
  const server = createServer((request, response) => {
    const pathname = new URL(request.url, "http://fixture").pathname;
    const requestedPath = normalize(resolve(docsDirectory, `.${pathname}`));
    if (!requestedPath.startsWith(`${docsDirectory}/`)) {
      response.writeHead(404).end();
      return;
    }

    try {
      const body = readFileSync(requestedPath);
      const contentType = requestedPath.endsWith(".json")
        ? "application/json"
        : requestedPath.endsWith(".js")
          ? "text/javascript"
          : "text/html";
      response.writeHead(200, { "connection": "close", "content-type": contentType });
      response.end(body);
    } catch {
      response.writeHead(404).end();
    }
  });
  return server;
}

function matrixSpan(dom, attribute, value) {
  const pattern = new RegExp(
    `<span[^>]*class="benchmark-matrix-result"[^>]*${attribute}="${value}"[^>]*>([^<]*)</span>`);
  const match = dom.match(pattern);
  assert.ok(match, `matrix result with ${attribute}=${value} was not rendered`);
  return match[1];
}

test("matrix displays Plank's value for wins, losses, and unavailable results", async t => {
  const browser = findBrowser();
  if (!browser) {
    t.skip("Chromium is not installed; set BENCHMARK_BROWSER to a Chromium-compatible browser");
    return;
  }

  const server = serveDocs();
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  const browserArguments = [
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--virtual-time-budget=2000",
    "--dump-dom",
    `http://127.0.0.1:${port}/benchmarks/tests/matrix-fixture.html`
  ];
  let result;
  try {
    result = await runFile(browser, browserArguments, {
      encoding: "utf8",
      maxBuffer: 4 * 1024 * 1024,
      timeout: 10000
    });
  } catch (error) {
    assert.fail(error.stderr || error.message);
  }
  const dom = result.stdout;

  assert.match(dom, /aria-label="loss, Plain: 1 thread 200 ms, 2 threads 400 ms"/);
  assert.match(dom, /aria-label="win, Plain: 1 thread 100 ms, 2 threads 150 ms"/);
  assert.match(dom, /aria-label="unavailable, Plain: 1 thread Unavailable, 2 threads Unavailable"/);
  assert.equal(matrixSpan(dom, "data-loss", "strong"), "200 ms");
  assert.equal(matrixSpan(dom, "data-win", "strong"), "100 ms");
  assert.match(dom, /<span[^>]*class="benchmark-matrix-result"[^>]*>Unavailable<\/span>/);
  assert.match(dom, /title="Plank used 100% more time than Competitor"/);
});
