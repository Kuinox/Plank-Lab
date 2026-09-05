const { test } = require('node:test');
const assert = require('node:assert/strict');
const { validateReport, median, uniqueBytes, clipRange } = require('../../../docs/benchmarks/s3-footer.js');

function request(startByte, endByte, overrides = {}) {
  return { id: 1, method: 'GET', range: `bytes=${startByte}-${endByte}`, startByte, endByte,
    startMs: 1, durationMs: 2, statusCode: 206, bytesReceived: endByte - startByte + 1, error: null, ...overrides };
}
function report() {
  return { schemaVersion: 1, dataset: { name: 'fixture.parquet', mode: 'metadata-only',
      fileSizeBytes: 1000, footerOffset: 892, footerLengthBytes: 100 },
    runs: [{ library: 'Plank', iteration: 1, elapsedMs: 4, error: null, requests: [request(892, 999)] }] };
}

test('coverage merges overlapping and repeated reads, excludes HEAD and failed bodies', () => {
  assert.equal(uniqueBytes([request(0, 3), request(2, 7), request(2, 7), request(20, 24),
    request(0, 999, { method: 'HEAD', bytesReceived: 0 }),
    request(30, 40, { error: 'incomplete', bytesReceived: 5 }),
    request(50, 60, { statusCode: 500 }), request(70, 80, { bytesReceived: 1 })]), 13);
});
test('file coordinates convert inclusive ranges without losing the last byte', () => {
  assert.deepEqual(clipRange(990, 1000, 900, 1000), { left: 90, width: 10 });
  assert.deepEqual(clipRange(999, 1000, 900, 1000), { left: 99, width: 1 });
  assert.deepEqual(clipRange(50, 150, 100, 200), { left: 0, width: 50 });
  assert.equal(clipRange(0, 4, 900, 1000), null);
  assert.equal(clipRange(1000, 1010, 900, 1000), null);
});
test('medians keep zero values and do not reorder input samples', () => {
  const samples = [8, 0, 4, 2];
  assert.equal(median(samples), 3);
  assert.deepEqual(samples, [8, 0, 4, 2]);
  assert.equal(median([8, 0, 2]), 2);
  assert.equal(median([]), null);
});
test('viewer accepts successful and partial failed benchmark traces', () => {
  assert.equal(validateReport(report()).schemaVersion, 1);
  const failed = report();
  failed.runs[0].error = 'Reader failed';
  failed.runs[0].requests[0] = request(892, 999, { error: 'Connection closed', bytesReceived: 32 });
  assert.doesNotThrow(() => validateReport(failed));
});
test('viewer rejects corrupt offsets, duplicate identities, and invalid time data', () => {
  for (const mutate of [
    d => d.schemaVersion = 2,
    d => d.dataset.footerOffset++,
    d => d.dataset.footerOffset = Number.MAX_SAFE_INTEGER + 1,
    d => d.runs.push(d.runs[0]),
    d => d.runs[0].requests.push(d.runs[0].requests[0]),
    d => d.runs[0].requests[0].endByte = 1000,
    d => d.runs[0].requests[0].startMs = -1,
    d => d.runs[0].requests[0].durationMs = Infinity,
    d => d.runs[0].elapsedMs = NaN
  ]) {
    const data = report(); mutate(data); assert.throws(() => validateReport(data));
  }
});
