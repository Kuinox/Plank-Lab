# Minimal parallel Parquet autoresearch

This directory is intentionally small. Twelve independent researchers are pinned one
per physical core. Fifteen minutes is a maximum run time: an early submission enters the
serialized deterministic gate immediately and its slot is refilled without waiting for the
other researchers. Researchers produce only a compressed column carrier; the trusted gate
forms the canonical Parquet envelope and promotes only a strictly smaller complete file that
preserves the data, metadata, compatibility, and single-core runtime constraints in
`MISSION.md`.

There is no refutation list. `trials.jsonl` contains scoped observations, and the generated
`NOTEBOOK.md` exposes only recent exact trials to each fresh slot run.

## Lifecycle

```bash
cp config.example.json config.json
# Edit config.json for the local input, model, and machine.
./bootstrap.sh
./serve_dashboard.sh
./run.sh
```

Stop the loop with `./stop.sh` and the dashboard with `./stop_dashboard.sh`.

The dashboard is served at <http://127.0.0.1:8765>.

Generated workspaces, logs, validation artifacts, and live research state stay local. The
winning C reproducer is kept under `best/reproducer`; its large generated inputs and column
bundles are reproducible and intentionally excluded from Git.
