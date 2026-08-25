# Plank Lab

> [!WARNING]
> This repository is deliberately vibe-coded experimental infrastructure. Much of it was
> produced through rapid AI-assisted iteration. It is not the supported Plank library, it
> is not production software, and its scripts may consume substantial CPU, memory, disk,
> cloud resources, or fuzzing capacity. Read every command before running it.

Plank Lab contains the exploratory work kept out of the clean
[Plank](https://github.com/Kuinox/Plank) package repository:

- published and diagnostic benchmarks;
- fuzz targets, corpora, fleet scripts, and crash triage;
- the `pqmin` parallel autoresearch harness and dashboard;
- experimental test cases that directly drive fuzz targets;
- checked-in benchmark result snapshots and their renderer.

The supported library is included as the `library/Plank` submodule so every experiment can
pin the exact source revision it measured.

## Checkout

```sh
git clone --recurse-submodules https://github.com/Kuinox/Plank-Lab.git
cd Plank-Lab
dotnet test --solution Plank-Lab.sln --configuration Release
```

The [published benchmark matrix](https://kuinox.github.io/Plank-Lab/) is served from
`docs/` and embedded in the main Plank documentation. The individual benchmark, fuzzing,
and autoresearch directories contain their own operational notes.
