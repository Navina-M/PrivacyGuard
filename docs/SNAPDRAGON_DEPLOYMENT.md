# Snapdragon / Qualcomm AI Hub Deployment — Status & Plan

**Status: architected, not implemented, not hardware-tested.**

This document exists so the project's edge-AI ambitions are represented
accurately. Nothing below should be read as a claim that Snapdragon
acceleration currently works — it doesn't, because no Snapdragon device
was available during development.

## Current state

- The app runs entirely on CPU (`dlp/ai_status.py` → `ai_backend: "Local
  CPU (regex + NER)"`).
- No contextual AI model is wired in yet (that's Phase 2 of the build
  plan — see `PrivacyGuard_Edge_Phased_Plan.md`).
- `dlp/ai_status.py:snapdragon_status()` always reports **"Not Available
  on Current Device"** — this is a static, honest status, not a live
  hardware probe (there's no hardware to probe).

## Intended architecture

```
                 AI MODEL
                    |
          +---------+---------+
          |                   |
          v                   v
     CPU BACKEND       SNAPDRAGON BACKEND
     (implemented)     (interface only)
                              |
                              v
                    Qualcomm AI Toolchain
                              |
                              v
                       NPU / GPU / CPU
```

`dlp/ai_status.py` already exposes the shape this abstraction needs
(`contextual_ai_status()`, `snapdragon_status()`). A future
`ai_engine/` package (per the phased plan, Phase 2/4) would implement:

- `ai_engine/base.py` — a common `AIBackend` interface
- `ai_engine/cpu_backend.py` — the working local backend
- `ai_engine/snapdragon_backend.py` — Qualcomm-targeted backend

## Steps required to actually finish this (needs Snapdragon hardware)

1. **Pick a model.** A small text/entity/context classification model —
   not a vision or chat model — suited to running locally. Model choice
   is deliberately deferred until it can be checked against the current
   Qualcomm AI Hub model catalog, since a good choice today may not be
   the best choice later.
2. **Check current official docs.** Before writing any Qualcomm-specific
   code, consult the live Qualcomm AI Hub / Qualcomm AI Runtime
   documentation for supported model formats, conversion tooling, and
   the current runtime API. Do not assume last-known API shapes are
   still correct — this space moves.
3. **Convert/optimize the model** using the officially supported
   Qualcomm AI Hub workflow for the chosen model architecture.
4. **Implement `SnapdragonBackend`** against the real runtime API (no
   invented function names), with the same interface as `CPUBackend` so
   `dlp/ai_status.py` and the risk engine don't need to change.
5. **Benchmark on real hardware.** Extend a benchmark module to record
   actual inference time, processing time, and memory on the Snapdragon
   device — never fabricate or estimate these numbers. Compare against
   the CPU backend's real numbers side by side.
6. **Update `snapdragon_status()`** to reflect real, detected hardware
   capability instead of the current static "Not Available" — and only
   ever report "Enabled" when acceleration is actually active.

## Hard constraints (carried over from the build plan)

- Never fake NPU usage or benchmark numbers.
- Never claim Snapdragon acceleration without having actually tested it.
- The app must keep working on CPU-only hardware regardless of
  Snapdragon backend status — CPU is not a "fallback path," it's a
  first-class supported mode.
