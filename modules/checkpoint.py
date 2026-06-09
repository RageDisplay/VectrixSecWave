"""Crash/ban-safe progress tracking for multi-target runs.

A long unattended scan of many bank domains can die mid-way — antifraud ban,
expired session, killed shell. The checkpoint records which targets finished so
`--resume` can pick up the rest instead of re-scanning everything (and re-poking
antifraud on domains already covered).

State lives in `<output_dir>/.vectrix_state/<mode>.json` and is rewritten after
every completed target, so at most one target's progress is ever lost.
"""
from __future__ import annotations

import json
from pathlib import Path


class Checkpoint:
    def __init__(self, output_dir: Path, mode: str):
        self.dir = output_dir / ".vectrix_state"
        self.path = self.dir / f"{mode}.json"
        self.mode = mode
        self._completed: set[str] = set()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def load(self) -> None:
        """Load previously completed targets (for --resume)."""
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._completed = set(data.get("completed", []))
        except (json.JSONDecodeError, OSError):
            self._completed = set()

    def reset(self, targets: list[str]) -> None:
        """Begin a fresh run (no resume): clear prior completion state."""
        self._completed = set()
        self._write(targets)

    def is_done(self, target: str) -> bool:
        return target in self._completed

    def pending(self, targets: list[str]) -> list[str]:
        return [t for t in targets if t not in self._completed]

    def mark_done(self, target: str, targets: list[str]) -> None:
        self._completed.add(target)
        self._write(targets)

    def clear(self) -> None:
        """Remove the state file once the whole run finished cleanly."""
        try:
            self.path.unlink()
        except OSError:
            pass

    # ── Internal ─────────────────────────────────────────────────────────────

    def _write(self, targets: list[str]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "mode": self.mode,
            "targets": targets,
            "completed": sorted(self._completed),
        }
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.path)
