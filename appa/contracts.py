"""Tool calls, tool contracts, and the append-only log of committed effects."""
import hashlib
import json
from dataclasses import dataclass, field
from typing import Callable

from .labels import Label, Partial, Trust, TOP


@dataclass
class Call:
    tool: str
    args: dict

    def render(self) -> str:
        """The canonical, byte-exact form. The monitor renders it, never the model."""
        return json.dumps({"tool": self.tool, "args": self.args}, sort_keys=True)

    def digest(self) -> str:
        return hashlib.sha256(self.render().encode()).hexdigest()[:16]

    def __repr__(self):
        inner = ", ".join(f"{k}={v!r}" for k, v in self.args.items())
        return f"{self.tool}({inner})"


def _nothing(args):
    return None


@dataclass(frozen=True)
class Contract:
    """What a tool promises, declared once, inside the trusted base."""
    name: str
    # (i) the label its admitted result contributes: None (nothing),
    #     a Label, or ("unknown", source_id) for unannotated data
    reads: Callable = _nothing
    # who receives data when the call runs (None = not a sink)
    recipients: Callable | None = None
    # (iii) preconditions
    min_trust: Trust = Trust.SUSPICIOUS
    requires_prior: tuple = ()
    requires_no_prior: tuple = ()
    gate: str | None = None            # a mandatory authority gate
    # (ii) effect tokens committed on reported success
    effects: tuple = ()

    def declared(self, args) -> Partial:
        d = self.reads(args)
        if d is None:
            return Partial(TOP)
        if isinstance(d, Label):
            return Partial(d)
        return Partial(TOP, frozenset({d[1]}))          # ("unknown", source)


class EffectLog:
    """Append-only. Only successful outcomes commit tokens, nothing removes them.
    Shared by every branch of a trajectory tree."""

    def __init__(self):
        self._committed: set[str] = set()
        self.events: list[tuple[str, str, str]] = []   # (trajectory, tool, outcome)

    def record(self, trajectory, call, outcome, effects):
        self.events.append((trajectory, call.tool, outcome))
        if outcome == "success":
            self._committed |= set(effects)

    def prior(self, k):
        return k in self._committed

    def no_prior(self, k):
        return k not in self._committed

    def snapshot(self) -> frozenset:
        return frozenset(self._committed)
