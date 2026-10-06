"""The registered exceptions: who (rulings), what (sanitizers), how (casts),
and the shape-bounded exit channel (schemas). All of it lives in the TCB."""
from dataclasses import dataclass, field
from typing import Callable

from .labels import Label, PRINCIPALS


# --- Authority: who may let one exact call through -------------------------

@dataclass(frozen=True)
class Mandate:
    authority: str
    covers: frozenset                          # gap kinds it may waive
    recipients_within: frozenset = PRINCIPALS  # recipient gaps only within this
    decide: Callable = lambda call: True       # a rule, a human, or a judge model


@dataclass
class Ruling:
    authority: str
    gap: str
    digest: str           # hash of the exact rendered call
    trajectory: str       # the branch it was issued in
    consumed: bool = False


class AuthorityDesk:
    def __init__(self, mandates, gates=None):
        self.mandates = {m.authority: m for m in mandates}
        self.gates = gates or {}              # gate name -> authorities that must all sign
        self.issued: list[Ruling] = []

    def approvers_for(self, gap, recipients=frozenset()):
        """Which authorities could cover this gap at all. Says nothing about
        whether they will: that is decide()'s job."""
        if gap.startswith("gate:"):
            need = self.gates.get(gap[5:], ())
            ok = need and all(a in self.mandates and gap in self.mandates[a].covers
                              for a in need)
            return list(need) if ok else []
        for m in self.mandates.values():
            if gap in m.covers and (gap != "recipient"
                                    or recipients <= m.recipients_within):
                return [m.authority]
        return []

    def request(self, call, gap, recipients, trajectory):
        who = self.approvers_for(gap, recipients)
        if not who:
            return None                       # outside every mandate: cannot even ask
        rulings = []
        for a in who:
            if not self.mandates[a].decide(call):
                return None
            rulings.append(Ruling(a, gap, call.digest(), trajectory))
        self.issued += rulings
        return rulings


# --- Casts: how an unannotated source gets a real label --------------------

@dataclass(frozen=True)
class Cast:
    name: str
    ceiling: Label                 # the least restrictive label it may ever return
    fn: Callable                   # (source_id, world) -> Label | None

    def resolve(self, source, world):
        lam = self.fn(source, world)
        if lam is None or not (lam <= self.ceiling):
            return None            # fail closed: no answer, or an answer above the ceiling
        return lam


# --- Sanitizers: what clean version of the data may be produced ------------

@dataclass(frozen=True)
class Sanitizer:
    name: str
    from_label: Label              # the input it is authorised to accept
    to_label: Label                # the label its output carries
    fn: Callable                   # raw text -> clean value


# --- Schemas: the shape-bounded exit of a child branch ---------------------

class SchemaError(Exception):
    pass


@dataclass(frozen=True)
class Schema:
    shape: dict
    merge_label: Label             # a declared TCB decision, not a validation result


def attest(value: dict, shape: dict) -> dict:
    """Exact validation of shape and bandwidth. Free text has nowhere to go."""
    if set(value) != set(shape):
        raise SchemaError(f"fields {sorted(value)} != {sorted(shape)}")
    out = {}
    for name, spec in shape.items():
        v, kind = value[name], spec["type"]
        if kind == "bool" and isinstance(v, bool):
            out[name] = v
        elif (kind == "int" and isinstance(v, int) and not isinstance(v, bool)
              and spec["min"] <= v <= spec["max"]):
            out[name] = v
        elif kind == "enum" and isinstance(v, str) and v in spec["values"]:
            out[name] = v
        else:
            raise SchemaError(f"{name}={v!r} does not fit {spec}")
    return out
