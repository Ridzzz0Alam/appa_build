"""The reference monitor: Gate 1 before dispatch, Gate 2 at admission,
a recovery planner when Gate 1 says no, and disposable child branches."""
from collections import deque
from dataclasses import dataclass, field

from .contracts import Call, EffectLog
from .labels import Label, Partial, Trust, TOP
from .policy import attest


@dataclass
class Check:
    gaps: set
    d: Partial          # the declared contribution of this call
    after: Partial      # the prospective label c_tau(L) = L ^ d
    narrowing: bool
    casts: dict         # unknown source -> label resolved for this check


@dataclass
class Outcome:
    status: str                       # dispatched | blocked | needs_accept
    gaps: frozenset = frozenset()
    result: object = None
    routes: dict = field(default_factory=dict)


@dataclass
class Plan:
    steps: list                       # ("run", Call) or ("ruling", gap)
    ruled: frozenset


class Monitor:
    def __init__(self, world, contracts, *, desk=None, casts=None, sanitizers=None,
                 schemas=None, prereqs=None, log=None, audit=None,
                 label=None, trajectory="root", prospective=True):
        self.world, self.contracts = world, contracts
        self.desk, self.prereqs = desk, prereqs or {}
        self.casts, self.sanitizers = casts or {}, sanitizers or {}
        self.schemas = schemas or {}
        self.log = log if log is not None else EffectLog()      # shared tree-wide
        self.audit = audit if audit is not None else []         # shared tree-wide
        self.label = label or Partial(TOP)                      # trajectory-local
        self.trajectory, self.prospective = trajectory, prospective
        self.schema, self._children = None, 0
        self.drift = []

    # ---- helpers ---------------------------------------------------------
    def recipients(self, call):
        c = self.contracts[call.tool]
        return c.recipients(call.args) if c.recipients else frozenset()

    def resolve(self, partial):
        """Run registered casts over every unresolved source. Fail closed."""
        label, used = partial.known, {}
        for src in sorted(partial.unresolved):
            cast = self.casts.get(src.split(":")[0])
            lam = cast.resolve(src, self.world) if cast else None
            if lam is None:
                return None, used
            used[src] = lam
            label = label.meet(lam)
        return label, used

    # ---- Gate 1 ----------------------------------------------------------
    def check(self, call, d=None, label=None, effects=None) -> Check:
        c = self.contracts[call.tool]
        label = label or self.label
        effects = self.log.snapshot() if effects is None else effects
        d = d or c.declared(call.args)
        after = label.meet(d)
        judged = after if self.prospective else label     # reactive monitors judge L
        gaps, used, eff = set(), {}, judged.known
        consumes = c.recipients is not None or c.min_trust > Trust.SUSPICIOUS
        if consumes and judged.unresolved:                # lazy: only a sink asks
            resolved, used = self.resolve(judged)
            if resolved is None:
                gaps.add("unestablished")
            else:
                eff = resolved
        if c.recipients and not c.recipients(call.args) <= eff.readers:
            gaps.add("recipient")
        if eff.trust < c.min_trust:
            gaps.add("trust")
        gaps |= {f"prior:{k}" for k in c.requires_prior if k not in effects}
        gaps |= {f"no_prior:{k}" for k in c.requires_no_prior if k in effects}
        if c.gate:
            gaps.add(f"gate:{c.gate}")
        return Check(gaps, d, after, after.known < label.known, used)

    def _covered(self, call, gaps, rulings):
        if not self.desk:
            return set()
        rec, digest, covered = self.recipients(call), call.digest(), set()
        for g in gaps:
            mine = {r.authority for r in rulings
                    if r.gap == g and r.digest == digest and not r.consumed
                    and r.trajectory == self.trajectory}
            need = set(self.desk.approvers_for(g, rec))
            if need and need <= mine:
                covered.add(g)
        return covered

    def dispatch(self, call, accept=False, rulings=(), via=None) -> Outcome:
        """via = a registered sanitizer bound to this call's realized return."""
        d = Partial(self.sanitizers[via].to_label) if via else None
        chk = self.check(call, d)
        open_gaps = chk.gaps - self._covered(call, chk.gaps, rulings)
        if open_gaps:
            return Outcome("blocked", frozenset(open_gaps),
                           routes=self.routes(call, open_gaps))
        if chk.narrowing and not accept:
            return Outcome("needs_accept", routes={"narrowing": self.narrowing_routes(call)})
        # one atomic step: consume rulings, log acceptance, dispatch
        used = [r for r in rulings if r.digest == call.digest()]
        for r in used:
            r.consumed = True
        if used or chk.narrowing:
            self.audit.append({"trajectory": self.trajectory, "call": call.render(),
                               "rulings": [(r.authority, r.gap) for r in used],
                               "accepted_narrowing": chk.narrowing})
        res = self.world.execute(call)
        self.log.record(self.trajectory, call, res.outcome,
                        self.contracts[call.tool].effects)
        return Outcome("dispatched", result=self.admit(call, res, chk, via))

    # ---- Gate 2 ----------------------------------------------------------
    def admit(self, call, res, chk, via):
        """Check what actually came back before the model ever sees it."""
        contribution = chk.d
        if res.label is not None and not (chk.d.known <= res.label):
            self.drift.append((call.tool, chk.d.known, res.label))   # contract lied
        if via:
            san = self.sanitizers[via]
            if res.label is None or not (san.from_label <= res.label):
                raise PermissionError(f"{via} is not authorised for {res.label}")
            res.value, res.doc = san.fn(res.value), None             # raw never admitted
        elif res.label is not None:
            contribution = Partial(chk.d.known.meet(res.label), chk.d.unresolved)
        elif res.unknown:
            contribution = Partial(chk.d.known, chk.d.unresolved | {res.unknown})
        new = self.label.meet(contribution)
        if chk.casts:                                  # commit resolutions we used
            known = new.known
            for lam in chk.casts.values():
                known = known.meet(lam)
            new = Partial(known, new.unresolved - set(chk.casts))
        self.label = new
        return res

    # ---- recovery --------------------------------------------------------
    def narrowing_routes(self, call):
        routes = ["accept the narrowing", "fork a child branch"]
        routes += [f"read through sanitizer {s}" for s in self.sanitizers]
        return routes

    def routes(self, call, gaps):
        rec, menu = self.recipients(call), {}
        for g in sorted(gaps):
            opts = []
            if g.startswith("prior:") and g[6:] in self.prereqs:
                opts.append(f"run {self.prereqs[g[6:]](call).tool}")
            who = self.desk.approvers_for(g, rec) if self.desk else []
            if who:
                opts.append("ruling from " + " + ".join(who))
            if not opts:
                opts = (["irreparable: the log only grows"] if g.startswith("no_prior")
                        else ["no registered route"])
            menu[g] = opts
        return menu

    def plan(self, call):
        """Breadth-first search over registered transitions. Finite, so it ends."""
        rec = self.recipients(call)
        start = (self.label, self.log.snapshot(), frozenset())
        queue, seen = deque([(start, [])]), {start}
        while queue:
            (label, effects, ruled), steps = queue.popleft()
            gaps = self.check(call, label=label, effects=effects).gaps - ruled
            if not gaps:
                return Plan(steps, ruled)
            if len(steps) >= 6:
                continue
            moves = []
            for g in gaps:
                if g.startswith("prior:") and g[6:] in self.prereqs:
                    pc = self.prereqs[g[6:]](call)
                    pchk = self.check(pc, label=label, effects=effects)
                    if not pchk.gaps:
                        eff2 = effects | set(self.contracts[pc.tool].effects)
                        moves.append((("run", pc), (pchk.after, frozenset(eff2), ruled)))
                if self.desk and self.desk.approvers_for(g, rec):
                    moves.append((("ruling", g), (label, effects, ruled | {g})))
            for step, state in moves:
                if state not in seen:
                    seen.add(state)
                    queue.append((state, steps + [step]))
        return None

    # ---- branches --------------------------------------------------------
    def fork(self, schema=None):
        self._children += 1
        child = Monitor(self.world, self.contracts, desk=self.desk, casts=self.casts,
                        sanitizers=self.sanitizers, schemas=self.schemas,
                        prereqs=self.prereqs, log=self.log, audit=self.audit,
                        label=self.label,                      # inherit, never TOP
                        trajectory=f"{self.trajectory}/c{self._children}",
                        prospective=self.prospective)
        child.schema = schema
        return child

    def attest_exit(self, child, value):
        spec = self.schemas[child.schema]
        return attest(value, spec.shape), spec.merge_label

    def merge(self, label: Label):
        self.label = Partial(self.label.known.meet(label), self.label.unresolved)
