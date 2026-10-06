"""Trace one guarded episode: every dispatch, which branch it ran in, what happened."""
import random
from appa.monitor import Monitor
from bench.agent import Agent
from bench.company import build_monitor, new_world
from bench.scenarios import SCENARIOS

_dispatch = Monitor.dispatch
def traced(self, call, accept=False, rulings=(), via=None):
    out = _dispatch(self, call, accept, rulings, via)
    extra = f" gaps={sorted(out.gaps)}" if out.gaps else ""
    signed = f" rulings={[r.authority for r in rulings]}" if rulings else ""
    print(f"  {self.trajectory:<8} {call.tool:<14} {out.status:<11}{extra}{signed}  L={self.label}")
    return out
Monitor.dispatch = traced

scn = next(s for s in SCENARIOS if s.name == "dual-control-wire")
for seed in range(5):
    rng = random.Random(f"{scn.name}|chaos|{seed}")
    if rng.random() < 0.85:                       # find a seed where the child is hijacked
        break
world = new_world(); mon = build_monitor(world)
agent = Agent("appa", random.Random(f"{scn.name}|chaos|{seed}"), "chaos")
agent.run(scn, world, mon)
print(f"\n  wires {world.wires}")
print(f"  utility {scn.utility(world)}  unsafe {scn.unsafe(world)}  stats {dict(agent.stats)}")
