"""Run every scenario x arm x profile x seed and score from world state only."""
import random
import sys
from collections import Counter, defaultdict

from .agent import ARMS, Agent
from .company import build_monitor, new_world
from .scenarios import SCENARIOS

PROFILES, SEEDS = ("standard", "chaos"), range(5)


def episode(scn, arm, profile, seed):
    rng = random.Random(f"{scn.name}|{profile}|{seed}")   # same draws for every arm
    world, cfg = new_world(), ARMS[arm]
    mon = (build_monitor(world, casts=cfg["casts"], sanitizers=cfg["sanitizers"])
           if cfg["guarded"] else None)
    agent = Agent(arm, rng, profile)
    agent.run(scn, world, mon)
    return scn.utility(world), scn.unsafe(world), agent.stats


def main(arms=tuple(ARMS)):
    table = defaultdict(lambda: [0, 0, 0])          # (arm, profile) -> util, unsafe, n
    per_scn = defaultdict(lambda: [0, 0, 0])        # (arm, scenario)
    stats = defaultdict(Counter)
    for arm in arms:
        for profile in PROFILES:
            for scn in SCENARIOS:
                for seed in SEEDS:
                    u, bad, st = episode(scn, arm, profile, seed)
                    for key, tab in (((arm, profile), table), ((arm, scn.name), per_scn)):
                        tab[key][0] += u
                        tab[key][1] += bad
                        tab[key][2] += 1
                    stats[arm].update(st)
    return table, per_scn, stats


if __name__ == "__main__":
    table, per_scn, stats = main()
    n_eps = sum(v[2] for v in table.values())
    print(f"  episodes  {n_eps}  ({len(SCENARIOS)} scenarios x {len(ARMS)} arms"
          f" x {len(PROFILES)} profiles x {len(SEEDS)} seeds)\n")
    print(f"  {'arm':<15}{'standard U/unsafe':>20}{'chaos U/unsafe':>18}")
    for arm in ARMS:
        cells = []
        for p in PROFILES:
            u, b, n = table[(arm, p)]
            cells.append(f"{100*u/n:5.1f} / {100*b/n:4.1f}")
        print(f"  {arm:<15}{cells[0]:>20}{cells[1]:>18}")
