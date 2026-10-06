"""Security labels: who may read a value, and how much we trust it."""
from dataclasses import dataclass
from enum import IntEnum


class Trust(IntEnum):
    SUSPICIOUS = 0
    ATTESTED = 1      # passed a registered shape check, never promoted by itself
    TRUSTED = 2


# The whole reader universe of our mock company. "public" means anyone at all.
PRINCIPALS = frozenset({"public", "staff", "hr", "finance", "legal", "counsel"})
INTERNAL = frozenset({"staff", "hr", "finance", "legal"})


@dataclass(frozen=True)
class Label:
    readers: frozenset
    trust: Trust

    def meet(self, other: "Label") -> "Label":
        """Combine two streams: fewer readers, lower trust. Never the reverse."""
        return Label(self.readers & other.readers, min(self.trust, other.trust))

    def __le__(self, other):               # "at least as restrictive as"
        return self.readers <= other.readers and self.trust <= other.trust

    def __lt__(self, other):
        return self <= other and self != other

    def __repr__(self):
        if self.readers == PRINCIPALS:
            names = "*"
        elif self.readers == INTERNAL:
            names = "internal"
        else:
            names = ",".join(sorted(self.readers)) or "nobody"
        return f"({names}, {self.trust.name.lower()})"


TOP = Label(PRINCIPALS, Trust.TRUSTED)


def lab(readers: str, trust: str = "trusted") -> Label:
    """lab('hr') -> ({hr}, trusted); lab('*', 'suspicious'); lab('internal')."""
    if readers == "*":
        rs = PRINCIPALS
    elif readers == "internal":
        rs = INTERNAL
    else:
        rs = frozenset(readers.split())
    return Label(rs, Trust[trust.upper()])


@dataclass(frozen=True)
class Partial:
    """An established bound plus unannotated sources nobody has resolved yet."""
    known: Label
    unresolved: frozenset = frozenset()

    def meet(self, other: "Partial") -> "Partial":
        return Partial(self.known.meet(other.known), self.unresolved | other.unresolved)

    def __repr__(self):
        extra = f" + unknown{sorted(self.unresolved)}" if self.unresolved else ""
        return f"{self.known}{extra}"
