"""Finite ideal-permutation path controls, not fixed-RP57 cryptographic evidence.

The caller explicitly supplies tapes and public endpoint attempts. The probability
lemma additionally REQUIRES public attempts to be independent of hidden salts and
capacities given disclosed words. This module cannot infer that hypothesis from
Python values or enforce it against closures/global variables. Virtual salts and
output capacities must be independent uniform draws conditional on disclosed
words. The common initial
capacity must be fixed before, or independent of, the virtual private output
capacities, conditionally on disclosed words.
"""

from dataclasses import dataclass
from fractions import Fraction

Point = tuple[int, int, int]
Edge = tuple[Point, Point]


def _point(value: Point, size: int) -> None:
    if (type(size) is not int or size < 2 or type(value) is not tuple
            or len(value) != 3 or any(type(x) is not int or not 0 <= x < size for x in value)):
        raise ValueError("noncanonical finite-state point")


@dataclass(frozen=True)
class Path:
    """One fresh salted path; its edges are private ideal-game data."""

    size: int
    initial_capacity: int
    salt: int
    edges: tuple[Edge, ...]

    @property
    def disclosed(self) -> tuple[int, ...]:
        """The second coordinate of each supplied private output."""
        return tuple(output[1] for _, output in self.edges)


def path(size: int, initial_capacity: int, domain: int, salt: int,
         outputs: tuple[Point, ...], blocks: tuple[tuple[int, int], ...]) -> Path:
    """Build a width-three, rate-two path with unchanged carried capacity.

    This starts at the first salt-bearing primitive input, not a full transcript.
    Every later block may depend on preceding private execution; addition never
    changes capacity. Outputs are explicit virtual tapes, not RP57 evaluations.
    """
    current = (initial_capacity, domain, salt)
    _point(current, size)
    if not outputs or len(blocks) + 1 != len(outputs):
        raise ValueError("one output per primitive edge required")
    edges = []
    for index, output in enumerate(outputs):
        _point(output, size)
        edges.append((current, output))
        if index < len(blocks):
            left, right = blocks[index]
            _point((0, left, right), size)
            current = (output[0], (output[1] + left) % size, (output[2] + right) % size)
    return Path(size, initial_capacity, salt, tuple(edges))



def _validate_path(selected: Path) -> None:
    _point((selected.initial_capacity, 0, selected.salt), selected.size)
    if not selected.edges:
        raise ValueError("empty private path")
    for input_, output in selected.edges:
        _point(input_, selected.size)
        _point(output, selected.size)
    if (selected.edges[0][0][0] != selected.initial_capacity
            or selected.edges[0][0][2] != selected.salt):
        raise ValueError("salt-bearing input mismatch")
    for (_, previous), (following, _) in zip(selected.edges, selected.edges[1:]):
        if previous[0] != following[0]:
            raise ValueError("absorption changed capacity")


def bad_reasons(paths: tuple[Path, ...], public: tuple[Edge, ...]) -> frozenset[str]:
    """Check the conservative salt/capacity first-hit event on complete tapes.

    All paths in one field use the same initial capacity. Public includes BOTH
    endpoints of every attempt, including replay and refused output candidates.
    It need not itself be a consistent permutation table. Fresh attempts are not
    deduplicated; exact retained replay must reuse its original Path entry.
    """
    if not paths:
        if public:
            raise ValueError("public endpoints need a selected finite alphabet")
        return frozenset()
    for selected in paths:
        _validate_path(selected)
    size, initial = paths[0].size, paths[0].initial_capacity
    if any(p.size != size or p.initial_capacity != initial for p in paths):
        raise ValueError("one field and initial capacity per experiment")
    if any(type(edge) is not tuple or len(edge) != 2 for edge in public):
        raise ValueError("one public attempt must have exactly two endpoints")
    endpoints = tuple(point for edge in public for point in edge)
    for point in endpoints:
        _point(point, size)
    reasons = set()
    seen_salts = set()
    seen_capacities = {initial}
    for selected in paths:
        if selected.salt in seen_salts:
            reasons.add("fresh_salt_collision")
        seen_salts.add(selected.salt)
        if selected.edges[0][0] in endpoints:
            reasons.add("initial_input_hit")
        for _, output in selected.edges:
            if output[0] in seen_capacities:
                reasons.add("private_capacity_collision")
            seen_capacities.add(output[0])
            if any(output[0] == endpoint[0] for endpoint in endpoints):
                reasons.add("public_capacity_hit")
    return frozenset(reasons)


def first_hit_bound(size: int, attempts: int, hidden_edges: int, public_attempts: int) -> Fraction:
    """Conditional union bound, never an empirical or fixed-permutation claim."""
    if type(size) is not int or size < 2 or any(type(x) is not int or x < 0 for x in (attempts, hidden_edges, public_attempts)):
        raise ValueError("finite nonnegative experiment bounds required")
    if hidden_edges < attempts:
        raise ValueError("each fresh attempt has a salt-bearing edge")
    numerator = (2 * public_attempts * (attempts + hidden_edges)
                 + attempts * (attempts - 1) // 2
                 + hidden_edges * (hidden_edges + 1) // 2)
    return min(Fraction(1), Fraction(numerator, size))


class PartialPermutation:
    """A finite partial bijection with visible replay/refusal, never overwrites."""

    def __init__(self, size: int):
        if type(size) is not int or size < 2:
            raise ValueError("finite alphabet required")
        self.size = size
        self.forward: dict[Point, Point] = {}
        self.inverse: dict[Point, Point] = {}
        self.attempts: list[tuple[str, Point, Point]] = []

    def propose_forward(self, input_: Point, candidate: Point) -> tuple[str, Point | None]:
        """Read a known edge, or try one explicit fresh-output candidate."""
        _point(input_, self.size)
        _point(candidate, self.size)
        self.attempts.append(("forward", input_, candidate))
        if input_ in self.forward:
            return ("replay", self.forward[input_])
        if candidate in self.inverse:
            return ("occupied", None)
        self.forward[input_] = candidate
        self.inverse[candidate] = input_
        return ("created", candidate)

    def propose_inverse(self, output: Point, candidate: Point) -> tuple[str, Point | None]:
        """Read a known inverse, or try one explicit fresh-input candidate."""
        _point(output, self.size)
        _point(candidate, self.size)
        self.attempts.append(("inverse", candidate, output))
        if output in self.inverse:
            return ("replay", self.inverse[output])
        if candidate in self.forward:
            return ("occupied", None)
        self.forward[candidate] = output
        self.inverse[output] = candidate
        return ("created", candidate)

    def retain_path(self, selected: Path) -> None:
        """Install exact edges or refuse while preserving every earlier edge.

        This checks table consistency only. A Path is not source admission and
        passing this method does not discharge the stronger no-bad premise.
        """
        _validate_path(selected)
        if selected.size != self.size:
            raise ValueError("another finite alphabet")
        for input_, output in selected.edges:
            verdict, actual = self.propose_forward(input_, output)
            if verdict == "occupied" or actual != output:
                raise ValueError("inconsistent private path")

    def snapshot(self) -> tuple[Edge, ...]:
        """Canonical edge data for outcome comparison."""
        return tuple(sorted(self.forward.items()))
