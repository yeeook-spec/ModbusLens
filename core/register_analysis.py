"""Read-only interpretations of captured Modbus registers.

Addresses are zero-based PDU addresses, never 4xxxx/3xxxx reference numbers.
Scores are deliberately conservative troubleshooting hints, not probabilities or
proof of a tag's type, offset, byte order, scaling, or engineering units. A single
snapshot cannot establish those things. Raw words and exact addresses accompany
every interpretation so it can be checked against device documentation.
"""

from dataclasses import dataclass
import math
from numbers import Integral, Real
import struct
from typing import Iterable, Iterator, Mapping


DEFAULT_OFFSETS = (-2, -1, 0, 1, 2)
DATA_TYPES = ("U16", "S16", "U32", "S32", "F32")
BYTE_ORDERS = ("ABCD", "CDAB", "BADC", "DCBA")
_ORDER_INDICES = {
    "ABCD": (0, 1, 2, 3),
    "CDAB": (2, 3, 0, 1),
    "BADC": (1, 0, 3, 2),
    "DCBA": (3, 2, 1, 0),
}
_FLOAT32_MIN_NORMAL = 2.0 ** -126


@dataclass(frozen=True, slots=True)
class RegisterCandidate:
    requested_address: int
    pdu_address: int
    offset: int
    raw_words: tuple[int, ...]
    data_type: str
    byte_order: str
    value: int | float
    score: int
    reasons: tuple[str, ...]
    in_range: bool | None


def _address(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, Integral) or not 0 <= value <= 65535:
        raise ValueError("PDU addresses must be integers from 0 through 65535.")
    return int(value)


def _bound(value: float | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, Real) or not math.isfinite(value):
        raise ValueError("Expected-value bounds must be finite numbers.")
    return value


def _choices(values: Iterable[str], allowed: tuple[str, ...], label: str) -> tuple[str, ...]:
    choices = tuple(dict.fromkeys(values))
    if not choices or any(choice not in allowed for choice in choices):
        raise ValueError(f"{label} must contain only: {', '.join(allowed)}.")
    return choices


def _score(value, data_type, words, min_value, max_value):
    """Return heuristic priority and explicit evidence; do not infer units/type."""
    reasons = []
    score = 50
    if all(word == 0 for word in words):
        score -= 20
        reasons.append("All raw words are 0x0000; zero may be valid or uninitialized.")
    elif all(word == 0xFFFF for word in words):
        score -= 35
        reasons.append("All raw words are 0xFFFF; may be a sentinel or valid data.")
    elif any(word == 0xFFFF for word in words):
        score -= 10
        reasons.append("Contains 0xFFFF; may be a sentinel or valid data.")

    has_bounds = min_value is not None or max_value is not None
    if not math.isfinite(value):
        reasons.insert(0, "Non-finite float (NaN or infinity).")
        return 0, tuple(reasons), False if has_bounds else None

    in_range = None
    if has_bounds:
        in_range = ((min_value is None or value >= min_value)
                    and (max_value is None or value <= max_value))
        if in_range:
            score += 30
            reasons.append("Within the supplied expected-value range.")
        else:
            score -= 45
            reasons.append("Outside the supplied expected-value range.")

    if data_type == "F32":
        magnitude = abs(value)
        if 0 < magnitude < _FLOAT32_MIN_NORMAL:
            score -= 40
            reasons.append("Subnormal float; often a mismatched interpretation.")
        elif 0 < magnitude < 1e-6:
            score -= 15
            reasons.append("Magnitude below 1e-6; confirm units and scaling.")
        elif magnitude > 1e12:
            score -= 25
            reasons.append("Magnitude above 1e12; confirm units and scaling.")
        if not reasons:
            reasons.append("Finite float; plausibility requires units, scaling, or an expected range.")
    elif not reasons:
        reasons.append("Integer interpretation; plausibility requires units, scaling, or an expected range.")

    return max(0, min(100, score)), tuple(reasons), in_range


def iter_register_candidates(
    registers: Mapping[int, int | None],
    addresses: Iterable[int],
    *,
    offsets: Iterable[int] = DEFAULT_OFFSETS,
    data_types: Iterable[str] = DATA_TYPES,
    byte_orders: Iterable[str] = BYTE_ORDERS,
    min_value: float | None = None,
    max_value: float | None = None,
) -> Iterator[RegisterCandidate]:
    """Yield ranked interpretations for each requested address, in input order.

    ``registers`` is a capture keyed by exact PDU address. Omitted addresses and
    values of None mean unreadable/missing: no multiword value crosses that gap.
    ``addresses=range(start, end + 1)`` examines every nominal address in a section;
    the iterator only retains one nominal address's candidates at a time, so the
    full 0..65535 address space need not produce a huge result list.

    Bounds apply to decoded values before any scaling. Candidates outside bounds
    remain visible with ``in_range=False``; no outlier is silently discarded.
    A 16-bit value uses byte order AB. The four 32-bit orders are permutations of
    the two captured words' bytes A B C D, with each captured word big-endian.
    Scores only prioritize inspection and cannot choose a correct data type.
    """
    selected_types = _choices(data_types, DATA_TYPES, "Data types")
    selected_orders = _choices(byte_orders, BYTE_ORDERS, "Byte orders")
    selected_offsets = tuple(dict.fromkeys(offsets))
    if not selected_offsets or any(isinstance(offset, bool) or not isinstance(offset, Integral)
                                   for offset in selected_offsets):
        raise ValueError("Offsets must contain at least one integer.")
    min_value, max_value = _bound(min_value), _bound(max_value)
    if min_value is not None and max_value is not None and min_value > max_value:
        raise ValueError("Minimum expected value must not exceed the maximum.")

    # Validate rather than mask invalid capture data into an apparently good word.
    words_by_address = {}
    for captured_address, word in registers.items():
        captured_address = _address(captured_address)
        if word is None:
            continue
        if isinstance(word, bool) or not isinstance(word, Integral) or not 0 <= word <= 65535:
            raise ValueError("Captured register words must be integers from 0 through 65535, or None.")
        words_by_address[captured_address] = int(word)

    for requested_address in addresses:
        requested_address = _address(requested_address)
        candidates = []
        for offset in selected_offsets:
            pdu_address = requested_address + offset
            if not 0 <= pdu_address <= 65535 or pdu_address not in words_by_address:
                continue
            for data_type in selected_types:
                width = 1 if data_type in ("U16", "S16") else 2
                if pdu_address + width - 1 > 65535:
                    continue
                if any(pdu_address + index not in words_by_address for index in range(width)):
                    continue
                raw_words = tuple(words_by_address[pdu_address + index] for index in range(width))
                raw_bytes = b"".join(word.to_bytes(2, "big") for word in raw_words)
                for order in (("AB",) if width == 1 else selected_orders):
                    ordered = (raw_bytes if width == 1
                               else bytes(raw_bytes[index] for index in _ORDER_INDICES[order]))
                    if data_type == "F32":
                        value = struct.unpack(">f", ordered)[0]
                    else:
                        value = int.from_bytes(ordered, "big", signed=data_type.startswith("S"))
                    score, reasons, in_range = _score(value, data_type, raw_words, min_value, max_value)
                    candidates.append(RegisterCandidate(
                        requested_address, pdu_address, int(offset), raw_words,
                        data_type, order, value, score, reasons, in_range,
                    ))
        # Prefer the requested address only as a tie-breaker, not as evidence.
        candidates.sort(key=lambda candidate: (-candidate.score, abs(candidate.offset), candidate.offset))
        yield from candidates


def analyze_registers(registers: Mapping[int, int | None], addresses: Iterable[int], **options) -> list[RegisterCandidate]:
    """Materialize candidates for a small section; use the iterator for large scans."""
    return list(iter_register_candidates(registers, addresses, **options))
