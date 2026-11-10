"""Pure statistical functions for WP6 paired experimental evaluation.

Provides:
- Exact McNemar test for paired binary outcomes (integer arithmetic, no overflow).
- Wilcoxon signed-rank test with tie handling: exact distribution for small numbers of
  non-zero differences, normal approximation with tie correction otherwise.
- Wilson score confidence intervals for binomial proportions.
- Newcombe (1998, method 10) interval for a paired difference of proportions, plus a paired
  non-inferiority decision and p-value built on it (used for H2).
- Seeded percentile bootstrap for paired mean differences.
- Holm-Bonferroni step-down multiple-testing correction.
"""

from __future__ import annotations

import math
import random
import statistics
from collections.abc import Mapping, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

EXACT_WILCOXON_MAX_NONZERO = 25


class McNemarResult(BaseModel):
    """Result of an exact McNemar test on paired binary outcomes."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    n_pairs: int = Field(ge=0)
    concordant_true: int = Field(ge=0)
    concordant_false: int = Field(ge=0)
    b_only_first_true: int = Field(ge=0)
    c_only_second_true: int = Field(ge=0)
    discordant_total: int = Field(ge=0)
    p_value: float = Field(ge=0.0, le=1.0)


class WilcoxonResult(BaseModel):
    """Result of a paired Wilcoxon signed-rank test (exact or normal approximation)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    n_pairs: int = Field(ge=0)
    n_nonzero: int = Field(ge=0)
    w_plus: float = Field(ge=0.0)
    w_minus: float = Field(ge=0.0)
    statistic: float = Field(ge=0.0)
    z_score: float
    p_value: float = Field(ge=0.0, le=1.0)
    method: Literal["exact", "normal"]


class ProportionInterval(BaseModel):
    """Wilson score confidence interval for a binomial proportion."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    successes: int = Field(ge=0)
    total: int = Field(ge=0)
    proportion: float = Field(ge=0.0, le=1.0)
    lower: float = Field(ge=0.0, le=1.0)
    upper: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(gt=0.0, lt=1.0)


class PairedDifferenceInterval(BaseModel):
    """Newcombe (1998) method-10 interval for p_first - p_second on paired binary data."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    n_pairs: int = Field(ge=0)
    both_true: int = Field(ge=0)
    first_only: int = Field(ge=0)
    second_only: int = Field(ge=0)
    both_false: int = Field(ge=0)
    p_first: float = Field(ge=0.0, le=1.0)
    p_second: float = Field(ge=0.0, le=1.0)
    difference: float = Field(ge=-1.0, le=1.0)
    lower: float = Field(ge=-1.0, le=1.0)
    upper: float = Field(ge=-1.0, le=1.0)
    confidence: float = Field(gt=0.0, lt=1.0)


class NonInferiorityResult(BaseModel):
    """Paired non-inferiority decision: is p_first - p_second > -margin?"""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    margin: float = Field(gt=0.0, le=1.0)
    alpha: float = Field(gt=0.0, lt=0.5)
    n_pairs: int = Field(ge=0)
    difference: float = Field(ge=-1.0, le=1.0)
    lower_bound: float = Field(ge=-1.0, le=1.0)
    non_inferior: bool
    p_value: float = Field(ge=0.0, le=1.0)


class BootstrapMeanDiffResult(BaseModel):
    """Seeded percentile bootstrap interval for paired mean difference (x - y)."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    n_pairs: int = Field(ge=0)
    mean_x: float
    mean_y: float
    mean_diff: float
    ci_lower: float
    ci_upper: float
    confidence: float = Field(gt=0.0, lt=1.0)
    n_resamples: int = Field(ge=1)
    seed: int


class HolmAdjustedItem(BaseModel):
    """Single hypothesis result after Holm-Bonferroni step-down adjustment."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    hypothesis_id: str
    raw_p_value: float = Field(ge=0.0, le=1.0)
    adjusted_p_value: float = Field(ge=0.0, le=1.0)
    rejected: bool
    alpha: float = Field(gt=0.0, lt=1.0)


def _z_for_confidence(confidence: float) -> float:
    """Two-sided standard-normal critical value for the given confidence level."""
    return statistics.NormalDist().inv_cdf(1.0 - 0.5 * (1.0 - confidence))


def _sig(value: float, digits: int = 12) -> float:
    """Round to `digits` significant figures (p-values below 1e-12 must not collapse to 0)."""
    return float(f"{value:.{digits}g}")


def _check_confidence(confidence: float) -> None:
    if not (0.0 < confidence < 1.0):
        raise ValueError(f"confidence must be in (0, 1), got {confidence}")


def exact_mcnemar_test(
    outcomes_a: Sequence[bool],
    outcomes_b: Sequence[bool],
    *,
    alternative: Literal["two-sided", "less", "greater"] = "two-sided",
) -> McNemarResult:
    """Compute exact binomial McNemar test for paired binary sequences.

    `b_only_first_true` counts pairs where only the first sequence is true. For
    `alternative="less"` the p-value is P(X <= b) with X ~ Binomial(discordant, 1/2), i.e. evidence
    that the first sequence has the lower success rate; "greater" is the mirror image.
    """
    if len(outcomes_a) != len(outcomes_b):
        raise ValueError(
            f"Paired sequences must have equal length ({len(outcomes_a)} != {len(outcomes_b)})."
        )
    both_true = 0
    both_false = 0
    b_count = 0
    c_count = 0
    for a_val, b_val in zip(outcomes_a, outcomes_b, strict=True):
        a_bool = bool(a_val)
        b_bool = bool(b_val)
        if a_bool and b_bool:
            both_true += 1
        elif not a_bool and not b_bool:
            both_false += 1
        elif a_bool:
            b_count += 1
        else:
            c_count += 1

    n_disc = b_count + c_count
    if n_disc == 0:
        p_val = 1.0
    else:
        denom = 1 << n_disc  # exact integer; int / int true division cannot overflow here
        if alternative == "less":
            p_val = sum(math.comb(n_disc, i) for i in range(b_count + 1)) / denom
        elif alternative == "greater":
            p_val = sum(math.comb(n_disc, i) for i in range(b_count, n_disc + 1)) / denom
        else:
            k_min = min(b_count, c_count)
            p_val = 2 * sum(math.comb(n_disc, i) for i in range(k_min + 1)) / denom
        p_val = min(1.0, max(0.0, p_val))

    return McNemarResult(
        n_pairs=len(outcomes_a),
        concordant_true=both_true,
        concordant_false=both_false,
        b_only_first_true=b_count,
        c_only_second_true=c_count,
        discordant_total=n_disc,
        p_value=_sig(p_val),
    )


def _exact_signed_rank_two_sided_p(doubled_ranks: Sequence[int], doubled_w_min: int) -> float:
    """Exact two-sided p for W+ given (possibly tied) ranks doubled to integers.

    Under H0 every sign assignment is equally likely, so W+ = sum of ranks over positive signs
    has a distribution obtainable by dynamic programming. It is symmetric, so the two-sided p
    equals 2 * P(W+ <= min(W+, W-)).
    """
    total = sum(doubled_ranks)
    counts = [0] * (total + 1)
    counts[0] = 1
    for rank in doubled_ranks:
        for s in range(total, rank - 1, -1):
            counts[s] += counts[s - rank]
    tail = sum(counts[: doubled_w_min + 1])
    return min(1.0, 2 * tail / (1 << len(doubled_ranks)))


def wilcoxon_signed_rank_test(
    x: Sequence[float],
    y: Sequence[float],
    *,
    correction: bool = False,
) -> WilcoxonResult:
    """Paired Wilcoxon signed-rank test (zero differences dropped, midranks for ties).

    With at most `EXACT_WILCOXON_MAX_NONZERO` non-zero differences the exact null distribution
    is used (valid with ties). Otherwise the normal approximation with tie correction is used;
    `correction` applies a continuity correction to that approximation only.
    """
    if len(x) != len(y):
        raise ValueError(
            f"Paired sequences must have equal length ({len(x)} != {len(y)})."
        )
    diffs = [float(a) - float(b) for a, b in zip(x, y, strict=True)]
    nonzero = [d for d in diffs if d != 0.0]
    n_r = len(nonzero)
    if n_r == 0:
        return WilcoxonResult(
            n_pairs=len(x),
            n_nonzero=0,
            w_plus=0.0,
            w_minus=0.0,
            statistic=0.0,
            z_score=0.0,
            p_value=1.0,
            method="exact",
        )

    indexed = sorted(enumerate(nonzero), key=lambda pair: abs(pair[1]))
    ranks = [0.0] * n_r
    tie_counts: list[int] = []

    i = 0
    while i < n_r:
        j = i
        abs_val = abs(indexed[i][1])
        while j < n_r and math.isclose(
            abs(indexed[j][1]), abs_val, rel_tol=1e-12, abs_tol=1e-12
        ):
            j += 1
        tie_len = j - i
        avg_rank = 0.5 * ((i + 1) + j)
        for k in range(i, j):
            ranks[indexed[k][0]] = avg_rank
        if tie_len > 1:
            tie_counts.append(tie_len)
        i = j

    w_plus = sum(r for d, r in zip(nonzero, ranks, strict=True) if d > 0.0)
    w_minus = sum(r for d, r in zip(nonzero, ranks, strict=True) if d < 0.0)
    w_stat = min(w_plus, w_minus)

    mean_w = n_r * (n_r + 1) / 4.0
    tie_term = sum(t * t * t - t for t in tie_counts) / 48.0
    var_w = (n_r * (n_r + 1) * (2 * n_r + 1)) / 24.0 - tie_term
    z_val = 0.0 if var_w <= 0.0 else (w_stat - mean_w) / math.sqrt(var_w)

    if n_r <= EXACT_WILCOXON_MAX_NONZERO:
        doubled = [round(2.0 * r) for r in ranks]
        p_val = _exact_signed_rank_two_sided_p(doubled, round(2.0 * w_stat))
        method: Literal["exact", "normal"] = "exact"
    else:
        method = "normal"
        if var_w <= 0.0:
            p_val = 1.0
        else:
            num = w_stat - mean_w
            if correction and num != 0.0:
                num = num - 0.5 if num > 0.0 else num + 0.5
            z_val = num / math.sqrt(var_w)
            p_val = min(1.0, max(0.0, math.erfc(abs(z_val) / math.sqrt(2.0))))

    return WilcoxonResult(
        n_pairs=len(x),
        n_nonzero=n_r,
        w_plus=round(w_plus, 6),
        w_minus=round(w_minus, 6),
        statistic=round(w_stat, 6),
        z_score=round(z_val, 8),
        p_value=_sig(p_val),
        method=method,
    )


def _wilson_bounds(successes: int, total: int, z: float) -> tuple[float, float]:
    """Unrounded Wilson score limits for successes/total at critical value z."""
    n = float(total)
    p_hat = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2.0 * n)) / denom
    radicand = max(0.0, (p_hat * (1.0 - p_hat) / n) + (z2 / (4.0 * n * n)))
    half = (z * math.sqrt(radicand)) / denom
    return min(1.0, max(0.0, center - half)), min(1.0, max(0.0, center + half))


def wilson_score_interval(
    successes: int,
    total: int,
    *,
    confidence: float = 0.95,
) -> ProportionInterval:
    """Compute Wilson score confidence interval for a binomial proportion."""
    if total < 0 or successes < 0 or successes > total:
        raise ValueError(f"Invalid binomial counts: successes={successes}, total={total}")
    _check_confidence(confidence)
    if total == 0:
        return ProportionInterval(
            successes=0,
            total=0,
            proportion=0.0,
            lower=0.0,
            upper=0.0,
            confidence=confidence,
        )
    low, high = _wilson_bounds(successes, total, _z_for_confidence(confidence))
    return ProportionInterval(
        successes=successes,
        total=total,
        proportion=round(successes / total, 6),
        lower=round(low, 6),
        upper=round(high, 6),
        confidence=confidence,
    )


def _paired_counts(first: Sequence[bool], second: Sequence[bool]) -> tuple[int, int, int, int]:
    if len(first) != len(second):
        raise ValueError(
            f"Paired sequences must have equal length ({len(first)} != {len(second)})."
        )
    both_true = first_only = second_only = both_false = 0
    for a_val, b_val in zip(first, second, strict=True):
        a_bool = bool(a_val)
        b_bool = bool(b_val)
        if a_bool and b_bool:
            both_true += 1
        elif a_bool:
            first_only += 1
        elif b_bool:
            second_only += 1
        else:
            both_false += 1
    return both_true, first_only, second_only, both_false


def _newcombe_paired_bounds(
    a: int, b: int, c: int, d: int, confidence: float, *, z: float | None = None
) -> tuple[float, float, float, float, float]:
    """Return (p_first, p_second, difference, lower, upper) by Newcombe (1998) method 10.

    Cells: a = both true, b = first only, c = second only, d = both false.
    """
    n = a + b + c + d
    p1 = (a + b) / n
    p2 = (a + c) / n
    z = _z_for_confidence(confidence) if z is None else z
    l1, u1 = _wilson_bounds(a + b, n, z)
    l2, u2 = _wilson_bounds(a + c, n, z)

    margin_product = (a + b) * (c + d) * (a + c) * (b + d)
    if margin_product == 0:
        phi = 0.0
    else:
        raw = a * d - b * c
        numerator = max(raw - n / 2.0, 0.0) if raw > 0 else float(raw)
        phi = numerator / math.sqrt(margin_product)

    diff = p1 - p2
    lo_arm = (p1 - l1) ** 2 - 2.0 * phi * (p1 - l1) * (u2 - p2) + (u2 - p2) ** 2
    hi_arm = (u1 - p1) ** 2 - 2.0 * phi * (u1 - p1) * (p2 - l2) + (p2 - l2) ** 2
    lower = max(-1.0, diff - math.sqrt(max(0.0, lo_arm)))
    upper = min(1.0, diff + math.sqrt(max(0.0, hi_arm)))
    return p1, p2, diff, lower, upper


def newcombe_paired_difference_interval(
    first: Sequence[bool],
    second: Sequence[bool],
    *,
    confidence: float = 0.95,
) -> PairedDifferenceInterval:
    """Newcombe (1998) method-10 interval for p_first - p_second on paired binary data."""
    _check_confidence(confidence)
    a, b, c, d = _paired_counts(first, second)
    n = a + b + c + d
    if n == 0:
        return PairedDifferenceInterval(
            n_pairs=0,
            both_true=0,
            first_only=0,
            second_only=0,
            both_false=0,
            p_first=0.0,
            p_second=0.0,
            difference=0.0,
            lower=0.0,
            upper=0.0,
            confidence=confidence,
        )
    p1, p2, diff, lower, upper = _newcombe_paired_bounds(a, b, c, d, confidence)
    return PairedDifferenceInterval(
        n_pairs=n,
        both_true=a,
        first_only=b,
        second_only=c,
        both_false=d,
        p_first=round(p1, 6),
        p_second=round(p2, 6),
        difference=round(diff, 6),
        lower=round(lower, 6),
        upper=round(upper, 6),
        confidence=confidence,
    )


def paired_noninferiority_test(
    first: Sequence[bool],
    second: Sequence[bool],
    *,
    margin: float,
    alpha: float = 0.025,
) -> NonInferiorityResult:
    """Test H1: p_first - p_second > -margin on paired binary data (e.g. GateHeal vs baseline).

    Decision: non-inferior iff the lower limit of the Newcombe two-sided (1 - 2*alpha) interval
    exceeds -margin (one-sided level alpha). The p-value is the smallest one-sided level at which
    that decision flips, found by bisection; it is 1.0 when the point estimate itself does not
    exceed -margin. It is intended as an input to the Holm correction.
    """
    if not (0.0 < margin <= 1.0):
        raise ValueError(f"margin must be in (0, 1], got {margin}")
    if not (0.0 < alpha < 0.5):
        raise ValueError(f"alpha must be in (0, 0.5), got {alpha}")
    a, b, c, d = _paired_counts(first, second)
    n = a + b + c + d
    if n == 0:
        return NonInferiorityResult(
            margin=margin,
            alpha=alpha,
            n_pairs=0,
            difference=0.0,
            lower_bound=0.0,
            non_inferior=False,
            p_value=1.0,
        )

    def lower_at(one_sided_alpha: float) -> float:
        # z from the upper-tail probability directly: 1 - 2*alpha loses all precision below 1e-16.
        z_alpha = -statistics.NormalDist().inv_cdf(one_sided_alpha)
        return _newcombe_paired_bounds(a, b, c, d, 1.0 - 2.0 * one_sided_alpha, z=z_alpha)[3]

    _, _, diff, lower, _ = _newcombe_paired_bounds(a, b, c, d, 1.0 - 2.0 * alpha)
    threshold = -margin
    if diff <= threshold:
        p_val = 1.0
    else:
        lo, hi = 1e-300, 0.5 - 1e-12
        if lower_at(lo) > threshold:
            p_val = lo
        elif lower_at(hi) <= threshold:
            p_val = 1.0
        else:
            for _ in range(200):
                mid = math.sqrt(lo * hi)  # bisect on the log scale: p can be astronomically small
                if lower_at(mid) > threshold:
                    hi = mid
                else:
                    lo = mid
            p_val = hi
    return NonInferiorityResult(
        margin=margin,
        alpha=alpha,
        n_pairs=n,
        difference=round(diff, 6),
        lower_bound=round(lower, 6),
        non_inferior=lower > threshold,
        p_value=_sig(min(1.0, max(0.0, p_val))),
    )


def paired_bootstrap_mean_diff(
    x: Sequence[float],
    y: Sequence[float],
    *,
    n_resamples: int = 2000,
    confidence: float = 0.95,
    seed: int = 20261028,
) -> BootstrapMeanDiffResult:
    """Compute seeded percentile bootstrap CI for paired mean difference (x - y)."""
    if len(x) != len(y):
        raise ValueError(
            f"Paired sequences must have equal length ({len(x)} != {len(y)})."
        )
    if n_resamples < 1:
        raise ValueError("n_resamples must be >= 1")
    _check_confidence(confidence)

    n = len(x)
    if n == 0:
        return BootstrapMeanDiffResult(
            n_pairs=0,
            mean_x=0.0,
            mean_y=0.0,
            mean_diff=0.0,
            ci_lower=0.0,
            ci_upper=0.0,
            confidence=confidence,
            n_resamples=n_resamples,
            seed=seed,
        )

    fx = [float(v) for v in x]
    fy = [float(v) for v in y]
    diffs = [a - b for a, b in zip(fx, fy, strict=True)]
    mean_x = statistics.fmean(fx)
    mean_y = statistics.fmean(fy)
    obs_diff = statistics.fmean(diffs)

    rng = random.Random(seed)
    boot_means: list[float] = []
    inv_n = 1.0 / n
    for _ in range(n_resamples):
        total = 0.0
        for _ in range(n):
            total += diffs[rng.randrange(n)]
        boot_means.append(total * inv_n)

    boot_means.sort()
    alpha = 1.0 - confidence
    low_pos = (0.5 * alpha) * (n_resamples - 1)
    high_pos = (1.0 - 0.5 * alpha) * (n_resamples - 1)

    def _interp(pos: float) -> float:
        lo = math.floor(pos)
        hi = min(n_resamples - 1, math.ceil(pos))
        frac = pos - lo
        return boot_means[lo] * (1.0 - frac) + boot_means[hi] * frac

    return BootstrapMeanDiffResult(
        n_pairs=n,
        mean_x=round(mean_x, 6),
        mean_y=round(mean_y, 6),
        mean_diff=round(obs_diff, 6),
        ci_lower=round(_interp(low_pos), 6),
        ci_upper=round(_interp(high_pos), 6),
        confidence=confidence,
        n_resamples=n_resamples,
        seed=seed,
    )


def holm_bonferroni_correction(
    p_values: Mapping[str, float] | Sequence[tuple[str, float]],
    *,
    alpha: float = 0.05,
) -> tuple[HolmAdjustedItem, ...]:
    """Apply Holm-Bonferroni step-down multiple-testing correction across a family."""
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")
    items = (
        list(p_values.items())
        if isinstance(p_values, Mapping)
        else list(p_values)
    )
    m = len(items)
    if m == 0:
        return ()

    for hyp_id, p_val in items:
        if not (0.0 <= p_val <= 1.0):
            raise ValueError(f"Invalid p-value for {hyp_id!r}: {p_val}")

    indexed = list(enumerate(items))
    indexed.sort(key=lambda entry: (entry[1][1], entry[0]))

    adjusted_by_idx: dict[int, HolmAdjustedItem] = {}
    running_max = 0.0
    step_down_stopped = False

    for rank_idx, (orig_idx, (hyp_id, raw_p)) in enumerate(indexed):
        multiplier = m - rank_idx
        candidate = min(1.0, raw_p * multiplier)
        running_max = max(running_max, candidate)
        adj_p = min(1.0, running_max)
        if adj_p > alpha:
            step_down_stopped = True
        rejected = (not step_down_stopped) and (adj_p <= alpha)
        adjusted_by_idx[orig_idx] = HolmAdjustedItem(
            hypothesis_id=hyp_id,
            raw_p_value=_sig(raw_p),
            adjusted_p_value=_sig(adj_p),
            rejected=rejected,
            alpha=alpha,
        )

    return tuple(adjusted_by_idx[idx] for idx in range(m))
