"""Pure statistical functions for WP6 paired experimental evaluation.

Provides:
- Exact McNemar test for paired binary outcomes.
- Wilcoxon signed-rank test with tie correction for paired continuous outcomes.
- Wilson score confidence intervals for binomial proportions.
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
    """Result of a paired Wilcoxon signed-rank test with tie correction."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    n_pairs: int = Field(ge=0)
    n_nonzero: int = Field(ge=0)
    w_plus: float = Field(ge=0.0)
    w_minus: float = Field(ge=0.0)
    statistic: float = Field(ge=0.0)
    z_score: float
    p_value: float = Field(ge=0.0, le=1.0)


class ProportionInterval(BaseModel):
    """Wilson score confidence interval for a binomial proportion."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    successes: int = Field(ge=0)
    total: int = Field(ge=0)
    proportion: float = Field(ge=0.0, le=1.0)
    lower: float = Field(ge=0.0, le=1.0)
    upper: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(gt=0.0, lt=1.0)


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


def _norm_ppf(p: float) -> float:
    """Rational approximation (Acklam / Beasley-Springer-Moro) for standard normal PPF."""
    if not (0.0 < p < 1.0):
        raise ValueError(f"Probability p must be in (0, 1), got {p}")
    if abs(p - 0.975) < 1e-12:
        return 1.959963984540054
    a = (
        -3.969683028665376e01,
        2.209460984245205e02,
        -2.759285104469687e02,
        1.383577518672690e02,
        -3.066479806614716e01,
        2.506628277459239e00,
    )
    b = (
        -5.447609879822406e01,
        1.615858368580409e02,
        -1.556989798598866e02,
        6.680131188771972e01,
        -1.328068155288572e01,
    )
    c = (
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e00,
        -2.549732539343734e00,
        4.374664141464968e00,
        2.938163982698783e00,
    )
    d = (
        7.784695709041462e-03,
        3.224671290700398e-01,
        2.445134137142996e00,
        3.754408661907416e00,
    )
    p_low = 0.02425
    p_high = 1.0 - p_low
    if p < p_low:
        q = math.sqrt(-2.0 * math.log(p))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
            (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0
        )
    if p <= p_high:
        q = p - 0.5
        r = q * q
        return (
            (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5])
            * q
            / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0)
        )
    q = math.sqrt(-2.0 * math.log(1.0 - p))
    return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
        (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0
    )


def exact_mcnemar_test(
    outcomes_a: Sequence[bool],
    outcomes_b: Sequence[bool],
    *,
    alternative: Literal["two-sided", "less", "greater"] = "two-sided",
) -> McNemarResult:
    """Compute exact binomial McNemar test for paired binary sequences."""
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
        elif a_bool and not b_bool:
            b_count += 1
        else:
            c_count += 1

    n_disc = b_count + c_count
    if n_disc == 0:
        p_val = 1.0
    else:
        denom = float(1 << n_disc)
        if alternative == "less":
            tail = sum(math.comb(n_disc, i) for i in range(b_count + 1)) / denom
            p_val = min(1.0, max(0.0, tail))
        elif alternative == "greater":
            tail = sum(math.comb(n_disc, i) for i in range(b_count, n_disc + 1)) / denom
            p_val = min(1.0, max(0.0, tail))
        else:
            k_min = min(b_count, c_count)
            lower_tail = sum(math.comb(n_disc, i) for i in range(k_min + 1)) / denom
            p_val = min(1.0, max(0.0, 2.0 * lower_tail))

    return McNemarResult(
        n_pairs=len(outcomes_a),
        concordant_true=both_true,
        concordant_false=both_false,
        b_only_first_true=b_count,
        c_only_second_true=c_count,
        discordant_total=n_disc,
        p_value=round(p_val, 12),
    )


def wilcoxon_signed_rank_test(
    x: Sequence[float],
    y: Sequence[float],
    *,
    correction: bool = False,
) -> WilcoxonResult:
    """Compute paired Wilcoxon signed-rank test with tie correction."""
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
        )

    indexed = sorted(enumerate(nonzero), key=lambda pair: abs(pair[1]))
    ranks = [0.0] * n_r
    tie_counts: list[int] = []

    i = 0
    while i < n_r:
        j = i
        abs_val = abs(indexed[i][1])
        while j < n_r and math.isclose(abs(indexed[j][1]), abs_val, rel_tol=1e-12, abs_tol=1e-12):
            j += 1
        tie_len = j - i
        avg_rank = 0.5 * ((i + 1) + j)
        for k in range(i, j):
            orig_idx = indexed[k][0]
            ranks[orig_idx] = avg_rank
        if tie_len > 1:
            tie_counts.append(tie_len)
        i = j

    w_plus = sum(r for d, r in zip(nonzero, ranks, strict=True) if d > 0.0)
    w_minus = sum(r for d, r in zip(nonzero, ranks, strict=True) if d < 0.0)
    w_stat = min(w_plus, w_minus)

    mean_w = n_r * (n_r + 1) / 4.0
    tie_term = sum(t * t * t - t for t in tie_counts) / 48.0
    var_w = (n_r * (n_r + 1) * (2 * n_r + 1)) / 24.0 - tie_term

    if var_w <= 0.0:
        return WilcoxonResult(
            n_pairs=len(x),
            n_nonzero=n_r,
            w_plus=round(w_plus, 6),
            w_minus=round(w_minus, 6),
            statistic=round(w_stat, 6),
            z_score=0.0,
            p_value=1.0,
        )

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
        p_value=round(p_val, 12),
    )


def wilson_score_interval(
    successes: int,
    total: int,
    *,
    confidence: float = 0.95,
) -> ProportionInterval:
    """Compute Wilson score confidence interval for a binomial proportion."""
    if total < 0 or successes < 0 or successes > total:
        raise ValueError(f"Invalid binomial counts: successes={successes}, total={total}")
    if not (0.0 < confidence < 1.0):
        raise ValueError(f"confidence must be in (0, 1), got {confidence}")
    if total == 0:
        return ProportionInterval(
            successes=0,
            total=0,
            proportion=0.0,
            lower=0.0,
            upper=0.0,
            confidence=confidence,
        )

    alpha = 1.0 - confidence
    z = _norm_ppf(1.0 - 0.5 * alpha)
    z2 = z * z
    n = float(total)
    p_hat = successes / n

    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2.0 * n)) / denom
    radicand = max(0.0, (p_hat * (1.0 - p_hat) / n) + (z2 / (4.0 * n * n)))
    half = (z * math.sqrt(radicand)) / denom

    low = min(1.0, max(0.0, center - half))
    high = min(1.0, max(0.0, center + half))
    return ProportionInterval(
        successes=successes,
        total=total,
        proportion=round(p_hat, 6),
        lower=round(low, 6),
        upper=round(high, 6),
        confidence=confidence,
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
    if not (0.0 < confidence < 1.0):
        raise ValueError(f"confidence must be in (0, 1), got {confidence}")

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
        lo = int(math.floor(pos))
        hi = min(n_resamples - 1, int(math.ceil(pos)))
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
            raw_p_value=round(raw_p, 12),
            adjusted_p_value=round(adj_p, 12),
            rejected=rejected,
            alpha=alpha,
        )

    return tuple(adjusted_by_idx[idx] for idx in range(m))
