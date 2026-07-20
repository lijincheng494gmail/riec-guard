from __future__ import annotations

from collections import Counter

import pytest

from riec_guard.protocols.group_bootstrap import resample_whole_groups
from riec_guard.riec.design import PreparedDataset, SemanticSeries


def _dataset() -> PreparedDataset:
    return PreparedDataset(
        response=(1.0, 1.1, 2.0, 2.1, 2.2, 3.0),
        group_keys=(("A",), ("A",), ("B",), ("B",), ("B",), ("C",)),
        group_tokens=("GRP-A", "GRP-A", "GRP-B", "GRP-B", "GRP-B", "GRP-C"),
        product=SemanticSeries("product", "product", True, ("P",) * 6),
        stream=SemanticSeries("stream", "stream", True, ("S",) * 6),
        shift=SemanticSeries("shift", None, False, None),
        time_hours=(0.0, 1.0, 2.0, 3.0, 4.0, 5.0),
        time_column="time",
        time_confirmed=True,
        row_order=(0, 1, 2, 3, 4, 5),
        n_rows=6,
        n_groups=3,
    )


@pytest.mark.parametrize(
    ("sampled", "expected_rows"),
    [
        (("GRP-A", "GRP-C", "GRP-A"), 5),
        (("GRP-B", "GRP-B", "GRP-B"), 9),
        (("GRP-C", "GRP-A", "GRP-B"), 6),
    ],
)
def test_resampling_keeps_complete_groups_and_distinguishes_repeats(
    sampled: tuple[str, ...], expected_rows: int
) -> None:
    source = _dataset()
    result = resample_whole_groups(source, sampled, replicate_index=12)

    assert result.n_groups == len(sampled)
    assert result.n_rows == expected_rows
    assert len(set(result.group_tokens)) == len(sampled)
    assert all(token.startswith("BGRP-000012-") for token in result.group_tokens)
    counts = Counter(result.group_tokens)
    expected_sizes = {"GRP-A": 2, "GRP-B": 3, "GRP-C": 1}
    for draw_index, source_token in enumerate(sampled):
        assert counts[f"BGRP-000012-{draw_index:06d}"] == expected_sizes[source_token]

    # Resampling is non-mutating and local identifiers do not carry source labels.
    assert source.group_tokens == ("GRP-A", "GRP-A", "GRP-B", "GRP-B", "GRP-B", "GRP-C")
    assert not any(
        source_token in token for source_token in sampled for token in result.group_tokens
    )


def test_unknown_source_group_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown group token"):
        resample_whole_groups(_dataset(), ("GRP-UNKNOWN",), replicate_index=0)
