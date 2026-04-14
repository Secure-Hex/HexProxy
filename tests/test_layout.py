from hexproxy.tui.layout import SplitLayout


def test_split_layout_partitions_with_ratio() -> None:
    layout = SplitLayout(min_primary=20, min_secondary=10)
    primary, secondary = layout.partition(100, 0.3)
    assert primary == 30
    assert secondary == 70


def test_split_layout_enforces_minimum_sizes() -> None:
    layout = SplitLayout(min_primary=20, min_secondary=10)
    primary, secondary = layout.partition(30, 0.1)
    assert primary == 20
    assert secondary == 10


def test_split_layout_gracefully_handles_small_total() -> None:
    layout = SplitLayout(min_primary=20, min_secondary=20)
    primary, secondary = layout.partition(10, 0.5)
    assert primary + secondary == 10
    assert primary == 5
    assert secondary == 5


def test_split_layout_clamps_ratio_adjustments() -> None:
    layout = SplitLayout(min_primary=5, min_secondary=5, min_ratio=0.2, max_ratio=0.8)
    base_ratio = 0.5
    assert layout.adjust_ratio(base_ratio, 1.0) == 0.8
    assert layout.adjust_ratio(base_ratio, -1.0) == 0.2


def test_split_layout_limits_primary_when_secondary_minimum_applies() -> None:
    layout = SplitLayout(min_primary=30, min_secondary=40)
    total = 100
    primary, secondary = layout.partition(total, 0.95)
    assert primary == total - layout.min_secondary
    assert secondary == layout.min_secondary
