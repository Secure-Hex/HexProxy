from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class SplitLayout:
    min_primary: int
    min_secondary: int
    min_ratio: float = 0.1
    max_ratio: float = 0.9

    def clamp_ratio(self, ratio: float) -> float:
        return min(max(ratio, self.min_ratio), self.max_ratio)

    def adjust_ratio(self, ratio: float, delta: float) -> float:
        return self.clamp_ratio(ratio + delta)

    def partition(self, total: int, ratio: float) -> tuple[int, int]:
        total = max(total, 0)
        if total == 0:
            return 0, 0
        ratio = self.clamp_ratio(ratio)
        target = int(round(total * ratio))
        target = min(max(target, 0), total)
        if total >= self.min_primary + self.min_secondary:
            max_primary = total - self.min_secondary
            primary = min(max(target, self.min_primary), max_primary)
        else:
            primary = min(target, total)
        secondary = total - primary
        if total >= self.min_primary + self.min_secondary:
            secondary = max(secondary, self.min_secondary)
        return primary, secondary
