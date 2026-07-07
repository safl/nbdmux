"""URL-state helpers for paginated + sortable HTML tables.

Ported from :mod:`bty.web._table_state` so the nbdmux operator UI
shares the same "sort clicks + page nav live in the query string,
one server round-trip per interaction" pattern the bty operator
console uses. The eventual ``trio-common`` extraction rolls this
into one library.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

PER_PAGE_CHOICES: tuple[int, ...] = (10, 25, 50, 100)
DEFAULT_PER_PAGE = PER_PAGE_CHOICES[0]

_NUMBERED_WINDOW = 2


@dataclass(frozen=True)
class SortState:
    column: str
    direction: str  # "asc" | "desc"
    order_by_sql: str

    def is_active(self, column: str) -> bool:
        return self.column == column

    def next_direction(self, column: str) -> str:
        return "desc" if self.is_active(column) and self.direction == "asc" else "asc"


@dataclass(frozen=True)
class PageState:
    page: int
    per_page: int
    total: int
    offset: int
    limit: int

    @property
    def last_page(self) -> int:
        if self.total <= 0:
            return 1
        return (self.total + self.per_page - 1) // self.per_page

    @property
    def first_row(self) -> int:
        if self.total <= 0:
            return 0
        return self.offset + 1

    @property
    def last_row(self) -> int:
        if self.total <= 0:
            return 0
        return min(self.offset + self.per_page, self.total)

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.last_page

    def numbered_pages(self) -> list[int]:
        lo = max(1, self.page - _NUMBERED_WINDOW)
        hi = min(self.last_page, self.page + _NUMBERED_WINDOW)
        return list(range(lo, hi + 1))


def parse_sort(
    params: Mapping[str, str],
    *,
    allowed: Mapping[str, str],
    default_column: str,
    default_direction: str = "asc",
) -> SortState:
    """Parse ``?sort=...&dir=...`` against a per-page column allowlist.

    ``allowed`` maps the URL column key to a SQL fragment (or Python
    key, for in-memory tables). Anything not in ``allowed`` falls back
    to ``default_column`` -- the only SQL safety guard. Direction
    outside ``asc|desc`` falls back to ``default_direction``.
    """
    if default_column not in allowed:
        raise ValueError(
            f"default_column {default_column!r} must be in the allowlist {sorted(allowed)!r}"
        )
    raw_col = params.get("sort") or ""
    column = raw_col if raw_col in allowed else default_column
    raw_dir = (params.get("dir") or "").lower()
    direction = raw_dir if raw_dir in ("asc", "desc") else default_direction
    expr = allowed[column]
    order_by_sql = f"{expr} {direction.upper()}"
    return SortState(column=column, direction=direction, order_by_sql=order_by_sql)


def parse_pagination(
    params: Mapping[str, str],
    *,
    total: int,
    default_per_page: int = DEFAULT_PER_PAGE,
) -> PageState:
    """Parse ``?page=<N>&per_page=<N>``, clamp to sane values, return
    a :class:`PageState` carrying offset / limit / nav data."""
    raw_per = params.get("per_page") or ""
    try:
        per_candidate = int(raw_per)
    except ValueError:
        per_candidate = default_per_page
    per_page = per_candidate if per_candidate in PER_PAGE_CHOICES else default_per_page

    if total < 0:
        total = 0
    last_page = max(1, (total + per_page - 1) // per_page) if total > 0 else 1

    raw_page = params.get("page") or ""
    try:
        page_candidate = int(raw_page)
    except ValueError:
        page_candidate = 1
    page = max(1, min(last_page, page_candidate))

    offset = (page - 1) * per_page
    return PageState(page=page, per_page=per_page, total=total, offset=offset, limit=per_page)


def build_query_string(
    base: Mapping[str, str | None],
    overrides: Mapping[str, str | None] | None = None,
) -> str:
    """Merge ``base`` and ``overrides``, drop empty / None values,
    return a URL-encoded query string suitable for header /
    pagination links. Stable key order so two callers producing the
    same logical URL emit byte-identical strings (helps testing).
    """
    import urllib.parse

    merged: dict[str, str] = {}
    for k, v in base.items():
        if v:
            merged[k] = str(v)
    if overrides:
        for k, v in overrides.items():
            if v is None or v == "":
                merged.pop(k, None)
            else:
                merged[k] = str(v)
    return urllib.parse.urlencode(sorted(merged.items()))
