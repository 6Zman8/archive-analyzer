from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from archive_analyzer.review_table import (
    ColumnKind,
    ColumnSpec,
    TableFilter,
    TableState,
    TreeLassoController,
    TreeTableController,
    UiSettingsStore,
    apply_table_state,
    enum_filter_values,
)
from archive_analyzer.review_ui import MEMBER_TABLE_SPECS


@dataclass(frozen=True)
class Row:
    number: int
    name: str
    confidence: float | None
    pages: int | None
    review: str


SPECS = (
    ColumnSpec("number", "번호", 55, ColumnKind.NUMBER),
    ColumnSpec("name", "파일명", 180, ColumnKind.TEXT),
    ColumnSpec("confidence", "신뢰도", 80, ColumnKind.NUMBER),
    ColumnSpec("pages", "페이지", 70, ColumnKind.NUMBER),
    ColumnSpec("review", "검토", 100, ColumnKind.ENUM),
)

ROWS = (
    Row(1, "번역판 A", 0.9, 30, "보존"),
    Row(2, "원본 B", 0.9, 20, "보류"),
    Row(3, "번역판 C", None, 25, "제거 후보"),
    Row(4, "별도 D", 0.5, None, "보존"),
)


def test_header_sort_is_stable_by_fixed_number() -> None:
    result = apply_table_state(
        (ROWS[1], ROWS[0]), SPECS, TableState(sort_key="confidence", descending=True)
    )
    assert [item.number for item in result] == [1, 2]


def test_missing_numeric_values_remain_after_real_values_in_both_directions() -> None:
    ascending = apply_table_state(ROWS, SPECS, TableState(sort_key="confidence"))
    descending = apply_table_state(
        ROWS, SPECS, TableState(sort_key="confidence", descending=True)
    )
    assert ascending[-1].number == 3
    assert descending[-1].number == 3


def test_filters_support_contains_ranges_and_enum_sets() -> None:
    state = TableState(
        filters={
            "name": TableFilter(contains="번역"),
            "pages": TableFilter(minimum=20, maximum=30),
            "review": TableFilter(allowed=frozenset({"보존", "보류"})),
        }
    )
    assert [row.number for row in apply_table_state(ROWS, SPECS, state)] == [1]


def test_ui_settings_store_recovers_invalid_json_and_writes_atomically(tmp_path: Path) -> None:
    path = tmp_path / "ui-settings.json"
    path.write_text("not-json", encoding="utf-8")
    store = UiSettingsStore(path)
    assert store.widths("members") == {}
    store.save_widths("members", {"name": 240, "invalid": -5})
    assert json.loads(path.read_text(encoding="utf-8"))["tables"]["members"]["name"] == 240
    assert store.widths("members") == {"name": 240}


def test_ui_settings_store_ignores_unknown_and_invalid_saved_widths(tmp_path: Path) -> None:
    path = tmp_path / "ui-settings.json"
    path.write_text(
        json.dumps({"tables": {"members": {"name": 220, "unknown": 80, "pages": 0}}}),
        encoding="utf-8",
    )
    assert UiSettingsStore(path).widths("members") == {"name": 220}


class FakeTree:
    def __init__(self, region: str = "nothing") -> None:
        self.region = region
        self.headings: dict[str, dict[str, object]] = {}
        self.columns: dict[str, dict[str, object]] = {}
        self.column_options = self.columns
        self.rows: dict[str, tuple[object, ...]] = {}
        self.order: list[str] = []
        self.selected: tuple[str, ...] = ()
        self.bindings: dict[str, object] = {}

    def heading(self, key: str, **kwargs):  # type: ignore[no-untyped-def]
        self.headings.setdefault(key, {}).update(kwargs)
        return self.headings[key]

    def column(self, key: str, option=None, **kwargs):  # type: ignore[no-untyped-def]
        values = self.columns.setdefault(key, {"width": 100})
        if kwargs:
            values.update(kwargs)
        return values.get(option) if option is not None else values

    def bind(self, sequence: str, callback, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        self.bindings[sequence] = callback

    def get_children(self):  # type: ignore[no-untyped-def]
        return tuple(self.order)

    def delete(self, item_id: str) -> None:
        self.order.remove(item_id)
        self.rows.pop(item_id, None)

    def insert(self, _parent, _index, iid: str, values):  # type: ignore[no-untyped-def]
        self.order.append(iid)
        self.rows[iid] = tuple(values)

    def selection(self):  # type: ignore[no-untyped-def]
        return self.selected

    def selection_set(self, values) -> None:  # type: ignore[no-untyped-def]
        self.selected = (values,) if isinstance(values, str) else tuple(values)

    def identify_region(self, _x: int, _y: int) -> str:
        return self.region

    def identify_row(self, _y: int) -> str:
        return ""


def test_controller_toggles_heading_marker_and_ctrl_a_only_visible_rows(tmp_path: Path) -> None:
    tree = FakeTree()
    controller = TreeTableController(
        tree, SPECS, "members", UiSettingsStore(tmp_path / "settings.json")
    )
    controller.set_rows(ROWS)
    controller.set_filters({"review": TableFilter(allowed=frozenset({"보존"}))})
    assert tree.order == ["row-0", "row-1"]
    controller.toggle_sort("confidence")
    assert "▲" in str(tree.headings["confidence"]["text"])
    controller.toggle_sort("confidence")
    assert "▼" in str(tree.headings["confidence"]["text"])
    assert tree.bindings["<Control-a>"](None) == "break"
    assert tree.selected == ("row-0", "row-1")


def test_controller_retains_selected_rows_when_sorting(tmp_path: Path) -> None:
    tree = FakeTree()
    controller = TreeTableController(
        tree, SPECS, "members", UiSettingsStore(tmp_path / "settings.json")
    )
    controller.set_rows(ROWS)
    tree.selection_set("row-2")
    controller.toggle_sort("pages")
    assert tree.selected == ("row-2",)


def test_lasso_controller_autoscrolls_only_beyond_visible_edge() -> None:
    class LassoTree(FakeTree):
        def identify_region(self, _x: int, _y: int) -> str:
            return "nothing"

        def identify_row(self, _y: int) -> str:
            return ""

        def selection_remove(self, _values) -> None:  # type: ignore[no-untyped-def]
            self.selected = ()

        def winfo_height(self) -> int:
            return 100

        def bbox(self, item_id: str):  # type: ignore[no-untyped-def]
            return (0, 20 if item_id == "1" else 40, 500, 20)

        def yview_scroll(self, amount: int, _unit: str) -> None:
            self.scrolled = amount

    tree = LassoTree()
    tree.order = ["1", "2"]
    tree.scrolled = 0
    controller = TreeLassoController(tree)
    assert controller.begin(type("Event", (), {"x": 10, "y": 45})()) == "break"
    assert controller.drag(type("Event", (), {"x": 10, "y": 120})()) == "break"
    assert tree.scrolled == 1
    assert tree.selected == ("2",)


def test_inactive_lasso_does_not_consume_separator_events() -> None:
    tree = FakeTree(region="separator")
    ended: list[bool] = []
    lasso = TreeLassoController(tree, on_end=lambda: ended.append(True))
    event = type("Event", (), {"x": 20, "y": 4})()

    assert lasso.begin(event) is None
    assert lasso.drag(event) is None
    assert lasso.end(event) is None
    assert ended == []


def test_columns_have_fixed_logical_width_for_horizontal_scrolling(tmp_path: Path) -> None:
    tree = FakeTree()
    TreeTableController(
        tree, MEMBER_TABLE_SPECS, "members", UiSettingsStore(tmp_path / "ui.json")
    )

    assert all(options["stretch"] is False for options in tree.column_options.values())
    assert all(options["minwidth"] >= 24 for options in tree.column_options.values())


def test_visible_rows_callback_receives_filtered_sorted_rows(tmp_path: Path) -> None:
    matching = {"group_key": "one", "number": 1, "status": "보존 1 / 제거 후보 1"}
    other = {"group_key": "two", "number": 2, "status": "보류"}
    specs = (
        ColumnSpec("number", "번호", 55, ColumnKind.NUMBER),
        ColumnSpec("status", "검토 상태", 125, ColumnKind.ENUM),
    )
    seen: list[tuple[object, ...]] = []
    controller = TreeTableController(
        FakeTree(),
        specs,
        "groups",
        UiSettingsStore(tmp_path / "ui.json"),
        visible_rows_callback=lambda rows: seen.append(rows),
    )

    controller.set_rows((other, matching))
    controller.set_filters(
        {"status": TableFilter(allowed=frozenset({"보존 1 / 제거 후보 1"}))}
    )

    assert seen[-1] == (matching,)
    assert controller.visible_rows == (matching,)


def test_enum_filter_values_uses_displayed_values() -> None:
    rows = (
        {"recommendation": "보존 추천", "mosaic": "있음", "quality": "고화질"},
        {"recommendation": "보존 추천", "mosaic": "없음", "quality": "저화질"},
    )
    specs = (
        ColumnSpec("recommendation", "추천", 100, ColumnKind.ENUM),
        ColumnSpec("mosaic", "모자이크", 100, ColumnKind.ENUM),
        ColumnSpec("quality", "화질", 100, ColumnKind.ENUM),
    )

    assert enum_filter_values(rows, specs, lambda row, spec: row[spec.key]) == {
        "recommendation": ("보존 추천",),
        "mosaic": ("없음", "있음"),
        "quality": ("고화질", "저화질"),
    }
