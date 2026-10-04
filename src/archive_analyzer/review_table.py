from __future__ import annotations

import json
import math
import os
import tempfile
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


class ColumnKind(StrEnum):
    TEXT = "TEXT"
    NUMBER = "NUMBER"
    ENUM = "ENUM"


@dataclass(frozen=True, slots=True)
class ColumnSpec:
    key: str
    title: str
    width: int
    kind: ColumnKind


@dataclass(frozen=True, slots=True)
class TableFilter:
    contains: str | None = None
    minimum: float | None = None
    maximum: float | None = None
    allowed: frozenset[str] = frozenset()
    exclude_all: bool = False


@dataclass(frozen=True, slots=True)
class TableState:
    sort_key: str = ""
    descending: bool = False
    filters: Mapping[str, TableFilter] = field(default_factory=dict)


_KNOWN_COLUMN_KEYS = frozenset(
    {
        "number",
        "work",
        "relation",
        "confidence",
        "count",
        "status",
        "name",
        "directory",
        "path",
        "resolution",
        "size",
        "format",
        "pages",
        "mtime",
        "language",
        "color",
        "mosaic",
        "quality",
        "review",
        "file_state",
        "pair",
        "evidence",
        "recommendation",
    }
)


def _value(row: object, key: str) -> object:
    if isinstance(row, Mapping):
        if key in row:
            return row.get(key)
        aliases = {
            "number": "member_number",
            "name": "file_name",
            "directory": "path",
            "size": "file_size",
            "pages": "page_count",
            "mtime": "mtime_ns",
            "review": "review_status_text",
            "file_state": "file_operation_status_text",
            "work": "work_label",
            "relation": "relation_text",
            "status": "review_status_text",
            "evidence": "reason_text",
            "recommendation": "recommendation_text",
        }
        alias = aliases.get(key)
        if alias in row:
            value = row.get(alias)
            return value.parent if key == "directory" and isinstance(value, Path) else value
        return None
    value = getattr(row, key, None)
    if value is not None:
        return value
    aliases = {
        "number": "member_number",
        "name": "file_name",
        "directory": "directory",
        "size": "file_size",
        "pages": "page_count",
        "mtime": "mtime_ns",
        "review": "review_status_text",
        "file_state": "file_operation_status_text",
        "language": "language_text",
        "color": "color_text",
        "mosaic": "mosaic_text",
        "quality": "quality_text",
        "work": "work_label",
        "relation": "relation_text",
        "status": "review_status_text",
        "evidence": "reason_text",
        "recommendation": "recommendation_text",
    }
    alias = aliases.get(key)
    if alias is not None:
        value = getattr(row, alias, None)
        if value is not None:
            return value
    if key == "resolution":
        resolution = getattr(row, "representative_resolution", None)
        if resolution is not None:
            try:
                return int(resolution[0]) * int(resolution[1])
            except (TypeError, ValueError, IndexError):
                return None
    if key == "count":
        members = getattr(row, "members", None)
        if members is not None:
            return len(members)
    if key == "pages":
        matched_pages = getattr(row, "matched_pages", None)
        if matched_pages is not None:
            return matched_pages
    if key == "pair":
        left = getattr(row, "left_file_name", None)
        right = getattr(row, "right_file_name", None)
        if left is not None and right is not None:
            return f"{left} ↔ {right}"
    return None


def _display_value(value: object) -> object:
    return getattr(value, "value", value)


def _number(value: object) -> float | None:
    value = _display_value(value)
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _stable_number(
    row: object,
    fallback: int,
    value_getter: Callable[[object, str], object] | None = None,
) -> tuple[int, str, int]:
    get_value = value_getter or _value
    for key in ("number", "member_number", "group_number", "archive_id"):
        value = _number(get_value(row, key))
        if value is not None:
            return (0, f"{value:030.6f}", fallback)
    return (1, "", fallback)


def _matches(
    row: object,
    spec: ColumnSpec,
    condition: TableFilter,
    value_getter: Callable[[object, str], object] | None = None,
) -> bool:
    raw = _display_value((value_getter or _value)(row, spec.key))
    if condition.exclude_all:
        return False
    if condition.contains is not None:
        if raw is None or condition.contains.casefold() not in str(raw).casefold():
            return False
    if condition.allowed:
        if raw is None or _filter_text(raw, spec.key) not in condition.allowed:
            return False
    if condition.minimum is not None or condition.maximum is not None:
        parsed = _number(raw)
        if parsed is None:
            return False
        if condition.minimum is not None and parsed < condition.minimum:
            return False
        if condition.maximum is not None and parsed > condition.maximum:
            return False
    return True


def apply_table_state(
    rows: Sequence[object],
    specs: Sequence[ColumnSpec],
    state: TableState,
    *,
    value_getter: Callable[[object, str], object] | None = None,
    stable_number_getter: Callable[[object, int], object] | None = None,
) -> tuple[object, ...]:
    """Filter and stably sort rows without changing the source sequence."""

    spec_by_key = {spec.key: spec for spec in specs}
    filtered = [
        (index, row)
        for index, row in enumerate(rows)
        if all(
            key not in spec_by_key
            or _matches(row, spec_by_key[key], condition, value_getter)
            for key, condition in state.filters.items()
        )
    ]
    spec = spec_by_key.get(state.sort_key)
    if spec is None:
        return tuple(row for _index, row in filtered)

    # Put the stable secondary key in place first; Python's stable sort keeps
    # it when equal primary values are encountered, in either direction.
    if stable_number_getter is None:
        filtered.sort(
            key=lambda item: _stable_number(item[1], item[0], value_getter)
        )
    else:
        filtered.sort(
            key=lambda item: (
                0,
                _number(stable_number_getter(item[1], item[0]))
                if _number(stable_number_getter(item[1], item[0])) is not None
                else 0,
                item[0],
            )
        )
    if spec.kind is ColumnKind.NUMBER:
        present: list[tuple[int, object]] = []
        missing: list[tuple[int, object]] = []
        for item in filtered:
            (
                present
                if _number((value_getter or _value)(item[1], spec.key)) is not None
                else missing
            ).append(item)
        present.sort(
            key=lambda item: _number((value_getter or _value)(item[1], spec.key))
            or 0.0,
            reverse=state.descending,
        )
        if stable_number_getter is None:
            missing.sort(
                key=lambda item: _stable_number(item[1], item[0], value_getter)
            )
        else:
            missing.sort(
                key=lambda item: (
                    _number(stable_number_getter(item[1], item[0]))
                    if _number(stable_number_getter(item[1], item[0])) is not None
                    else 0,
                    item[0],
                )
            )
        return tuple(row for _index, row in (*present, *missing))

    filtered.sort(
        key=lambda item: str(
            _display_value((value_getter or _value)(item[1], spec.key)) or ""
        ).casefold(),
        reverse=state.descending,
    )
    return tuple(row for _index, row in filtered)


def enum_filter_values(
    rows: Sequence[object],
    specs: Sequence[ColumnSpec],
    value_getter: Callable[[object, ColumnSpec], object],
) -> Mapping[str, tuple[str, ...]]:
    """Return the distinct ENUM values currently displayed in each column."""

    return {
        spec.key: tuple(
            sorted(
                {
                    str(_display_value(value))
                    for row in rows
                    if (value := value_getter(row, spec)) is not None
                },
                key=str.casefold,
            )
        )
        for spec in specs
        if spec.kind is ColumnKind.ENUM
    }


class UiSettingsStore:
    """Persist table widths in a small per-user JSON file."""

    def __init__(self, path: Path | None = None) -> None:
        local = Path(os.environ.get("LOCALAPPDATA", tempfile.gettempdir()))
        self.path = Path(path) if path is not None else local / "ArchiveAnalyzer" / "ui-settings.json"

    def _load(self) -> dict[str, Any]:
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def widths(
        self, table_key: str, specs: Sequence[ColumnSpec] | None = None
    ) -> dict[str, int]:
        tables = self._load().get("tables", {})
        values = tables.get(table_key, {}) if isinstance(tables, dict) else {}
        if not isinstance(values, dict):
            return {}
        allowed = (
            {spec.key for spec in specs}
            if specs is not None
            else _KNOWN_COLUMN_KEYS
        )
        output: dict[str, int] = {}
        for key, value in values.items():
            if key not in allowed or isinstance(value, bool):
                continue
            try:
                width = int(value)
            except (TypeError, ValueError):
                continue
            if width > 0:
                output[str(key)] = width
        return output

    def save_widths(self, table_key: str, widths: Mapping[str, int]) -> None:
        document = self._load()
        tables = document.setdefault("tables", {})
        if not isinstance(tables, dict):
            tables = {}
            document["tables"] = tables
        existing = tables.get(table_key, {})
        if not isinstance(existing, dict):
            existing = {}
        for key, value in widths.items():
            if isinstance(value, bool):
                continue
            try:
                width = int(value)
            except (TypeError, ValueError):
                continue
            if width > 0:
                existing[str(key)] = width
        tables[table_key] = existing
        self._save(document)

    def preference(self, key: str, default=None):
        return self._load().get("preferences", {}).get(key, default)

    def save_preference(self, key: str, value) -> None:
        document = self._load()
        document.setdefault("preferences", {})[key] = value
        self._save(document)

    def _save(self, document) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = handle.name
                json.dump(document, handle, ensure_ascii=False, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            temporary = None
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass


class TreeLassoController:
    """Explorer-style rectangle selection for a ttk.Treeview."""

    def __init__(
        self,
        tree: object,
        *,
        borders: Sequence[object] = (),
        selector: Callable[..., tuple[str, ...]] | None = None,
        on_end: Callable[[], None] | None = None,
    ) -> None:
        self.tree = tree
        self.borders = tuple(borders)
        self.selector = selector
        self.on_end = on_end
        self.start: tuple[int, int] | None = None
        self.anchor = ""
        self.dragging = False
        self.initial_selection: tuple[str, ...] = ()

    def bind(self) -> None:
        bind = getattr(self.tree, "bind", None)
        if bind is None:
            return
        bind("<ButtonPress-1>", self.begin)
        bind("<B1-Motion>", self.drag)
        bind("<ButtonRelease-1>", self.end)

    def begin(self, event: object) -> str | None:
        x = int(getattr(event, "x", 0))
        y = int(getattr(event, "y", 0))
        identify_region = getattr(self.tree, "identify_region", lambda _x, _y: "nothing")
        identify_row = getattr(self.tree, "identify_row", lambda _y: "")
        if identify_region(x, y) in {"heading", "separator"}:
            self.start = None
            return None
        self.anchor = str(identify_row(y))
        self.dragging = False
        self.initial_selection = (
            tuple(getattr(self.tree, "selection", lambda: ())())
            if int(getattr(event, "state", 0)) & 4 else ()
        )
        self.start = (x, y)
        if self.anchor:
            return None
        selection_remove = getattr(self.tree, "selection_remove", None)
        if selection_remove is not None:
            selection_remove(getattr(self.tree, "selection", lambda: ())())
        return "break"

    def drag(self, event: object) -> str | None:
        if self.start is None:
            return None
        x = int(getattr(event, "x", 0))
        y = int(getattr(event, "y", 0))
        if not self.dragging and max(abs(x - self.start[0]), abs(y - self.start[1])) < 4:
            return "break"
        self.dragging = True
        width = int(getattr(self.tree, "winfo_width", lambda: 0)())
        height = int(getattr(self.tree, "winfo_height", lambda: 0)())
        if x <= 4:
            getattr(self.tree, "xview_scroll", lambda *_args: None)(-1, "units")
        elif width and x >= width - 4:
            getattr(self.tree, "xview_scroll", lambda *_args: None)(1, "units")
        if y <= 4:
            getattr(self.tree, "yview_scroll", lambda *_args: None)(-1, "units")
        elif height and y >= height - 4:
            getattr(self.tree, "yview_scroll", lambda *_args: None)(1, "units")
        rows: list[tuple[str, tuple[int, int, int, int]]] = []
        for item_id in getattr(self.tree, "get_children", lambda: ())():
            box = getattr(self.tree, "bbox", lambda _item: ()) (item_id)
            if box:
                rows.append((str(item_id), tuple(int(value) for value in box)))
        selector = self.selector
        if selector is None:
            try:
                from archive_analyzer.review_ui import rectangle_selection_ids
            except ImportError:
                selector = _rectangle_selection_ids
            else:
                selector = rectangle_selection_ids
        selected = selector(tuple(rows), self.start, (x, y))
        if self.anchor and rows:
            # Use the displayed order, including rows scrolled out of view.
            target = getattr(self.tree, "identify_row", lambda _y: "")(y)
            if not target:
                target = rows[0 if y < rows[0][1][1] else -1][0]
            order = tuple(getattr(self.tree, "get_children")())
            if self.anchor in order and target in order:
                first, last = sorted((order.index(self.anchor), order.index(target)))
                selected = order[first:last + 1]
        selected = tuple(dict.fromkeys((*self.initial_selection, *selected)))
        selection_remove = getattr(self.tree, "selection_remove", None)
        selection_set = getattr(self.tree, "selection_set", None)
        if selection_remove is not None:
            selection_remove(getattr(self.tree, "selection", lambda: ())())
        if selection_set is not None:
            selection_set(selected)
        self._draw(self.start, (x, y))
        return "break"

    def end(self, _event: object | None = None) -> str | None:
        active = self.start is not None and (self.dragging or not self.anchor)
        self.start = None
        self.dragging = False
        if not active:
            return None
        for border in self.borders:
            getattr(border, "place_forget", lambda: None)()
        if self.on_end is not None:
            self.on_end()
        return "break"

    def _draw(self, start: tuple[int, int], current: tuple[int, int]) -> None:
        if len(self.borders) != 4:
            return
        left, right = sorted((start[0], current[0]))
        top, bottom = sorted((start[1], current[1]))
        width = max(2, right - left)
        height = max(2, bottom - top)
        top_border, bottom_border, left_border, right_border = self.borders
        top_border.place(x=left, y=top, width=width, height=2)
        bottom_border.place(x=left, y=bottom, width=width, height=2)
        left_border.place(x=left, y=top, width=2, height=height)
        right_border.place(x=right, y=top, width=2, height=height)


def _rectangle_selection_ids(
    rows: tuple[tuple[str, tuple[int, int, int, int]], ...],
    start: tuple[int, int],
    current: tuple[int, int],
) -> tuple[str, ...]:
    left, right = sorted((start[0], current[0]))
    top, bottom = sorted((start[1], current[1]))
    return tuple(
        item_id
        for item_id, (x, y, width, height) in rows
        if x <= right and x + width >= left and y <= bottom and y + height >= top
    )


class TreeTableController:
    def __init__(
        self,
        tree: object,
        specs: Sequence[ColumnSpec],
        settings_key: str,
        store: UiSettingsStore | None = None,
        *,
        value_getter: Callable[[object, ColumnSpec], object] | None = None,
        row_id_getter: Callable[[object, int], str] | None = None,
        visible_rows_callback: Callable[[tuple[object, ...]], None] | None = None,
    ) -> None:
        self.tree = tree
        self.specs = tuple(specs)
        self.settings_key = settings_key
        self.store = store or UiSettingsStore()
        self.value_getter = value_getter or (lambda row, spec: _display_value(_value(row, spec.key)))
        self.row_id_getter = row_id_getter or self._default_row_id
        self.visible_rows_callback = visible_rows_callback
        self.state = TableState(sort_key=self.specs[0].key if self.specs else "")
        self.rows: tuple[object, ...] = ()
        self.visible_rows: tuple[object, ...] = ()
        self._rows_by_id: dict[str, object] = {}
        self._fixed_numbers: dict[str, int] = {}
        self._configure()

    def _configure(self) -> None:
        widths = self.store.widths(self.settings_key, self.specs)
        heading = getattr(self.tree, "heading", None)
        column = getattr(self.tree, "column", None)
        bind = getattr(self.tree, "bind", None)
        for spec in self.specs:
            if heading is not None:
                heading(spec.key, text=spec.title + " ▾", command=lambda key=spec.key: self.open_filters(self.tree, key))
            if column is not None:
                column(
                    spec.key,
                    width=widths.get(spec.key, spec.width),
                    minwidth=24,
                    stretch=False,
                    anchor="w",
                )
        if bind is not None:
            bind("<Control-a>", self._select_all_event)

    def _default_row_id(self, row: object, index: int) -> str:
        for key in ("row_id", "set_key", "group_key", "archive_id", "member_number"):
            value = _value(row, key)
            if value is not None:
                return str(value)
        return f"row-{index}"

    def set_rows(self, rows: Sequence[object]) -> None:
        self.rows = tuple(rows)
        for index, row in enumerate(self.rows, start=1):
            row_id = str(self.row_id_getter(row, index - 1))
            self._fixed_numbers.setdefault(row_id, index)
        self._render()

    def toggle_sort(self, column_key: str) -> None:
        descending = self.state.sort_key == column_key and not self.state.descending
        self.state = replace(self.state, sort_key=column_key, descending=descending)
        self._update_headings()
        self._render()

    def set_filters(self, filters: Mapping[str, TableFilter]) -> None:
        self.state = replace(self.state, filters=dict(filters))
        self._update_headings()
        self._render()

    def open_filters(self, parent: object, column_key: str | None = None) -> None:
        values: dict[str, tuple[str, ...]] = {}
        labels: dict[str, dict[str, str]] = {}
        for spec in self.specs:
            # A column's own filter must not hide values when reopening it.
            other_filters = {key: value for key, value in self.state.filters.items() if key != spec.key}
            rows = apply_table_state(self.rows, self.specs, TableState(filters=other_filters),
                value_getter=lambda row, key: self._sort_value(row, key))
            mapping = {}
            for row in rows:
                raw = self._sort_value(row, spec.key)
                key = _filter_text(raw, spec.key)
                label = self.value_getter(row, spec)
                mapping[key] = _filter_text(label, spec.key) if spec.key == "confidence" else str(label or "(빈 값)")
            # Retain selected values even if another column currently excludes them.
            for key in self.state.filters.get(spec.key, TableFilter()).allowed:
                mapping.setdefault(key, key)
            values[spec.key] = tuple(sorted(mapping, key=lambda key: (_number(key) or 0, key.casefold())
                                            if spec.kind is ColumnKind.NUMBER else key.casefold()))
            labels[spec.key] = mapping
        updated = ColumnFilterDialog(parent, self.specs, self.state.filters,
            enum_values=values, value_labels=labels, column_key=column_key,
            sort_callback=self.toggle_sort).show()
        if updated is not None:
            self.set_filters(updated)

    def _sort_value(self, row: object, key: str) -> object:
        spec = next((item for item in self.specs if item.key == key), None)
        if key == "number":
            displayed = self.value_getter(row, spec) if spec is not None else None
            return displayed if _number(displayed) is not None else self._fixed_numbers.get(str(self.row_id_getter(row, 0)))
        if spec is not None and spec.kind is not ColumnKind.NUMBER:
            return self.value_getter(row, spec)
        return _value(row, key)

    def selected_ids(self) -> tuple[str, ...]:
        return tuple(str(value) for value in getattr(self.tree, "selection", lambda: ())())

    def restore_columns(self, defaults: Sequence[str]) -> None:
        saved = self.store.preference(self.settings_key + "_visible_columns", list(defaults))
        valid = {spec.key for spec in self.specs}
        columns = tuple(key for key in saved if key in valid) if isinstance(saved, (list, tuple)) else ()
        self.tree.configure(displaycolumns=columns or tuple(defaults))

    def choose_columns(self, parent: object) -> None:
        import tkinter as tk
        from tkinter import ttk
        dialog = tk.Toplevel(parent)
        dialog.title("표시할 열 선택")
        dialog.transient(parent)
        body = ttk.Frame(dialog, padding=16)
        body.pack(fill="both", expand=True)
        current = tuple(self.tree["displaycolumns"])
        flags = {}
        for spec in self.specs:
            flag = tk.BooleanVar(value=spec.key in current or "#all" in current)
            flags[spec.key] = flag
            ttk.Checkbutton(body, text=spec.title, variable=flag).pack(anchor="w", pady=3)
        status = ttk.Label(body, text="열 너비와 선택은 다음 실행에도 유지됩니다.")
        status.pack(pady=8)
        def apply():
            chosen = [spec.key for spec in self.specs if flags[spec.key].get()]
            if not chosen:
                status.configure(text="한 개 이상의 열을 선택해 주세요.")
                return
            self.tree.configure(displaycolumns=chosen)
            self.store.save_preference(self.settings_key + "_visible_columns", chosen)
            dialog.destroy()
        ttk.Button(body, text="적용", command=apply, style="Primary.TButton").pack(side="right")
        ttk.Button(body, text="취소", command=dialog.destroy).pack(side="right", padx=6)
        from .dialogs import center_dialog
        center_dialog(dialog, parent)
        dialog.grab_set()

    def select_all_visible(self, _event: object | None = None) -> str:
        values = tuple(str(value) for value in getattr(self.tree, "get_children", lambda: ())())
        selection_set = getattr(self.tree, "selection_set", None)
        if selection_set is not None:
            selection_set(values)
        return "break"

    def _select_all_event(self, event: object) -> str:
        return self.select_all_visible(event)

    def save_widths(self) -> None:
        widths: dict[str, int] = {}
        column = getattr(self.tree, "column", None)
        if column is None:
            return
        for spec in self.specs:
            try:
                value = column(spec.key, "width")
                widths[spec.key] = int(value)
            except Exception:
                continue
        self.store.save_widths(self.settings_key, widths)

    def row(self, item_id: str) -> object | None:
        return self._rows_by_id.get(str(item_id))

    def _render(self) -> None:
        previous_selection = tuple(
            str(value)
            for value in getattr(self.tree, "selection", lambda: ())()
        )
        existing = tuple(getattr(self.tree, "get_children", lambda: ())())
        existing_set = set(existing)
        old_rows = self._rows_by_id
        update = getattr(self.tree, "item", None)
        move = getattr(self.tree, "move", None)
        incremental = update is not None and move is not None
        delete = getattr(self.tree, "delete", None)
        if not incremental and delete is not None:
            for item_id in existing:
                delete(item_id)
        visible = apply_table_state(
            self.rows,
            self.specs,
            self.state,
            value_getter=self._sort_value,
            stable_number_getter=lambda row, _index: self._fixed_numbers.get(
                str(self.row_id_getter(row, 0))
            ),
        )
        self.visible_rows = tuple(visible)
        insert = getattr(self.tree, "insert", None)
        self._rows_by_id = {}
        if insert is not None:
            for index, row in enumerate(self.visible_rows):
                item_id = str(self.row_id_getter(row, index))
                if item_id in self._rows_by_id:
                    item_id = f"{item_id}-{index}"
                self._rows_by_id[item_id] = row
                values = tuple(_filter_text(self.value_getter(row, spec), spec.key) if spec.key == "confidence"
                               else self.value_getter(row, spec) for spec in self.specs)
                if incremental and item_id in existing_set:
                    if old_rows.get(item_id) != row:
                        update(item_id, values=values)
                else:
                    insert("", "end", iid=item_id, values=values)
        if incremental:
            for item_id in existing_set - self._rows_by_id.keys():
                delete(item_id)
            if existing != tuple(self._rows_by_id):
                for index, item_id in enumerate(self._rows_by_id):
                    move(item_id, "", index)
        selection_set = getattr(self.tree, "selection_set", None)
        if selection_set is not None:
            retained = tuple(item_id for item_id in previous_selection if item_id in self._rows_by_id)
            if retained:
                selection_set(retained)
        if self.visible_rows_callback is not None:
            self.visible_rows_callback(self.visible_rows)

    def _update_headings(self) -> None:
        heading = getattr(self.tree, "heading", None)
        if heading is None:
            return
        for spec in self.specs:
            marker = ""
            if spec.key == self.state.sort_key:
                marker = " ▼" if self.state.descending else " ▲"
            heading(spec.key, text=f"{spec.title}{marker}{' ●' if spec.key in self.state.filters else ''} ▾")


class TclError(Exception):
    """Fallback type so headless tests need not import tkinter."""


def _filter_text(value: object, key: str) -> str:
    if key == "confidence" and _number(value) is not None:
        return f"{float(value):.3f}"
    return "" if value is None else str(value)


class ColumnFilterDialog:
    """One bounded, searchable value checklist per column, like a spreadsheet."""
    def __init__(self, parent, specs, current_filters, *, enum_values=None,
                 value_labels=None, column_key=None, sort_callback=None):
        self.parent = parent
        self.specs = tuple(specs)
        self.current_filters = dict(current_filters)
        self.enum_values = dict(enum_values or {})
        self.value_labels = dict(value_labels or {})
        self.column_key = column_key
        self.sort_callback = sort_callback

    def show(self):
        import tkinter as tk
        from tkinter import ttk, messagebox
        parent = self.parent.winfo_toplevel()
        dialog = tk.Toplevel(parent)
        from archive_analyzer.ui_theme import apply_review_theme, checkbox_images
        apply_review_theme(dialog)
        dialog.title("열 필터")
        dialog.transient(parent)
        dialog.geometry("440x550")
        dialog.minsize(360, 420)
        dialog.maxsize(min(700, dialog.winfo_screenwidth()), min(800, dialog.winfo_screenheight()))
        body = ttk.Frame(dialog, padding=10)
        body.pack(fill="both", expand=True)
        column = tk.StringVar(value=next((s.title for s in self.specs if s.key == self.column_key), self.specs[0].title))
        chooser = ttk.Combobox(body, state="readonly", textvariable=column, values=[s.title for s in self.specs])
        chooser.pack(fill="x")
        sort_bar = ttk.Frame(body)
        sort_bar.pack(fill="x", pady=6)
        def sort(descending):
            if self.sort_callback is not None:
                # The bound controller owns ordering and preserves selected rows.
                owner = self.sort_callback.__self__
                owner.state = replace(owner.state, sort_key=active.key, descending=descending)
                owner._update_headings()
                owner._render()
            dialog.destroy()
        ttk.Button(sort_bar, text="오름차순 정렬", command=lambda: sort(False)).pack(side="left")
        ttk.Button(sort_bar, text="내림차순 정렬", command=lambda: sort(True)).pack(side="left", padx=4)
        query = tk.StringVar()
        ttk.Label(body, text="값 검색").pack(anchor="w")
        search = ttk.Entry(body, textvariable=query)
        search.pack(fill="x")
        controls = ttk.Frame(body)
        controls.pack(fill="x", pady=5)
        listing_frame = ttk.Frame(body)
        listing_frame.pack(fill="both", expand=True)
        listing = ttk.Treeview(listing_frame, show="tree", selectmode="none", height=12)
        checks = checkbox_images(dialog)
        listing._check_images = checks
        listing.column("#0", width=360, stretch=True)
        listing.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(listing_frame, command=listing.yview)
        scroll.pack(side="right", fill="y")
        listing.configure(yscrollcommand=scroll.set)
        numeric = ttk.LabelFrame(body, text="숫자 범위 (선택 사항)", padding=5)
        minimum, maximum = tk.StringVar(), tk.StringVar()
        ttk.Label(numeric, text="이상").grid(row=0, column=0)
        ttk.Entry(numeric, textvariable=minimum, width=12).grid(row=0, column=1)
        ttk.Label(numeric, text="이하").grid(row=0, column=2)
        ttk.Entry(numeric, textvariable=maximum, width=12).grid(row=0, column=3)
        result = None
        active = self.specs[0]
        checked = set()
        shown = []
        def render(*_args):
            nonlocal shown
            labels = self.value_labels.get(active.key, {})
            shown = [v for v in self.enum_values.get(active.key, ())
                     if query.get().casefold() in labels.get(v, v).casefold()]
            listing.delete(*listing.get_children())
            for i, value in enumerate(shown):
                listing.insert("", "end", iid=str(i), image=checks[int(value in checked)],
                               text="  " + labels.get(value, value or "(빈 값)"))
        def select_values(enable):
            checked.update(shown) if enable else checked.difference_update(shown)
            render()
        ttk.Button(controls, text="검색 결과 전체선택", command=lambda: select_values(True)).pack(side="left")
        ttk.Button(controls, text="전체해제", command=lambda: select_values(False)).pack(side="left", padx=4)
        def toggle(event):
            row = listing.identify_row(event.y)
            if row:
                value = shown[int(row)]
                checked.discard(value) if value in checked else checked.add(value)
                render()
            return "break"
        listing.bind("<Button-1>", toggle)
        def change(*_args):
            nonlocal active, checked
            active = next(s for s in self.specs if s.title == column.get())
            condition = self.current_filters.get(active.key, TableFilter())
            checked = set() if condition.exclude_all else set(condition.allowed or self.enum_values.get(active.key, ()))
            minimum.set("" if condition.minimum is None else str(condition.minimum))
            maximum.set("" if condition.maximum is None else str(condition.maximum))
            query.set("")
            numeric.pack_forget()
            if active.kind is ColumnKind.NUMBER:
                numeric.pack(fill="x", pady=6, before=footer)
            render()
        def accept(clear=False):
            nonlocal result
            result = dict(self.current_filters)
            if clear:
                result.pop(active.key, None)
            else:
                low, high = _dialog_number(minimum.get()), _dialog_number(maximum.get())
                if ((minimum.get().strip() and low is None) or (maximum.get().strip() and high is None)
                        or (low is not None and high is not None and low > high)):
                    messagebox.showerror("숫자 필터", "올바른 숫자 범위를 입력해 주세요.", parent=dialog)
                    result = None
                    return
                selection = checked.intersection(shown) if query.get() else checked
                all_values = set(self.enum_values.get(active.key, ()))
                condition = TableFilter(minimum=low, maximum=high,
                    allowed=frozenset(selection) if selection != all_values else frozenset(),
                    exclude_all=not bool(selection))
                if condition == TableFilter():
                    result.pop(active.key, None)
                else:
                    result[active.key] = condition
            dialog.destroy()
        footer = ttk.Frame(body)
        footer.pack(fill="x", pady=(8, 0))
        ttk.Button(footer, text="적용", command=accept).pack(side="left")
        ttk.Button(footer, text="이 열 필터 해제", command=lambda: accept(True)).pack(side="left", padx=4)
        ttk.Button(footer, text="취소", command=dialog.destroy).pack(side="right")
        chooser.bind("<<ComboboxSelected>>", change)
        query.trace_add("write", render)
        change()
        search.focus_set()
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.grab_set()
        from .dialogs import center_dialog
        center_dialog(dialog, parent)
        dialog.wait_window()
        return result


def _dialog_number(value: str) -> float | None:
    try:
        parsed = float(value.strip())
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


__all__ = [
    "ColumnFilterDialog",
    "ColumnKind",
    "ColumnSpec",
    "TableFilter",
    "TableState",
    "TreeLassoController",
    "TreeTableController",
    "UiSettingsStore",
    "apply_table_state",
    "enum_filter_values",
]
