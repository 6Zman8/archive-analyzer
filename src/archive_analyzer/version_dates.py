"""Title dates shared by initial candidate discovery and review recommendations."""
from calendar import monthrange
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
import re
import unicodedata


_DATE = re.compile(
    r"(?<!\d)(?:(?P<compact>(?:19|20)\d{6})|"
    r"(?P<year>(?:19|20)\d{2})[-._/년 ]+(?P<month>\d{1,2})"
    r"(?:[-._/월 ]+(?P<day>\d{1,2}))?일?)(?!\d)"
)
_RANGE = re.compile(r"\s*(?:~|〜|～|–|—|-|\.\.|to|부터|至)\s*", re.IGNORECASE)
_YEAR_RANGE = re.compile(r"(?<!\d)((?:19|20)\d{2})\s*(?:~|〜|～|–|—|-|to)\s*((?:19|20)\d{2})(?!\d)", re.IGNORECASE)
_ONGOING = re.compile(r"\b(?:ongoing|updated?|wip)\b|연재중|연재 중|更新中", re.IGNORECASE)


@dataclass(frozen=True)
class DateSpan:
    start: date
    end: date
    is_range: bool = False
    inferred: bool = False


@dataclass(frozen=True)
class TitleDates:
    key: str
    span: DateSpan | None
    versioned: bool


def parse_title_dates(path: Path) -> TitleDates:
    title = unicodedata.normalize("NFKC", path.stem).casefold()
    year_range = _YEAR_RANGE.search(title)
    if year_range and int(year_range[1]) <= int(year_range[2]):
        span = DateSpan(date(int(year_range[1]), 1, 1), date(int(year_range[2]), 12, 31), is_range=True)
        stripped = _ONGOING.sub(' ', title[:year_range.start()] + ' ' + title[year_range.end():])
        return TitleDates(' '.join(re.findall(r'[^\W_]+', stripped, re.UNICODE)), span, True)
    matches = tuple(_DATE.finditer(title))
    dates = []
    for match in matches:
        compact = match.group('compact')
        year, month, day = ((int(compact[:4]), int(compact[4:6]), int(compact[6:])) if compact
                            else (int(match['year']), int(match['month']), int(match['day']) if match['day'] else None))
        try:
            dates.append((date(year, month, day if day is not None else 1),
                          date(year, month, day if day is not None else monthrange(year, month)[1])))
        except ValueError:
            dates = []
            break
    span = None
    if len(dates) == 1:
        span = DateSpan(*dates[0])
    elif len(dates) == 2 and _RANGE.fullmatch(title[matches[0].end():matches[1].start()]):
        if dates[0][0] <= dates[1][1]:
            span = DateSpan(dates[0][0], dates[1][1], is_range=True)
    stripped = title
    if span is not None:
        stripped = title[:matches[0].start()] + ' ' + title[matches[-1].end():]
    ongoing = bool(_ONGOING.search(stripped))
    if span is not None or ongoing:
        stripped = _ONGOING.sub(' ', stripped)
    key = ' '.join(re.findall(r'[^\W_]+', stripped, re.UNICODE))
    return TitleDates(key, span, span is not None or ongoing)


def with_mtime(value: TitleDates, mtime_ns: int | None) -> DateSpan | None:
    if value.span is not None:
        return value.span
    if mtime_ns is None or mtime_ns < 0:
        return None
    try:
        day = datetime.fromtimestamp(mtime_ns / 1_000_000_000).date()
    except (ValueError, OverflowError, OSError):
        return None
    return DateSpan(day, day, inferred=True)
