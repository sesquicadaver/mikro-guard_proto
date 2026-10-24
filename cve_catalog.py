#!/usr/bin/env python3
"""Local RouterOS CVE catalog.

The file ``cve_catalog.json`` is stored next to this module. Online runs refresh
it from the NVD CVE 2.0 API when it is older than the configured age. The
embedded floor for the September 2026 advisories is unioned back on every load,
so a fetched feed can add CVEs and widen ranges but cannot mark those advisories
as fixed earlier than the vendor bulletin of 2026-10-06.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_HOST = "services.nvd.nist.gov"
NVD_QUERY = "cpe:2.3:o:mikrotik:routeros"
ADVISORY = "https://mikrotik.com/supportsec/september-2026-vulnerability/"
CATALOG_NAME = "cve_catalog.json"
SCHEMA = 1
MAX_CATALOG_BYTES = 2 * 1024 * 1024
MAX_NVD_BYTES = 8 * 1024 * 1024
MAX_CVES = 500
MAX_RANGES = 40
MAX_EXACT = 80
PAGE_SIZE = 200
MAX_PAGES = 10
SEED_UPDATED = "2026-10-06T00:00:00+00:00"
_VERSION = re.compile(r"(?:0|[1-9]\d{0,5})(?:\.(?:0|[1-9]\d{0,5})){0,2}")
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}")
_RANGE_KEYS = {"min_inclusive", "min_exclusive", "max_inclusive", "max_exclusive"}


class CatalogError(Exception):
    """The CVE catalog could not be read, fetched, or written."""


# Vendor floor after the 2026-10-06 bulletin. 7.23.4 and 7.24.2 do not fix
# CVE-2026-67278; the complete fix starts at 7.23.6 and 7.24.3.
_SEED_RANGES: dict[str, tuple[dict[str, str], ...]] = {
    "CVE-2026-67276": (
        {"min_inclusive": "7.9.0", "max_exclusive": "7.23.4"},
        {"min_inclusive": "7.24.0", "max_exclusive": "7.24.2"},
    ),
    "CVE-2026-67277": (
        {"min_inclusive": "6.0.0", "max_exclusive": "6.49.21"},
        {"min_inclusive": "7.0.0", "max_exclusive": "7.23.4"},
        {"min_inclusive": "7.24.0", "max_exclusive": "7.24.2"},
    ),
    "CVE-2026-67278": (
        {"min_inclusive": "7.0.0", "max_exclusive": "7.23.6"},
        {"min_inclusive": "7.24.0", "max_exclusive": "7.24.3"},
    ),
    "CVE-2026-67279": (
        {"min_inclusive": "6.0.0", "max_exclusive": "6.49.21"},
        {"min_inclusive": "7.0.0", "max_exclusive": "7.23.4"},
        {"min_inclusive": "7.24.0", "max_exclusive": "7.24.2"},
    ),
    "CVE-2026-67281": (
        {"min_inclusive": "7.20.0", "max_exclusive": "7.23.4"},
        {"min_inclusive": "7.24.0", "max_exclusive": "7.24.2"},
    ),
    "CVE-2026-86060": (
        {"min_inclusive": "6.0.0", "max_exclusive": "6.49.21"},
        {"min_inclusive": "7.0.0", "max_exclusive": "7.23.4"},
        {"min_inclusive": "7.24.0", "max_exclusive": "7.24.2"},
    ),
}
_SEED_TITLES = {
    "CVE-2026-67276": "RouterOS 7 SSH: неповна перевірка RSA-ключа",
    "CVE-2026-67277": "Сервіс bandwidth-test до автентифікації",
    "CVE-2026-67278": "Прийняття підроблених RSA-сертифікатів і SSH host key",
    "CVE-2026-67279": "SSH-канал без автентифікації",
    "CVE-2026-67281": "Читання файлів через WebFig без автентифікації",
    "CVE-2026-86060": "Підвищення прав через ім'я користувача SSH",
}
# NVD has no CPE for the 7.25.0 beta train named in the vendor bulletin.
# Rules apply only when the numeric ranges do not already say AFFECTED.
_ORIGINAL_BETA = (
    {"version": (7, 25, 0), "stage": "beta", "max_build": 3, "status": "AFFECTED"},
    {"version": (7, 25, 0), "stage": "beta", "min_build": 3, "status": "UNAFFECTED"},
)
PRERELEASE_RULES: dict[str, tuple[dict[str, Any], ...]] = {
    "CVE-2026-67276": _ORIGINAL_BETA,
    "CVE-2026-67277": _ORIGINAL_BETA,
    "CVE-2026-67279": _ORIGINAL_BETA,
    "CVE-2026-67281": _ORIGINAL_BETA,
    "CVE-2026-86060": _ORIGINAL_BETA,
    "CVE-2026-67278": (
        {"version": (7, 25, 0), "stage": "beta", "status": "UNKNOWN"},
        {"version": (7, 25, 0), "stage": "rc", "status": "UNKNOWN"},
    ),
}


def default_catalog_path() -> Path:
    """Path of the catalog stored beside this module and the audit script."""
    return Path(__file__).resolve().parent / CATALOG_NAME


def embedded_catalog() -> dict[str, Any]:
    """Floor catalog used when the file is missing or rejected."""
    cves = [
        {
            "id": cve_id,
            "title": _SEED_TITLES[cve_id],
            "published": "2026-09-05",
            "ranges": [dict(item) for item in ranges],
            "exact": [],
            "unbounded": False,
            "unparsed": False,
        }
        for cve_id, ranges in _SEED_RANGES.items()
    ]
    return {
        "schema": SCHEMA,
        "updated_at": SEED_UPDATED,
        "source": {"name": "embedded", "url": ADVISORY, "reported": len(cves), "kept": len(cves)},
        "cves": cves,
    }


def parse_version(text: str) -> tuple[int, int, int] | None:
    """Parse a dotted NVD/CPE version of one to three components."""
    if not isinstance(text, str) or not _VERSION.fullmatch(text):
        return None
    parts = [int(item) for item in text.split(".")]
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def format_version(value: tuple[int, int, int]) -> str:
    """Canonical three-component form so equivalent strings deduplicate."""
    return ".".join(str(part) for part in value)


def assess_catalog(parsed: tuple[Any, ...] | None, catalog: dict[str, Any]) -> list[dict[str, Any]]:
    """Classify one RouterOS version against every catalog entry.

    ``parsed`` is ``(major, minor, patch, stage, build)`` from the audit
    parser. ``stage`` is ``""``, ``"beta"``, or ``"rc"``. A prerelease sorts
    before the stable release with the same numbers, so the beta of a fix
    version stays inside an exclusive upper bound.
    """
    if not isinstance(catalog, dict) or not isinstance(catalog.get("cves"), list):
        raise CatalogError("Некоректний каталог CVE")
    results = []
    for cve in catalog["cves"]:
        if not isinstance(cve, dict) or not isinstance(cve.get("id"), str):
            raise CatalogError("Некоректний запис CVE")
        status = _status(parsed, cve)
        results.append({
            "id": cve["id"],
            "status": status,
            "decisive": _decisive(status, cve),
            "title": cve.get("title") if isinstance(cve.get("title"), str) else cve["id"],
            "ranges": cve.get("ranges") if isinstance(cve.get("ranges"), list) else [],
            "exact": cve.get("exact") if isinstance(cve.get("exact"), list) else [],
        })
    return results


def headline(results: list[dict[str, Any]], version_known: bool) -> str:
    """Collapse per-CVE results to AFFECTED, PATCHED, or UNKNOWN."""
    if not version_known:
        return "UNKNOWN"
    if any(item["status"] == "AFFECTED" for item in results):
        return "AFFECTED"
    if any(item["status"] == "UNKNOWN" and item["decisive"] for item in results):
        return "UNKNOWN"
    if not results:
        return "UNKNOWN"
    return "PATCHED"


def load_catalog(path: Path | None = None) -> tuple[dict[str, Any], str | None]:
    """Load the on-disk catalog and union the embedded floor. Never fetches."""
    path = default_catalog_path() if path is None else path
    if not path.exists():
        return embedded_catalog(), None
    try:
        disk = read_catalog(path)
    except CatalogError as exc:
        return embedded_catalog(), str(exc)
    return merge_floor(disk), None


def catalog_is_stale(path: Path, max_age: int, today: date | None = None) -> bool:
    """True when an online audit should refresh the file before the assessment."""
    if max_age < 0:
        raise CatalogError("Некоректний вік каталогу")
    if max_age == 0 or not path.is_file() or path.is_symlink():
        return True
    catalog, error = load_catalog(path)
    if error or catalog.get("source", {}).get("name") == "embedded":
        return True
    stamp = _stamp(catalog.get("updated_at"))
    if stamp is None:
        return True
    today = today or datetime.now(timezone.utc).date()
    age = (today - stamp.date()).days
    return age < 0 or age > max_age


def update_catalog(
    path: Path | None = None,
    *,
    fetcher: Callable[[int], dict[str, Any]] | None = None,
    sleeper: Callable[[float], None] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Fetch NVD, union the floor, and atomically replace the catalog file."""
    path = default_catalog_path() if path is None else path
    fetcher = fetcher or fetch_nvd_page
    sleeper = sleeper or time.sleep
    now = now or datetime.now(timezone.utc)
    pages: list[dict[str, Any]] = []
    start = 0
    total: int | None = None
    while True:
        if pages:
            sleeper(6)
        page = fetcher(start)
        if not isinstance(page, dict):
            raise CatalogError("Некоректна відповідь NVD")
        if total is None:
            reported = page.get("totalResults")
            if type(reported) is not int or not 0 < reported <= PAGE_SIZE * MAX_PAGES:
                raise CatalogError("Некоректна кількість CVE у відповіді NVD")
            total = reported
        if page.get("startIndex", start) != start:
            raise CatalogError("NVD повернув неочікувану сторінку")
        rows = page.get("vulnerabilities")
        if not isinstance(rows, list):
            raise CatalogError("Некоректна сторінка NVD")
        pages.append(page)
        if not rows:
            raise CatalogError("NVD обірвав сторінки каталогу")
        start += len(rows)
        if start >= total:
            break
        if len(pages) >= MAX_PAGES:
            raise CatalogError("Забагато сторінок NVD")
    merged = _validate(merge_floor(build_catalog(pages, now, total)))
    write_catalog(path, merged)
    return merged


def fetch_nvd_page(start_index: int) -> dict[str, Any]:
    """GET one NVD page. Redirects are limited to the NVD host over HTTPS."""
    if type(start_index) is not int or start_index < 0:
        raise CatalogError("Некоректний індекс сторінки NVD")
    params = urllib.parse.urlencode({
        "virtualMatchString": NVD_QUERY,
        "resultsPerPage": str(PAGE_SIZE),
        "startIndex": str(start_index),
    })
    request = urllib.request.Request(NVD_URL + "?" + params, headers=_headers(), method="GET")
    opener = urllib.request.build_opener(_PinnedRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            if response.status != 200:
                raise CatalogError("NVD відхилив запит каталогу")
            raw = _read_limited(response, MAX_NVD_BYTES)
    except CatalogError:
        raise
    except urllib.error.HTTPError as exc:
        raise CatalogError("NVD HTTP " + str(exc.code)) from exc
    except urllib.error.URLError as exc:
        raise CatalogError("Немає доступу до NVD") from exc
    try:
        value = _strict_json(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CatalogError("Відповідь NVD не є JSON") from exc
    if not isinstance(value, dict):
        raise CatalogError("Відповідь NVD не є об'єктом")
    return value


def build_catalog(pages: list[dict[str, Any]], now: datetime, reported: int) -> dict[str, Any]:
    """Normalize NVD pages into the local schema. Hardware CPEs are ignored."""
    by_id: dict[str, dict[str, Any]] = {}
    for page in pages:
        for item in page.get("vulnerabilities") or []:
            if isinstance(item, dict):
                _absorb(by_id, item.get("cve"))
    if not by_id:
        raise CatalogError("NVD не повернув жодного CVE RouterOS")
    if len(by_id) > MAX_CVES:
        raise CatalogError("Забагато CVE у відповіді NVD")
    return {
        "schema": SCHEMA,
        "updated_at": now.astimezone(timezone.utc).isoformat(),
        "source": {
            "name": "nvd",
            "url": NVD_URL,
            "query": "virtualMatchString=" + NVD_QUERY,
            "reported": reported,
            "kept": len(by_id),
        },
        "cves": [by_id[key] for key in sorted(by_id)],
    }


def merge_floor(disk: dict[str, Any] | None) -> dict[str, Any]:
    """Union embedded ranges into ``disk``. Seed ids cannot be deleted or narrowed."""
    if disk is None:
        return embedded_catalog()
    by_id = {cve["id"]: _copy_cve(cve) for cve in disk["cves"]}
    for cve_id, ranges in _SEED_RANGES.items():
        current = by_id.get(cve_id)
        floor_ranges = [dict(item) for item in ranges]
        if current is None:
            by_id[cve_id] = {
                "id": cve_id,
                "title": _SEED_TITLES[cve_id],
                "published": "2026-09-05",
                "ranges": floor_ranges,
                "exact": [],
                "unbounded": False,
                "unparsed": False,
            }
            continue
        current["ranges"] = _dedup(list(current["ranges"]) + floor_ranges)
        current["unbounded"] = False
        current["title"] = _SEED_TITLES[cve_id]
    return {
        "schema": SCHEMA,
        "updated_at": disk.get("updated_at") or SEED_UPDATED,
        "source": disk.get("source") or embedded_catalog()["source"],
        "cves": [by_id[key] for key in sorted(by_id)],
    }


def read_catalog(path: Path) -> dict[str, Any]:
    """Validate a catalog file. Symlinks and oversized files are rejected."""
    if path.is_symlink() or not path.is_file():
        raise CatalogError("Файл каталогу CVE недоступний")
    with path.open("rb") as stream:
        raw = stream.read(MAX_CATALOG_BYTES + 1)
    if len(raw) > MAX_CATALOG_BYTES:
        raise CatalogError("Завеликий каталог CVE")
    try:
        value = _strict_json(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CatalogError("Каталог CVE не є JSON") from exc
    return _validate(value)


def write_catalog(path: Path, catalog: dict[str, Any]) -> None:
    """Atomically replace the catalog. Existing symlinks are not followed."""
    catalog = _validate(catalog)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise CatalogError("Відмова запису каталогу CVE")
    payload = (json.dumps(catalog, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    if len(payload) > MAX_CATALOG_BYTES:
        raise CatalogError("Каталог CVE не вміщується у ліміт")
    temporary = path.with_name(path.name + ".tmp")
    flags = os.O_CREAT | os.O_TRUNC | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except Exception:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _status(parsed: tuple[Any, ...] | None, cve: dict[str, Any]) -> str:
    if not _parsed_ok(parsed):
        return "UNKNOWN"
    assert parsed is not None
    if _matched(parsed, cve):
        return "AFFECTED"
    if cve.get("unbounded") or cve.get("unparsed"):
        return "UNKNOWN"
    if _exact_prerelease(parsed, cve):
        return "UNKNOWN"
    ruled = _prerelease(parsed, cve["id"])
    return ruled or "UNAFFECTED"


def _decisive(status: str, cve: dict[str, Any]) -> bool:
    if status in {"AFFECTED", "UNAFFECTED"}:
        return True
    return status == "UNKNOWN" and not cve.get("unbounded") and not cve.get("unparsed")


def _matched(parsed: tuple[Any, ...], cve: dict[str, Any]) -> bool:
    key = _installed_key(parsed)
    for exact in cve.get("exact") or []:
        value = parse_version(exact)
        if value is not None and key[:3] == value and key[3] == 2:
            return True
    for rng in cve.get("ranges") or []:
        if isinstance(rng, dict) and _in_range(key, rng):
            return True
    return False


def _exact_prerelease(parsed: tuple[Any, ...], cve: dict[str, Any]) -> bool:
    """A beta of a release listed as an exact CPE match is not that release."""
    if parsed[3] not in {"beta", "rc"}:
        return False
    return any(parse_version(exact) == parsed[:3] for exact in cve.get("exact") or [])


def _prerelease(parsed: tuple[Any, ...], cve_id: str) -> str | None:
    _major, _minor, _patch, stage, build = parsed
    if stage not in {"beta", "rc"}:
        return None
    for rule in PRERELEASE_RULES.get(cve_id, ()):
        if parsed[:3] != rule["version"] or stage != rule["stage"]:
            continue
        if "max_build" in rule and not build < rule["max_build"]:
            continue
        if "min_build" in rule and not build >= rule["min_build"]:
            continue
        return str(rule["status"])
    return None


def _installed_key(parsed: tuple[Any, ...]) -> tuple[int, int, int, int, int]:
    major, minor, patch, stage, build = parsed
    rank = {"": 2, "rc": 1, "beta": 0}[stage]
    return (int(major), int(minor), int(patch), rank, 0 if stage == "" else int(build))


def _parsed_ok(parsed: tuple[Any, ...] | None) -> bool:
    if not isinstance(parsed, tuple) or len(parsed) != 5:
        return False
    major, minor, patch, stage, build = parsed
    return (
        type(major) is int and type(minor) is int and type(patch) is int and type(build) is int
        and stage in {"", "beta", "rc"} and build >= 0
    )


def _in_range(key: tuple[int, int, int, int, int], rng: dict[str, str]) -> bool:
    if "min_inclusive" in rng:
        low = (*_must_version(rng["min_inclusive"]), 0, 0)
    elif "min_exclusive" in rng:
        low = (*_must_version(rng["min_exclusive"]), 2, 1)
    else:
        low = (0, 0, 0, 0, 0)
    if key < low:
        return False
    if "max_exclusive" in rng:
        return key < (*_must_version(rng["max_exclusive"]), 2, 0)
    if "max_inclusive" in rng:
        return key < (*_must_version(rng["max_inclusive"]), 2, 1)
    return True


def _must_version(text: str) -> tuple[int, int, int]:
    value = parse_version(text)
    if value is None:
        raise CatalogError("Некоректна версія в каталозі CVE")
    return value


def _absorb(by_id: dict[str, dict[str, Any]], cve: Any) -> None:
    if not isinstance(cve, dict) or cve.get("vulnStatus") == "Rejected":
        return
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not _CVE_ID.fullmatch(cve_id):
        return
    ranges: list[dict[str, str]] = []
    exact: list[str] = []
    unbounded = False
    unparsed = False
    found = False
    for block in cve.get("configurations") or []:
        if not isinstance(block, dict):
            continue
        for node in block.get("nodes") or []:
            for match in _routeros_matches(node):
                found = True
                kind, value = _compile_match(match)
                if kind == "range":
                    ranges.append(value)
                elif kind == "exact":
                    exact.append(value)
                elif kind == "both":
                    ranges.append(value[0])
                    exact.append(value[1])
                elif kind == "unbounded":
                    unbounded = True
                else:
                    unparsed = True
    if not found:
        return
    title = _title(cve)
    published = _published(cve)
    current = by_id.get(cve_id)
    if current is None:
        by_id[cve_id] = {
            "id": cve_id,
            "title": title,
            "published": published,
            "ranges": _dedup(ranges),
            "exact": sorted(set(exact)),
            "unbounded": unbounded and not ranges and not exact,
            "unparsed": unparsed,
        }
        return
    current["ranges"] = _dedup(list(current["ranges"]) + ranges)
    current["exact"] = sorted(set(current["exact"]) | set(exact))
    current["unparsed"] = bool(current["unparsed"] or unparsed)
    current["unbounded"] = bool(unbounded and not current["ranges"] and not current["exact"])


def _routeros_matches(node: Any) -> list[dict[str, Any]]:
    if not isinstance(node, dict) or node.get("negate") is True:
        return []
    found: list[dict[str, Any]] = []
    for child in node.get("children") or []:
        found.extend(_routeros_matches(child))
    for match in node.get("cpeMatch") or []:
        if isinstance(match, dict) and match.get("vulnerable") is True and _is_routeros(match.get("criteria")):
            found.append(match)
    return found


def _is_routeros(criteria: Any) -> bool:
    if not isinstance(criteria, str):
        return False
    parts = _split_cpe(criteria)
    return len(parts) > 5 and parts[2] == "o" and parts[3].lower() == "mikrotik" and parts[4].lower() == "routeros"


def _compile_match(match: dict[str, Any]) -> tuple[str, Any]:
    parts = _split_cpe(str(match.get("criteria")))
    version = parts[5] if len(parts) > 5 else "*"
    exact = None
    if version not in {"*", "-", ""}:
        parsed = parse_version(version)
        if parsed is None:
            return "unparsed", None
        exact = format_version(parsed)
    bounds = _bounds(match)
    if bounds is None:
        return "unparsed", None
    if bounds and exact:
        # Keep both: a specific CPE version can sit beside a separate range.
        return "both", (bounds, exact)
    if bounds:
        return "range", bounds
    if exact:
        return "exact", exact
    return "unbounded", None


def _bounds(match: dict[str, Any]) -> dict[str, str] | None:
    pairs = (
        ("versionStartIncluding", "min_inclusive"),
        ("versionStartExcluding", "min_exclusive"),
        ("versionEndExcluding", "max_exclusive"),
        ("versionEndIncluding", "max_inclusive"),
    )
    parsed: dict[str, str] = {}
    for source, target in pairs:
        value = match.get(source)
        if value is None:
            continue
        parsed_version = parse_version(value) if isinstance(value, str) else None
        if parsed_version is None:
            return None
        parsed[target] = format_version(parsed_version)
    if "min_inclusive" in parsed and "min_exclusive" in parsed:
        return None
    if "max_inclusive" in parsed and "max_exclusive" in parsed:
        return None
    return parsed


def _title(cve: dict[str, Any]) -> str:
    text = ""
    for item in cve.get("descriptions") or []:
        if isinstance(item, dict) and item.get("lang") == "en" and isinstance(item.get("value"), str):
            text = item["value"]
            break
    text = " ".join(text.split())
    text = re.sub(r"https?://\S+", "", text).strip()
    sentence = re.split(r"(?<=\.)\s", text, maxsplit=1)[0]
    if len(sentence) > 180:
        sentence = sentence[:179] + "…"
    return sentence or str(cve.get("id"))


def _published(cve: dict[str, Any]) -> str:
    value = cve.get("published")
    if isinstance(value, str) and len(value) >= 10 and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value[:10]):
        return value[:10]
    return ""


def _split_cpe(criteria: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    escaped = False
    for char in criteria:
        if escaped:
            buf.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(char)
    parts.append("".join(buf))
    return parts


def _dedup(ranges: list[dict[str, str]]) -> list[dict[str, str]]:
    unique: list[dict[str, str]] = []
    for item in ranges:
        if item not in unique:
            unique.append(item)
    return sorted(unique, key=lambda item: json.dumps(item, sort_keys=True))


def _copy_cve(cve: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": cve["id"],
        "title": cve.get("title") or "",
        "published": cve.get("published") or "",
        "ranges": [dict(item) for item in cve.get("ranges") or []],
        "exact": list(cve.get("exact") or []),
        "unbounded": bool(cve.get("unbounded")),
        "unparsed": bool(cve.get("unparsed")),
    }


def _validate(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise CatalogError("Непідтримуваний формат каталогу CVE")
    if set(value) - {"schema", "updated_at", "source", "cves"}:
        raise CatalogError("Зайве поле каталогу CVE")
    if _stamp(value.get("updated_at")) is None:
        raise CatalogError("Некоректна дата каталогу CVE")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) - {"name", "url", "query", "reported", "kept"}:
        raise CatalogError("Некоректне джерело каталогу CVE")
    if not isinstance(source.get("name"), str) or not source["name"] or len(source["name"]) > 40:
        raise CatalogError("Некоректне ім'я джерела каталогу")
    for key in ("url", "query"):
        if key in source and (not isinstance(source[key], str) or len(source[key]) > 300):
            raise CatalogError("Некоректне джерело каталогу CVE")
    for key in ("reported", "kept"):
        if key in source and (type(source[key]) is not int or source[key] < 0):
            raise CatalogError("Некоректне джерело каталогу CVE")
    cves = value.get("cves")
    if not isinstance(cves, list) or not 1 <= len(cves) <= MAX_CVES:
        raise CatalogError("Некоректний список CVE")
    seen: set[str] = set()
    cleaned = []
    for cve in cves:
        cleaned.append(_validate_cve(cve, seen))
    return {
        "schema": SCHEMA,
        "updated_at": value["updated_at"],
        "source": source,
        "cves": cleaned,
    }


def _validate_cve(cve: Any, seen: set[str]) -> dict[str, Any]:
    if not isinstance(cve, dict) or set(cve) - {"id", "title", "published", "ranges", "exact", "unbounded", "unparsed"}:
        raise CatalogError("Некоректний запис CVE")
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not _CVE_ID.fullmatch(cve_id) or cve_id in seen:
        raise CatalogError("Некоректний ідентифікатор CVE")
    seen.add(cve_id)
    title = cve.get("title")
    if not isinstance(title, str) or len(title) > 200:
        raise CatalogError("Некоректний заголовок CVE")
    published = cve.get("published")
    if not isinstance(published, str) or (published and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", published)):
        raise CatalogError("Некоректна дата CVE")
    ranges = cve.get("ranges")
    exact = cve.get("exact")
    if (
        not isinstance(ranges, list) or len(ranges) > MAX_RANGES
        or not isinstance(exact, list) or len(exact) > MAX_EXACT
        or type(cve.get("unbounded")) is not bool or type(cve.get("unparsed")) is not bool
    ):
        raise CatalogError("Некоректні межі CVE")
    return {
        "id": cve_id,
        "title": title,
        "published": published,
        "ranges": [_validate_range(item) for item in ranges],
        "exact": [_validate_exact(item) for item in exact],
        "unbounded": cve["unbounded"],
        "unparsed": cve["unparsed"],
    }


def _validate_range(item: Any) -> dict[str, str]:
    if not isinstance(item, dict) or not item or set(item) - _RANGE_KEYS:
        raise CatalogError("Некоректний діапазон CVE")
    if ("min_inclusive" in item and "min_exclusive" in item) or ("max_inclusive" in item and "max_exclusive" in item):
        raise CatalogError("Суперечливий діапазон CVE")
    cleaned = {}
    for key, value in item.items():
        parsed = parse_version(value) if isinstance(value, str) else None
        if parsed is None:
            raise CatalogError("Некоректна межа діапазону CVE")
        cleaned[key] = format_version(parsed)
    return cleaned


def _validate_exact(item: Any) -> str:
    parsed = parse_version(item) if isinstance(item, str) else None
    if parsed is None:
        raise CatalogError("Некоректна точна версія CVE")
    return format_version(parsed)


def _stamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        stamp = datetime.fromisoformat(value)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        return None
    return stamp.astimezone(timezone.utc)


def _headers() -> dict[str, str]:
    headers = {"User-Agent": "mikrotik-audit-cve/1.1", "Accept": "application/json"}
    key = os.environ.get("NVD_API_KEY", "")
    if re.fullmatch(r"[A-Za-z0-9_-]{8,128}", key):
        headers["apiKey"] = key
    return headers


def _read_limited(response: Any, limit: int) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = response.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise CatalogError("Завелика відповідь NVD")
        chunks.append(chunk)
    return b"".join(chunks)


def _strict_json(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CatalogError("Повторний JSON-ключ")
            result[key] = value
        return result

    def bad_number(value: str) -> None:
        raise CatalogError("Недопустиме JSON-число")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=bad_number)


class _PinnedRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse a redirect that leaves the NVD HTTPS host."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname != NVD_HOST:
            raise CatalogError("Перенаправлення за межі NVD відхилено")
        return super().redirect_request(req, fp, code, msg, headers, newurl)
