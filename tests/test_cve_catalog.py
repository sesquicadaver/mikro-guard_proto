"""Catalog floor, NVD normalization, and on-disk refresh."""
from __future__ import annotations

import json
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

import cve_catalog
from cve_catalog import (
    CatalogError,
    _PinnedRedirect,
    assess_catalog,
    catalog_is_stale,
    default_catalog_path,
    embedded_catalog,
    headline,
    load_catalog,
    update_catalog,
    write_catalog,
)
from mikrotik_audit import collection_command, version

FIXTURE = Path(__file__).parent / "fixtures" / "nvd_page.json"
TODAY = date(2026, 10, 24)
NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)


def parsed(text):
    return version(text)


def statuses(text, catalog):
    results = assess_catalog(parsed(text), catalog)
    return {item["id"]: item["status"] for item in results}


def test_catalog_path_is_beside_the_script():
    assert default_catalog_path().name == "cve_catalog.json"
    assert default_catalog_path().parent == Path(cve_catalog.__file__).resolve().parent


def test_floor_matrix():
    catalog = embedded_catalog()
    assert statuses("7.24.2 (stable)", catalog)["CVE-2026-67278"] == "AFFECTED"
    assert statuses("7.24.2 (stable)", catalog)["CVE-2026-67276"] == "UNAFFECTED"
    assert statuses("7.24.3 (stable)", catalog)["CVE-2026-67278"] == "UNAFFECTED"
    assert statuses("7.23.4 (long-term)", catalog)["CVE-2026-67278"] == "AFFECTED"
    assert statuses("7.23.4 (long-term)", catalog)["CVE-2026-67276"] == "UNAFFECTED"
    assert statuses("7.23.6 (long-term)", catalog)["CVE-2026-67278"] == "UNAFFECTED"
    assert statuses("7.23.5 (long-term)", catalog)["CVE-2026-67278"] == "AFFECTED"
    assert statuses("6.49.20 (long-term)", catalog)["CVE-2026-67277"] == "AFFECTED"
    assert statuses("6.49.20 (long-term)", catalog)["CVE-2026-67276"] == "UNAFFECTED"
    assert statuses("6.49.21 (long-term)", catalog)["CVE-2026-67277"] == "UNAFFECTED"
    assert statuses("7.8.0 (stable)", catalog)["CVE-2026-67276"] == "UNAFFECTED"
    assert statuses("7.8.0 (stable)", catalog)["CVE-2026-67277"] == "AFFECTED"
    assert statuses("7.19.6 (stable)", catalog)["CVE-2026-67281"] == "UNAFFECTED"
    assert statuses("7.20.0 (stable)", catalog)["CVE-2026-67281"] == "AFFECTED"
    assert headline(assess_catalog(parsed("7.24.3 (stable)"), catalog), True) == "PATCHED"
    assert headline(assess_catalog(parsed("7.24.2 (stable)"), catalog), True) == "AFFECTED"


def test_prerelease_rules():
    catalog = embedded_catalog()
    assert statuses("7.25.0beta2", catalog)["CVE-2026-67276"] == "AFFECTED"
    assert statuses("7.25.0beta3", catalog)["CVE-2026-67276"] == "UNAFFECTED"
    assert statuses("7.25.0beta3", catalog)["CVE-2026-67278"] == "UNKNOWN"
    assert statuses("7.24.3beta1", catalog)["CVE-2026-67278"] == "AFFECTED"
    assert statuses("7.24.3rc1", catalog)["CVE-2026-67278"] == "AFFECTED"
    assert headline(assess_catalog(parsed("7.25.0beta3"), catalog), True) == "UNKNOWN"
    assert headline(assess_catalog(parsed("7.25.0 (stable)"), catalog), True) == "PATCHED"


def test_unclassified_prerelease_is_unknown_not_patched():
    catalog = embedded_catalog()
    results = assess_catalog(parsed("7.26beta1"), catalog)
    assert {item["status"] for item in results} == {"UNKNOWN"}
    assert all(item["decisive"] for item in results)
    assert headline(results, True) == "UNKNOWN"
    assert headline(assess_catalog(parsed("7.26.0 (stable)"), catalog), True) == "PATCHED"
    assert headline(assess_catalog(parsed("7.26rc1"), catalog), True) == "UNKNOWN"


def test_narrowed_file_cannot_drop_the_floor(tmp_path):
    path = tmp_path / "cve_catalog.json"
    catalog = embedded_catalog()
    catalog["cves"] = [item for item in catalog["cves"] if item["id"] != "CVE-2026-67278"]
    narrowed = next(item for item in embedded_catalog()["cves"] if item["id"] == "CVE-2026-67278")
    narrowed["ranges"] = [{"min_inclusive": "7.24.0", "max_exclusive": "7.24.2"}]
    catalog["cves"].append(narrowed)
    catalog["source"] = {"name": "nvd", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "reported": 6, "kept": 6}
    catalog["updated_at"] = NOW.isoformat()
    write_catalog(path, catalog)
    loaded, error = load_catalog(path)
    assert error is None
    assert statuses("7.24.2 (stable)", loaded)["CVE-2026-67278"] == "AFFECTED"
    assert "CVE-2026-67276" in {item["id"] for item in loaded["cves"]}


def test_invalid_file_falls_back_to_floor(tmp_path):
    path = tmp_path / "cve_catalog.json"
    path.write_text("{", encoding="utf-8")
    loaded, error = load_catalog(path)
    assert error
    assert statuses("7.24.2 (stable)", loaded)["CVE-2026-67278"] == "AFFECTED"


def test_symlink_is_refused(tmp_path):
    target = tmp_path / "elsewhere.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "cve_catalog.json"
    link.symlink_to(target)
    with pytest.raises(CatalogError):
        write_catalog(link, embedded_catalog())
    assert target.read_text(encoding="utf-8") == "{}"


def test_update_normalizes_nvd_and_paginates(tmp_path):
    first = json.loads(FIXTURE.read_text(encoding="utf-8"))
    second = {
        "startIndex": 2,
        "totalResults": 3,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2018-5951",
                "vulnStatus": "Modified",
                "published": "2018-02-06T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Unbounded example."}],
                "configurations": [{
                    "nodes": [{
                        "negate": False,
                        "cpeMatch": [{
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
                        }],
                    }],
                }],
            },
        }],
    }
    seen = []

    def fetcher(start):
        seen.append(start)
        return first if start == 0 else second

    path = tmp_path / "cve_catalog.json"
    slept = []
    updated = update_catalog(path, fetcher=fetcher, sleeper=slept.append, now=NOW)
    assert seen == [0, 2]
    assert slept == [6]
    assert path.is_file()
    assert (path.stat().st_mode & 0o777) == 0o644
    assert "https://example.invalid" not in path.read_text(encoding="utf-8")
    assert statuses("5.15 (stable)", updated)["CVE-2012-6050"] == "AFFECTED"
    assert statuses("5.15.1 (stable)", updated)["CVE-2012-6050"] == "UNAFFECTED"
    assert statuses("5.15beta1", updated)["CVE-2012-6050"] == "UNKNOWN"
    unbounded = next(item for item in updated["cves"] if item["id"] == "CVE-2018-5951")
    assert unbounded["unbounded"] is True
    gap = next(item for item in assess_catalog(parsed("7.24.3 (stable)"), updated) if item["id"] == "CVE-2018-5951")
    assert gap["status"] == "UNKNOWN" and gap["decisive"] is False
    assert headline(assess_catalog(parsed("7.24.3 (stable)"), updated), True) == "PATCHED"
    assert next(item["title"] for item in updated["cves"] if item["id"] == "CVE-2026-67278").startswith("Прийняття")


def test_empty_feed_does_not_replace_catalog(tmp_path):
    path = tmp_path / "cve_catalog.json"
    write_catalog(path, embedded_catalog())
    before = path.read_bytes()

    def fetcher(_start):
        return {"startIndex": 0, "totalResults": 1, "vulnerabilities": []}

    with pytest.raises(CatalogError):
        update_catalog(path, fetcher=fetcher, sleeper=lambda _seconds: None, now=NOW)
    assert path.read_bytes() == before


def test_staleness(tmp_path):
    path = tmp_path / "cve_catalog.json"
    assert catalog_is_stale(path, 7, TODAY) is True
    catalog = embedded_catalog()
    catalog["source"]["name"] = "nvd"
    catalog["updated_at"] = "2026-10-20T00:00:00+00:00"
    write_catalog(path, catalog)
    assert catalog_is_stale(path, 7, TODAY) is False
    assert catalog_is_stale(path, 0, TODAY) is True
    catalog["updated_at"] = "2026-10-01T00:00:00+00:00"
    write_catalog(path, catalog)
    assert catalog_is_stale(path, 7, TODAY) is True


def test_redirect_stays_on_nvd():
    handler = _PinnedRedirect()
    request = urllib.request.Request("https://services.nvd.nist.gov/rest/json/cves/2.0")
    with pytest.raises(CatalogError):
        handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example/cve")
    with pytest.raises(CatalogError):
        handler.redirect_request(request, None, 302, "Found", {}, "http://services.nvd.nist.gov/rest/json/cves/2.0")
    allowed = handler.redirect_request(
        request, None, 302, "Found", {}, "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=200",
    )
    assert allowed.get_full_url().startswith("https://services.nvd.nist.gov/")


def test_remote_command_does_not_carry_the_catalog():
    command = collection_command()
    assert "CVE-" not in command
    assert "cve_catalog" not in command
    assert "nvd.nist.gov" not in command


def test_duplicate_json_key_is_rejected(tmp_path):
    path = tmp_path / "cve_catalog.json"
    path.write_bytes(b'{"schema": 1, "schema": 1}\n')
    _loaded, error = load_catalog(path)
    assert error


def _one_page(cve_id, matches, total=1):
    return {
        "startIndex": 0,
        "totalResults": total,
        "vulnerabilities": [{
            "cve": {
                "id": cve_id,
                "vulnStatus": "Analyzed",
                "published": "2022-08-25T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Synthetic RouterOS match."}],
                "configurations": [{"nodes": [{"negate": False, "cpeMatch": matches}]}],
            },
        }],
    }


def _refresh(tmp_path, page):
    return update_catalog(
        tmp_path / "cve_catalog.json",
        fetcher=lambda _start: page,
        sleeper=lambda _seconds: None,
        now=NOW,
    )


def _only(catalog, cve_id):
    return {"cves": [item for item in catalog["cves"] if item["id"] == cve_id]}


def test_cpe_update_keeps_beta_identity(tmp_path):
    page = _one_page("CVE-2022-34960", [{
        "vulnerable": True,
        "criteria": "cpe:2.3:o:mikrotik:routeros:7.4:beta4:*:*:*:*:*:*",
    }])
    updated = _refresh(tmp_path, page)
    cve = next(item for item in updated["cves"] if item["id"] == "CVE-2022-34960")
    assert cve["exact"] == ["7.4.0beta4"]
    alone = _only(updated, "CVE-2022-34960")
    assert statuses("7.4beta4", alone)["CVE-2022-34960"] == "AFFECTED"
    assert statuses("7.4 (stable)", alone)["CVE-2022-34960"] == "UNAFFECTED"
    beta5 = next(item for item in assess_catalog(parsed("7.4beta5"), alone) if item["id"] == "CVE-2022-34960")
    assert beta5["status"] == "UNKNOWN" and beta5["decisive"] is True


def test_unsupported_cpe_update_is_unparsed(tmp_path):
    page = _one_page("CVE-2020-0001", [{
        "vulnerable": True,
        "criteria": "cpe:2.3:o:mikrotik:routeros:7.4:testing:*:*:*:*:*:*",
    }])
    updated = _refresh(tmp_path, page)
    cve = next(item for item in updated["cves"] if item["id"] == "CVE-2020-0001")
    assert cve["exact"] == []
    assert cve["unparsed"] is True
    item = next(item for item in assess_catalog(parsed("7.4 (stable)"), _only(updated, "CVE-2020-0001")))
    assert item["status"] == "UNKNOWN" and item["decisive"] is False


def test_bounded_and_unbounded_matches_keep_uncertainty(tmp_path):
    page = _one_page("CVE-2020-0002", [
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "7.1.0",
            "versionEndExcluding": "7.2.0",
        },
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
        },
    ])
    updated = _refresh(tmp_path, page)
    cve = next(item for item in updated["cves"] if item["id"] == "CVE-2020-0002")
    assert cve["unbounded"] is True
    assert cve["ranges"] == [{"min_inclusive": "7.1.0", "max_exclusive": "7.2.0"}]
    alone = _only(updated, "CVE-2020-0002")
    assert statuses("7.1.5 (stable)", alone)["CVE-2020-0002"] == "AFFECTED"
    outside = next(item for item in assess_catalog(parsed("7.3 (stable)"), alone))
    assert outside["status"] == "UNKNOWN" and outside["decisive"] is True


def test_floor_keeps_unbounded_uncertainty(tmp_path):
    page = _one_page("CVE-2026-67278", [
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "7.0.0",
            "versionEndExcluding": "7.23.6",
        },
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
        },
    ])
    path = tmp_path / "cve_catalog.json"
    updated = update_catalog(path, fetcher=lambda _start: page, sleeper=lambda _seconds: None, now=NOW)
    loaded, error = load_catalog(path)
    assert error is None
    for catalog in (updated, loaded):
        cve = next(item for item in catalog["cves"] if item["id"] == "CVE-2026-67278")
        assert cve["unbounded"] is True
        assert any(item.get("max_exclusive") == "7.24.3" for item in cve["ranges"])
        assert statuses("7.24.2 (stable)", catalog)["CVE-2026-67278"] == "AFFECTED"
        outside = next(
            item for item in assess_catalog(parsed("7.24.3 (stable)"), catalog)
            if item["id"] == "CVE-2026-67278"
        )
        assert outside["status"] == "UNKNOWN" and outside["decisive"] is True
        assert headline(assess_catalog(parsed("7.24.3 (stable)"), catalog), True) == "UNKNOWN"


def test_partial_unparsed_match_stays_decisive(tmp_path):
    page = _one_page("CVE-2020-0003", [
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "7.1.0",
            "versionEndExcluding": "7.2.0",
        },
        {
            "vulnerable": True,
            "criteria": "cpe:2.3:o:mikrotik:routeros:7.4:testing:*:*:*:*:*:*",
        },
    ])
    updated = _refresh(tmp_path, page)
    cve = next(item for item in updated["cves"] if item["id"] == "CVE-2020-0003")
    assert cve["unparsed"] is True
    assert cve["ranges"] == [{"min_inclusive": "7.1.0", "max_exclusive": "7.2.0"}]
    alone = _only(updated, "CVE-2020-0003")
    assert statuses("7.1.5 (stable)", alone)["CVE-2020-0003"] == "AFFECTED"
    outside = next(item for item in assess_catalog(parsed("7.3 (stable)"), alone))
    assert outside["status"] == "UNKNOWN" and outside["decisive"] is True
    assert headline(assess_catalog(parsed("7.3 (stable)"), alone), True) == "UNKNOWN"


def test_validator_rejects_empty_record_and_inverted_range(tmp_path):
    empty = embedded_catalog()
    empty["cves"].append({
        "id": "CVE-2020-0001",
        "title": "порожній запис",
        "published": "2020-01-01",
        "ranges": [],
        "exact": [],
        "unbounded": False,
        "unparsed": False,
    })
    with pytest.raises(CatalogError, match="невизначеності"):
        write_catalog(tmp_path / "empty.json", empty)

    inverted = embedded_catalog()
    inverted["cves"].append({
        "id": "CVE-2020-0002",
        "title": "перевернутий діапазон",
        "published": "2020-01-01",
        "ranges": [{"min_inclusive": "7.5.0", "max_exclusive": "7.4.0"}],
        "exact": [],
        "unbounded": False,
        "unparsed": False,
    })
    with pytest.raises(CatalogError, match="Порожній діапазон"):
        write_catalog(tmp_path / "inverted.json", inverted)


def test_permission_error_falls_back_to_floor(tmp_path, monkeypatch):
    path = tmp_path / "cve_catalog.json"
    path.write_text("{}\n", encoding="utf-8")

    def unreadable(_path):
        raise PermissionError("permission denied")

    monkeypatch.setattr(cve_catalog, "read_catalog", unreadable)
    loaded, error = load_catalog(path)
    assert error == "permission denied"
    assert loaded["source"]["name"] == "embedded"
    assert statuses("7.24.2 (stable)", loaded)["CVE-2026-67278"] == "AFFECTED"


def test_shipped_catalog_keeps_34960_prerelease():
    loaded, error = load_catalog(default_catalog_path())
    assert error is None
    cve = next(item for item in loaded["cves"] if item["id"] == "CVE-2022-34960")
    assert "7.4.0beta4" in cve["exact"]
    assert "7.4.0" not in cve["exact"]
    alone = {"cves": [cve]}
    assert statuses("7.4beta4", alone)["CVE-2022-34960"] == "AFFECTED"
    assert statuses("7.4 (stable)", alone)["CVE-2022-34960"] == "UNAFFECTED"
    assert headline(assess_catalog(parsed("7.26beta1"), loaded), True) != "PATCHED"


def test_api_key_is_not_taken_from_a_short_value(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "short")
    assert "apiKey" not in cve_catalog._headers()
    monkeypatch.setenv("NVD_API_KEY", "abcdEFGH-1234")
    assert cve_catalog._headers()["apiKey"] == "abcdEFGH-1234"
    assert "abcdEFGH-1234" not in cve_catalog.NVD_URL
