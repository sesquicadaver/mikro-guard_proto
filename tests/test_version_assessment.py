"""RouterOS version verdict uses the catalog instead of a single hardcoded cutoff."""
from __future__ import annotations

import argparse
from datetime import date

import pytest

from cve_catalog import embedded_catalog, write_catalog
from mikrotik_audit import Checks, main, prepare_catalog

TODAY = date(2026, 10, 24)


def snapshot(text, errors=None):
    return {
        "schema": 1,
        "host": "203.0.113.10",
        "routeros_version": text,
        "errors": errors or {},
        "data": {},
        "collected_at": "2026-10-24T00:00:00+00:00",
    }


def by_id(text, errors=None):
    report = Checks(snapshot(text, errors), catalog=embedded_catalog()).run(today=TODAY, offline=True)
    return {item["id"]: item["status"] for item in report["findings"]}, report


def test_incomplete_fix_is_vulnerable_and_complete_fix_is_not():
    affected, affected_report = by_id("7.24.2 (stable)")
    patched, patched_report = by_id("7.24.3 (stable)")
    assert affected["ROS-2026-09"] == "VULNERABLE_VERSION"
    assert affected["CVE-2026-67278"] == "VULNERABLE_VERSION"
    assert "CVE-2026-67276" not in affected
    assert patched["ROS-2026-09"] == "PASS"
    assert "CVE-2026-67278" not in patched
    assert affected_report["exit_code"] & 1 == 1
    assert patched_report["exit_code"] & 1 == 0
    assert patched_report["cve_catalog_count"] == 6


def test_branch_specific_fixes():
    long_term, _report = by_id("7.23.4 (long-term)")
    assert long_term["CVE-2026-67278"] == "VULNERABLE_VERSION"
    assert "CVE-2026-67276" not in long_term
    cleared, _report = by_id("6.49.21 (long-term)")
    assert cleared["ROS-2026-09"] == "PASS"
    webfig, _report = by_id("7.19.2 (stable)")
    assert "CVE-2026-67281" not in webfig
    assert webfig["CVE-2026-67279"] == "VULNERABLE_VERSION"


def test_inconsistent_snapshot_does_not_claim_a_fix():
    findings, _report = by_id("7.24.3 (stable)", {"consistency": "Версія змінилася"})
    assert findings["ROS-2026-09"] == "UNKNOWN"
    assert "CVE-2026-67278" not in findings


def test_prepare_uses_saved_catalog_until_it_is_stale(monkeypatch, tmp_path):
    path = tmp_path / "cve_catalog.json"
    catalog = embedded_catalog()
    catalog["source"]["name"] = "nvd"
    catalog["updated_at"] = "2026-10-24T00:00:00+00:00"
    write_catalog(path, catalog)
    monkeypatch.setattr("mikrotik_audit.default_catalog_path", lambda: path)
    monkeypatch.setattr("mikrotik_audit.catalog_is_stale", lambda *_args, **_kwargs: False)

    def fail_update(*_args, **_kwargs):
        raise AssertionError("свіжий каталог не треба завантажувати")

    monkeypatch.setattr("mikrotik_audit.update_catalog", fail_update)
    args = argparse.Namespace(update_cve=False, host="203.0.113.10", no_cve_update=False, cve_max_age=7)
    loaded, note = prepare_catalog(args)
    assert note is None
    assert loaded["source"]["name"] == "nvd"


def test_update_only_writes_beside_the_script(monkeypatch, tmp_path, capsys):
    path = tmp_path / "cve_catalog.json"
    monkeypatch.setattr("mikrotik_audit.default_catalog_path", lambda: path)

    def fake_update(target, **_kwargs):
        catalog = embedded_catalog()
        catalog["source"]["name"] = "nvd"
        catalog["updated_at"] = "2026-10-24T12:00:00+00:00"
        write_catalog(target, catalog)
        return catalog

    monkeypatch.setattr("mikrotik_audit.update_catalog", fake_update)
    assert main(["--update-cve"]) == 0
    assert path.is_file()
    output = capsys.readouterr().out
    assert str(path) in output
    with pytest.raises(SystemExit):
        main(["--update-cve", "--offline", str(tmp_path / "missing.json")])


def test_update_only_rejects_audit_options():
    with pytest.raises(SystemExit):
        main(["--update-cve", "--report", "report.json"])
