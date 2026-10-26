#!/usr/bin/env python3
"""Read-only MikroTik assessment. Python >=3.10, system OpenSSH; no exploits.

Run --help. Security boundaries and coverage limitations are in README.uk.md.
Only fixed RouterOS read expressions are sent over SSH. RouterOS :set below
assigns LOCAL script variables; it never changes a RouterOS configuration item.
CVE ranges are read from cve_catalog.json next to this file and refreshed from NVD.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from cve_catalog import (
    CatalogError,
    assess_catalog,
    catalog_is_stale,
    default_catalog_path,
    headline,
    load_catalog,
    update_catalog,
)

VERSION = "1.1.1"
MAX_BYTES = 8 * 1024 * 1024
MAX_ROWS = 1000
MARKER = "@MT-AUDIT-1@"
ADVISORY = "https://mikrotik.com/supportsec/september-2026-vulnerability/"
CERT = "https://cert.pl/en/posts/2026/09/mikrotik-routeros-cve/"
INCIDENT = "https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/"
HARDENING = "https://help.mikrotik.com/docs/spaces/ROS/pages/328353/Securing+your+router"
SERVICES_DOC = "https://help.mikrotik.com/docs/spaces/ROS/pages/103841820/Services"
USER_DOC = "https://help.mikrotik.com/docs/spaces/ROS/pages/8978504/User"
NVD_CATALOG_DOC = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# key: (menu, properties). These constants are the complete remote read allowlist.
# None means the firewall match map; comments/log-prefix/counters are removed.
TABLES = {
    "services": ("/ip/service", "name,disabled,invalid,dynamic,port,address,certificate,tls-version,vrf"),
    "users": ("/user", "name,disabled,group,address"),
    "groups": ("/user/group", "name,policy"),
    "ssh_keys": ("/user/ssh-keys", "user,key-type,bits,fingerprint"),
    "interfaces": ("/interface", "name,type,disabled,running,dynamic"),
    "lists": ("/interface/list", "name,include,exclude"),
    "members": ("/interface/list/member", "list,interface,dynamic,disabled"),
    "bridge_ports": ("/interface/bridge/port", "bridge,interface,disabled,pvid"),
    "ipv4_filter": ("/ip/firewall/filter", None),
    "ipv6_filter": ("/ipv6/firewall/filter", None),
    "packages": ("/system/package", "name,version,disabled"),
    "snmp_communities": ("/snmp/community", "security,addresses,read-access,write-access"),
    "scripts": ("/system/script", "name,owner,policy,dont-require-permissions"),
    "scheduler": ("/system/scheduler", "name,disabled,owner,policy,interval"),
    "netwatch": ("/tool/netwatch", "name,disabled,type"),
    "logs": ("/log", "time,topics"),
}
SCALARS = {
    "resource": ("/system/resource", "version,architecture-name,board-name,uptime"),
    "routerboard": ("/system/routerboard", "routerboard,current-firmware,upgrade-firmware"),
    "dns": ("/ip/dns", "allow-remote-requests,verify-doh-cert"),
    "mac_winbox": ("/tool/mac-server/mac-winbox", "allowed-interface-list"),
    "mac_telnet": ("/tool/mac-server", "allowed-interface-list"),
    "mac_ping": ("/tool/mac-server/ping", "enabled"),
    "neighbor": ("/ip/neighbor/discovery-settings", "discover-interface-list,mode,protocol"),
    "device_mode": ("/system/device-mode", "flagged,flagging-enabled,mode"),
    "ssh": ("/ip/ssh", "strong-crypto,forwarding-enabled,host-key-size,password-authentication"),
    "bandwidth": ("/tool/bandwidth-server", "enabled,authenticate"),
    "socks": ("/ip/socks", "enabled,port"),
    "proxy": ("/ip/proxy", "enabled,port"),
    "upnp": ("/ip/upnp", "enabled,allow-disable-external-interface"),
    "romon": ("/tool/romon", "enabled"),
    "snmp": ("/snmp", "enabled"),
    "smb": ("/ip/smb", "enabled"),
    "ipv6": ("/ipv6/settings", "disable-ipv6"),
}
SECTIONS = tuple(TABLES) + tuple(SCALARS)
VERSION_COMMAND = ':put [/system/resource/get version]'


class AuditError(Exception):
    """An incomplete or rejected operation, never a successful check."""


def boolean(value):
    """Three-valued boolean: absent/unrecognized values are not False."""
    if value is True or value in ("true", "yes"):
        return True
    if value is False or value in ("false", "no"):
        return False
    return None


def words(value):
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return value
    return []


def version(text):
    if not isinstance(text, str):
        return None
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:(beta|rc)(\d+))?"
                         r"(?: \((stable|long-term|testing|development)\))?", text.strip())
    if not match:
        return None
    major, minor, patch, stage, build, _ = match.groups()
    return (int(major), int(minor), int(patch or 0), stage or "", int(build or 0))


def _project(fields):
    return " ".join(f':set ($auditOut->"{field}") ($auditRow->"{field}");'
                    for field in fields.split(","))


def collection_command(max_rows=MAX_ROWS):
    """Generate a fixed, bounded read-only RouterOS expression, not user code."""
    if type(max_rows) is not int or not 1 <= max_rows <= MAX_ROWS:
        raise AuditError("Некоректний ліміт записів")
    commands = []
    for key, (menu, fields) in TABLES.items():
        body = (f':if ([{menu}/print count-only] > {max_rows}) do={{:error "limit"}}; '
                f':local auditIds [{menu}/find]; '
                f':if ([:len $auditIds] > {max_rows}) do={{:error "limit"}}; '
                ':local auditResult [:toarray ""]; :local auditBytes 0; '
                ':foreach auditId in=$auditIds do={ '
                f':local auditEntry [{menu}/print as-value from=$auditId]; '
                ':if ([:len $auditEntry] != 1) do={:error "changed"}; '
                ':local auditRow ($auditEntry->0); :local auditOut {"_schema"=1}; ')
        if fields is None:
            # Keep ALL match properties: ignoring an unfamiliar condition could
            # falsely label a conditional drop as an unconditional deny.
            body += (':foreach auditKey,auditValue in=$auditRow do={ '
                     ':if (($auditKey != "comment") && ($auditKey != "log-prefix") '
                     '&& ($auditKey != "bytes") && ($auditKey != "packets")) do={ '
                     ':set ($auditOut->$auditKey) $auditValue; }; }; ')
        else:
            body += _project(fields)
        source_field = {"scripts": "source", "scheduler": "on-event"}.get(key)
        if source_field:
            body += (f':local auditSource ($auditRow->"{source_field}"); '
                     ':set ($auditOut->"source-length") [:len $auditSource]; '
                     ':set ($auditOut->"fetch-hint") ([:typeof [:find $auditSource "fetch"]] != "nil"); '
                     ':set ($auditOut->"url-hint") ([:typeof [:find $auditSource "://"]] != "nil"); ')
        if key == "logs":
            # No raw log message, potentially containing credentials, leaves the router.
            body += (':local auditMessage ($auditRow->"message"); '
                     ':set ($auditOut->"flagged-hint") ([:typeof [:find $auditMessage "lagged"]] != "nil"); '
                     ':set ($auditOut->"login-hint") ([:typeof [:find $auditMessage "login failure for user -2 "]] != "nil"); '
                     ':set ($auditOut->"creation-hint") ([:typeof [:find $auditMessage "added by ssh:-2@"]] != "nil"); ')
        body += (':local auditEncoded [:serialize to=json options=json.no-string-conversion value=$auditOut]; '
                 ':if ([:len $auditEncoded] > 16384) do={:error "record limit"}; '
                 ':set auditBytes ($auditBytes + [:len $auditEncoded]); '
                 ':if ($auditBytes > 262144) do={:error "section limit"}; '
                 ':set auditResult ($auditResult, {$auditOut}); }; ')
        body += f':put ("{MARKER}{key}:" . [:serialize to=json options=json.no-string-conversion value=$auditResult]);'
        commands.append(f':do {{ {body} }} on-error={{ :put "{MARKER}{key}:ERROR"; }};')
    for key, (menu, fields) in SCALARS.items():
        body = ':local auditOut {"_schema"=1}; '
        for field in fields.split(","):
            # Properties differ between RouterOS releases. A missing property
            # stays absent; the corresponding check will become UNKNOWN.
            body += (f':do {{ :set ($auditOut->"{field}") [{menu}/get {field}]; }} '
                     'on-error={}; ')
        if key == "dns":
            body += (':do { :set ($auditOut->"doh-configured") '
                     '([:len [/ip/dns/get use-doh-server]] > 0); } on-error={}; ')
        body += f':put ("{MARKER}{key}:" . [:serialize to=json options=json.no-string-conversion value=$auditOut]);'
        commands.append(f':do {{ {body} }} on-error={{ :put "{MARKER}{key}:ERROR"; }};')
    return "{ " + " ".join(commands) + f' :put "{MARKER}END"; }}'


def strict_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AuditError("Повторний JSON-ключ")
            result[key] = value
        return result

    def bad_number(value):
        raise AuditError("Недопустиме JSON-число: " + value)

    try:
        return json.loads(text, object_pairs_hook=unique, parse_constant=bad_number)
    except (ValueError, RecursionError) as exc:
        raise AuditError("Некоректний JSON") from exc


def validate_section(key, value):
    if key in TABLES:
        if not isinstance(value, list) or len(value) > MAX_ROWS:
            raise AuditError("Некоректна таблиця: " + key)
        rows = value
    else:
        rows = [value]
    for row in rows:
        if (not isinstance(row, dict) or len(row) > 200 or
                type(row.get("_schema")) is not int or row["_schema"] != 1):
            raise AuditError("Некоректний запис: " + key)
        identifiers = {"name", "user", "group", "owner", "interface", "bridge", "list", "type", "chain", "action"}
        for field in identifiers & row.keys():
            if row[field] is not None and not isinstance(row[field], str):
                raise AuditError("Некоректний ідентифікатор: " + key)
        for item in row.values():
            if isinstance(item, float) and not math.isfinite(item):
                raise AuditError("Недопустиме число: " + key)
            if item is not None and not isinstance(item, (str, bool, int, float, list)):
                raise AuditError("Вкладена структура у властивості: " + key)
            if isinstance(item, list) and (len(item) > MAX_ROWS or
                                          any(not isinstance(x, (str, int, bool)) for x in item)):
                raise AuditError("Некоректний список властивості: " + key)
    return value


def parse_collection(raw):
    if len(raw) > MAX_BYTES:
        raise AuditError("Завелика відповідь")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise AuditError("Відповідь не є UTF-8") from exc
    data, errors, seen = {}, {}, set()
    finished = False
    for line in text.split("\n"):
        line = line.removesuffix("\r")
        if not line.strip():
            continue
        if line == MARKER + "END" and not finished:
            finished = True
            continue
        if finished or not line.startswith(MARKER):
            raise AuditError("Неочікуваний вивід RouterOS; перевірку не підтверджено")
        key, sep, payload = line[len(MARKER):].partition(":")
        if not sep or key not in SECTIONS or key in seen:
            raise AuditError("Невідомий або повторний розділ відповіді")
        seen.add(key)
        if payload == "ERROR":
            errors[key] = "Команда недоступна, недостатні права або перевищено ліміт записів"
            continue
        try:
            data[key] = validate_section(key, strict_json(payload))
        except AuditError as exc:
            errors[key] = str(exc)
    if not finished:
        raise AuditError("Відповідь обірвана: відсутній кінцевий маркер")
    for key in SECTIONS:
        if key not in seen:
            errors[key] = "Розділ не отримано"
    return data, errors


def safe_text(value, limit=400):
    text = str(value)
    text = "".join(char if not unicodedata.category(char).startswith("C") else "?" for char in text)
    return text if len(text) <= limit else text[:limit] + "…"


def run_bounded(argv, timeout, max_bytes=MAX_BYTES):
    """Drain both pipes concurrently, cap memory and total wall time. No shell."""
    events = queue.Queue(maxsize=16)
    stop = threading.Event()

    def publish(item):
        while not stop.is_set():
            try:
                events.put(item, timeout=0.1)
                return
            except queue.Full:
                pass

    def reader(stream, index):
        try:
            while not stop.is_set():
                chunk = stream.read(8192)
                if not chunk:
                    break
                publish((index, chunk))
        finally:
            publish((index, None))

    deadline = time.monotonic() + timeout
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, shell=False, bufsize=0) as process:
        threads = [threading.Thread(target=reader, args=(stream, i), daemon=True)
                   for i, stream in enumerate((process.stdout, process.stderr))]
        for thread in threads:
            thread.start()
        output = [bytearray(), bytearray()]
        closed, received = set(), 0
        try:
            while len(closed) != 2:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AuditError("Перевищено загальний час SSH-команди")
                try:
                    index, chunk = events.get(timeout=min(remaining, 0.1))
                except queue.Empty:
                    continue
                if chunk is None:
                    closed.add(index)
                else:
                    received += len(chunk)
                    if received > max_bytes:
                        raise AuditError("Перевищено ліміт відповіді SSH")
                    output[index].extend(chunk)
            try:
                code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise AuditError("SSH не завершився вчасно") from exc
            return code, bytes(output[0]), bytes(output[1])
        finally:
            stop.set()
            if process.poll() is None:
                process.kill()
            process.wait()
            for thread in threads:
                thread.join(timeout=1)


def valid_host(host):
    try:
        # Scope identifiers are intentionally unsupported; use a routable
        # management address for IPv6 instead.
        if "%" in host:
            return False
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(len(host) <= 253 and re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host))


def ssh_argv(args, command):
    executable = shutil.which("ssh")
    if not executable:
        raise AuditError("Потрібен встановлений OpenSSH client (ssh)")
    # Ignore ambient SSH config: no hidden forwarding, ProxyCommand, LocalCommand,
    # shared master connection, or alternate destination. User's agent still works.
    argv = [executable, "-F", os.devnull, "-T", "-o", "StrictHostKeyChecking=yes",
            "-o", "UpdateHostKeys=no", "-o", "VerifyHostKeyDNS=no",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
            "-o", "LogLevel=ERROR", "-o", "NumberOfPasswordPrompts=1",
            "-o", "BatchMode=" + ("no" if args.ask_password else "yes"),
            "-p", str(args.port), "-l", args.user]
    if args.known_hosts:
        path = str(Path(args.known_hosts).expanduser().resolve())
        if not Path(path).is_file() or any(c in path for c in '\n\r"%'):
            raise AuditError("Некоректний known_hosts")
        argv += ["-o", f'UserKnownHostsFile="{path}"', "-o", "GlobalKnownHostsFile=" + os.devnull]
    if args.identity:
        path = Path(args.identity).expanduser().resolve()
        if not path.is_file():
            raise AuditError("Файл приватного ключа не знайдено")
        argv += ["-i", str(path), "-o", "IdentitiesOnly=yes"]
    if args.ask_password:
        argv += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=keyboard-interactive,password"]
    argv += ["--", args.host, command]
    return argv


def collect(args):
    started = time.monotonic()
    code, raw, error = run_bounded(ssh_argv(args, VERSION_COMMAND), min(30, args.timeout), 65536)
    if code != 0 or error.strip():
        raise AuditError("SSH/версія: " + safe_text(error.decode("utf-8", "replace")))
    try:
        installed = raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise AuditError("Некоректна відповідь про версію") from exc
    if not version(installed):
        raise AuditError("RouterOS не повернув однозначну версію")
    snapshot = {"schema": 1, "tool_version": VERSION, "host": args.host,
                "collected_at": datetime.now(timezone.utc).isoformat(),
                "routeros_version": installed, "data": {}, "errors": {}}
    if version(installed)[:3] < (7, 13, 0):
        snapshot["errors"]["structured_collection"] = (
            "RouterOS до 7.13: лише перевірка версії; структурований аудит не підтримується")
        return snapshot
    try:
        remaining = args.timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise AuditError("Вичерпано час аудиту")
        code, raw, error = run_bounded(ssh_argv(args, collection_command(args.max_rows)), remaining)
        if code != 0 or error.strip():
            raise AuditError("SSH/збір: " + safe_text(error.decode("utf-8", "replace")))
        snapshot["data"], snapshot["errors"] = parse_collection(raw)
        observed = snapshot["data"].get("resource", {}).get("version")
        if observed is not None and version(observed) != version(installed):
            snapshot["errors"]["consistency"] = "Версія змінилася між двома SSH-сеансами"
    except AuditError as exc:
        snapshot["errors"]["structured_collection"] = str(exc)
    return snapshot


def read_snapshot(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise AuditError("Завеликий snapshot")
    try:
        value = strict_json(raw.decode("utf-8"))
    except UnicodeError as exc:
        raise AuditError("Snapshot не є UTF-8") from exc
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise AuditError("Непідтримуваний формат snapshot")
    if not isinstance(value.get("data"), dict) or not isinstance(value.get("errors"), dict):
        raise AuditError("Snapshot не містить data/errors")
    if (len(value["errors"]) > len(SECTIONS) + 4 or
            any(not isinstance(x, str) for x in value["errors"].values())):
        raise AuditError("Некоректний список помилок snapshot")
    if not version(value.get("routeros_version")) or not isinstance(value.get("host"), str):
        raise AuditError("Snapshot не містить коректної версії/адреси")
    for key, content in value["data"].items():
        if key not in SECTIONS:
            raise AuditError("Невідомий розділ snapshot")
        validate_section(key, content)
    return value


class Checks:
    def __init__(self, snapshot, untrusted=(), trusted=(), catalog=None, catalog_note=None):
        self.snapshot = snapshot
        self.data = snapshot["data"]
        self.untrusted = set(untrusted)
        self.trusted = [ipaddress.ip_network(x, strict=False) for x in trusted]
        self.findings = []
        if catalog is None:
            catalog, note = load_catalog(default_catalog_path())
            catalog_note = catalog_note or note
        self.catalog = catalog
        self.catalog_note = catalog_note

    def add(self, rule, status, severity, title, evidence=None, recommendation="", source=HARDENING):
        self.findings.append({"id": rule, "status": status, "severity": severity,
                              "title": title, "evidence": evidence,
                              "recommendation": recommendation, "source": source})

    def table(self, key):
        if key in self.snapshot["errors"] or "consistency" in self.snapshot["errors"]:
            return None
        return self.data.get(key)

    def field(self, key, field):
        row = self.table(key)
        return row.get(field) if isinstance(row, dict) else None

    def scope(self, addresses):
        """Service ACL versus explicitly declared trusted CIDRs, not RFC1918."""
        if addresses is None:
            return "UNKNOWN"
        if not isinstance(addresses, (str, list)):
            return "UNKNOWN"
        values = words(addresses)
        if not values:
            return "UNRESTRICTED"
        try:
            networks = [ipaddress.ip_network(x, strict=False) for x in values]
        except ValueError:
            return "UNKNOWN"
        if any(x.prefixlen == 0 for x in networks):
            return "UNRESTRICTED"
        if not self.trusted:
            return "RESTRICTED_UNVERIFIED"
        if all(any(n.version == t.version and n.subnet_of(t) for t in self.trusted) for n in networks):
            return "TRUSTED_ONLY"
        return "OUTSIDE_TRUSTED"

    def list_members(self, name, visited=()):
        """Conservative expansion; unknown/dynamic membership stays unknown."""
        if not isinstance(name, str) or name in visited or len(visited) >= 16:
            return None
        interfaces = self.table("interfaces")
        if name == "none":
            return set()
        if interfaces is None:
            return None
        universe = {x.get("name") for x in interfaces}
        if None in universe:
            return None
        if name == "all":
            return universe
        if name.startswith("!"):
            nested = self.list_members(name[1:], (*visited, name))
            return None if nested is None else universe - nested
        if name in ("static", "dynamic"):
            if any(boolean(x.get("dynamic")) is None for x in interfaces):
                return None
            return {x["name"] for x in interfaces if boolean(x["dynamic"]) == (name == "dynamic")}
        lists, members = self.table("lists"), self.table("members")
        if lists is None or members is None:
            return None
        definitions = [x for x in lists if x.get("name") == name]
        if len(definitions) != 1:
            return None
        definition = definitions[0]
        for field in ("include", "exclude"):
            value = definition.get(field)
            if value is not None and not isinstance(value, (str, list)):
                return None
            if isinstance(value, list) and any(not isinstance(x, str) for x in value):
                return None
        result = set()
        for list_name in words(definition.get("include")):
            values = self.list_members(list_name, (*visited, name))
            if values is None:
                return None
            result |= values
        for list_name in words(definition.get("exclude")):
            values = self.list_members(list_name, (*visited, name))
            if values is None:
                return None
            result -= values
        # RouterOS applies explicit members AFTER includes/excludes.
        result |= {x.get("interface") for x in members if x.get("list") == name
                   and boolean(x.get("disabled")) is not True}
        if not result.issubset(universe):
            return None
        return result

    def versions(self):
        installed = self.snapshot.get("routeros_version")
        known = "consistency" not in self.snapshot["errors"] and version(installed) is not None
        parsed = version(installed) if known else None
        results = assess_catalog(parsed, self.catalog)
        state = headline(results, known)
        affected = [item for item in results if item["status"] == "AFFECTED"]
        unconfirmed = [item for item in results if item["status"] == "UNKNOWN" and item["decisive"]]
        gaps = [item for item in results if item["status"] == "UNKNOWN" and not item["decisive"]]
        self.add("ROS-2026-09", {"AFFECTED": "VULNERABLE_VERSION", "PATCHED": "PASS", "UNKNOWN": "UNKNOWN"}[state],
                 "high" if state == "AFFECTED" else "info",
                 "Версія RouterOS і локальний каталог CVE",
                 {"version": installed, "assessment": state,
                  "affected": [item["id"] for item in affected],
                  "unconfirmed": [item["id"] for item in unconfirmed],
                  "catalog_count": len(self.catalog.get("cves", [])),
                  "catalog_updated_at": self.catalog.get("updated_at"),
                  "scope": "Зіставлення версії з каталогом; експлуатацію та факт компрометації не перевірено"},
                 "Встановити повну латку гілки. Для бюлетеня 2026-10-06 це 7.24.3, 7.23.6 або 6.49.21 і новіші; "
                 "7.24.2 і 7.23.4 не закривають CVE-2026-67278.", ADVISORY)
        for item in affected:
            self.add(item["id"], "VULNERABLE_VERSION", "high", item["title"],
                     {"version": installed, "ranges": item["ranges"], "exact": item["exact"]},
                     "Оновити RouterOS до версії поза цими межами.",
                     "https://nvd.nist.gov/vuln/detail/" + item["id"])
        if gaps:
            self.add("CVE-NO-RANGE", "UNKNOWN", "info",
                     "Частина CVE у каталозі не має машиночитних меж версій",
                     {"count": len(gaps), "ids": [item["id"] for item in gaps[:30]]},
                     "Ці записи не змінюють вердикт версії. Звірити їх вручну для старих релізів.",
                     NVD_CATALOG_DOC)
        current = self.field("routerboard", "current-firmware")
        upgrade = self.field("routerboard", "upgrade-firmware")
        hardware = boolean(self.field("routerboard", "routerboard"))
        if hardware is False:
            self.add("ROUTERBOOT", "NOT_APPLICABLE", "info", "RouterBOOT: не RouterBOARD")
        elif not version(current) or not version(upgrade):
            self.add("ROUTERBOOT", "UNKNOWN", "info", "Версію RouterBOOT не визначено")
        else:
            self.add("ROUTERBOOT", "PASS" if current == upgrade else "REVIEW", "info",
                     "Порівняння встановленого й доступного RouterBOOT",
                     {"current": current, "bundled": upgrade},
                     "Різниця версій сама по собі не доводить вразливості.")
        packages = self.table("packages")
        if packages is not None:
            mismatched = [p for p in packages if boolean(p.get("disabled")) is False
                          and version(p.get("version")) != version(installed)]
            if mismatched:
                self.add("PACKAGE-VERSIONS", "REVIEW", "medium", "Версії активних пакетів відрізняються", mismatched)

    def users(self):
        rows = self.table("users")
        if rows is None:
            return
        if not rows or any(not isinstance(x.get("name"), str) for x in rows):
            self.add("USERS", "UNKNOWN", "info", "Список користувачів неповний або некоректний")
            return
        groups = self.table("groups")
        for row in rows:
            name, disabled = row["name"], boolean(row.get("disabled"))
            if disabled is True:
                continue
            if disabled is None:
                self.add("USER-STATE", "UNKNOWN", "info", "Невідомий стан користувача", {"name": name})
                continue
            if name == "admin":
                self.add("DEFAULT-ADMIN", "HARDENING", "low", "Активний стандартний admin", {"name": name},
                         "Використовувати персональний обліковий запис; перед вимкненням admin перевірити альтернативний доступ.", USER_DOC)
            if name == "ops":
                self.add("IOC-OPS", "REVIEW", "medium", "Ім’я ops збігається з опублікованим індикатором",
                         {"name": name}, "Звірити власника й походження: саме ім’я не доводить злому.", INCIDENT)
            self.add("USER-ACL", "REVIEW" if self.scope(row.get("address")) != "TRUSTED_ONLY" else "PASS",
                     "info", "Обмеження адрес входу користувача",
                     {"name": name, "group": row.get("group"), "scope": self.scope(row.get("address"))},
                     "Звірити доступ і права з переліком дозволених адміністраторів.", USER_DOC)
            if groups is None or not any(g.get("name") == row.get("group") for g in groups):
                self.add("USER-GROUP", "UNKNOWN", "info", "Права групи користувача не визначено", {"name": name}, source=USER_DOC)
        for group in groups or []:
            policies = set(words(group.get("policy")))
            dangerous = policies & {"write", "policy", "reboot", "sensitive", "sniff", "test", "ftp"}
            if dangerous:
                self.add("GROUP-CAPABILITIES", "REVIEW", "info", "Привілейовані можливості групи",
                         {"group": group.get("name"), "capabilities": sorted(dangerous)},
                         "Мінімальні права аудитора перевіряються фактично; стандартна група read не є строго read-only.", USER_DOC)

    def services(self):
        rows = self.table("services")
        if rows is None:
            return
        if not rows:
            self.add("SERVICES-EMPTY", "UNKNOWN", "info", "Порожній список IP Services")
        for row in rows:
            name = row.get("name")
            if boolean(row.get("dynamic")) is True:
                continue
            enabled = boolean(row.get("disabled"))
            if not isinstance(name, str) or enabled is None:
                self.add("SERVICE-STATE", "UNKNOWN", "info", "Неповні дані служби", {"name": name})
                continue
            if enabled:
                self.add("SERVICE-DISABLED", "PASS", "info", "Службу вимкнено", {"name": name})
                continue
            evidence = {"name": name, "port": row.get("port"), "vrf": row.get("vrf"),
                        "address": row.get("address"), "scope": self.scope(row.get("address"))}
            if name in {"telnet", "ftp", "www", "api"}:
                self.add("PLAINTEXT-SERVICE", "MISCONFIGURATION", "medium", "Увімкнено незашифрований сервіс",
                         evidence, "Вимкнути, якщо не потрібен; використовувати захищений канал керування.", SERVICES_DOC)
            if evidence["scope"] in {"UNRESTRICTED", "OUTSIDE_TRUSTED"}:
                self.add("SERVICE-ACL", "POTENTIAL_EXPOSURE", "medium", "ACL сервісу не обмежений лише довіреними мережами",
                         evidence, "Перевірити IPv4/IPv6 input firewall; ACL сервісу не замінює firewall.", SERVICES_DOC)
            elif evidence["scope"] in {"UNKNOWN", "RESTRICTED_UNVERIFIED"}:
                self.add("SERVICE-ACL", "UNKNOWN", "info", "Довіреність ACL сервісу не підтверджено", evidence, source=SERVICES_DOC)
            if name in {"www-ssl", "api-ssl"}:
                certificate = row.get("certificate")
                self.add("TLS-CERTIFICATE", "UNKNOWN" if certificate is None else
                         ("MISCONFIGURATION" if certificate in ("", "none") else "REVIEW"),
                         "medium", "Налаштування сертифіката TLS", {"service": name, "certificate": certificate},
                         "Наявність імені сертифіката не підтверджує його чинності, довіри або коректного TLS handshake.", SERVICES_DOC)
            self.service_firewall(row)

    def service_firewall(self, row):
        try:
            if type(row["port"]) not in (int, str):
                raise ValueError
            port = int(row["port"])
            if not 1 <= port <= 65535:
                raise ValueError
        except (KeyError, ValueError, TypeError):
            self.add("SERVICE-PORT", "UNKNOWN", "info", "Не визначено TCP-порт сервісу", {"name": row.get("name")})
            return
        for interface in sorted(self.untrusted):
            for family in (4, 6):
                result, reason = self.firewall(family, interface, "tcp", port)
                self.add("SERVICE-INPUT", "POTENTIAL_EXPOSURE" if result == "POSSIBLE" else
                         ("CONFIGURED_BLOCK" if result == "BLOCK" else "UNKNOWN"),
                         "medium" if result == "POSSIBLE" else "info", "Статична оцінка input firewall",
                         {"service": row["name"], "port": port, "ip_version": family,
                          "interface": interface, "result": result, "reason": reason},
                         "Оцінка лише нових пакетів до цього локального порту; не доводить доступності з Інтернету.", SERVICES_DOC)

    def firewall(self, family, interface, protocol, port):
        """Tri-state, intentionally incomplete input-chain analysis.

        Unknown matchers may match OR not match. Unknown control flow stops
        analysis. An uncertain earlier accept can never be hidden by later drop.
        No NAT/raw/routing/topology simulation and no claim of WAN reachability.
        """
        rows = self.table(f"ipv{family}_filter")
        known = self.table("interfaces")
        if rows is None or known is None or interface not in {x.get("name") for x in known}:
            return "UNKNOWN", "Немає firewall або підтвердженого інтерфейсу"
        uncertain_accept = False
        for index, row in enumerate(rows):
            if not isinstance(row.get("chain"), str) or not row["chain"]:
                return "UNKNOWN", f"firewall #{index}: не визначено chain"
            if row.get("chain") != "input":
                continue
            if boolean(row.get("disabled")) is True or boolean(row.get("invalid")) is True:
                continue
            match = self.match_rule(row, interface, protocol, port)
            if match is False:
                continue
            if (boolean(row.get("disabled")) is None or
                    ("invalid" in row and boolean(row["invalid"]) is None)):
                match = None
            action = row.get("action")
            if action in {"log", "passthrough"}:
                continue
            if action == "accept":
                if match is True:
                    return "POSSIBLE", f"input #{index}: accept; попередні умовні правила можуть звужувати доступ"
                uncertain_accept = True
            elif action in {"drop", "reject"}:
                if match is True:
                    return ("POSSIBLE", "Перед блокуванням є умовний accept") if uncertain_accept else (
                        "BLOCK", f"input #{index}: завершальне блокування для заданого порту/інтерфейсу")
            else:
                return "UNKNOWN", f"input #{index}: неврахована дія або перехід {safe_text(action)}"
        return "POSSIBLE", "Можливий вихід із input без завершального блокування (implicit accept)"

    def match_rule(self, row, interface, protocol, port):
        outcomes = []
        ignored = {"_schema", ".id", "chain", "action", "disabled", "invalid", "dynamic", "log",
                   "log-prefix", "comment", "bytes", "packets", "reject-with"}
        for key, value in row.items():
            if key in ignored or value is None or value == "" or value == []:
                continue
            if key == "protocol":
                text = str(value)
                negative = text.startswith("!")
                text = text.lstrip("!")
                outcome = text in {protocol, {"tcp": "6", "udp": "17"}[protocol]}
                if text == "all":
                    outcome = True
                elif not text.isdigit() and text not in {"tcp", "udp", "icmp", "icmpv6", "ipv6-icmp", "gre", "ipsec-esp", "ipsec-ah"}:
                    outcome = None
                outcomes.append((not outcome if negative else outcome) if outcome is not None else None)
            elif key == "in-interface":
                if not isinstance(value, str):
                    outcomes.append(None)
                else:
                    outcomes.append(interface != value[1:] if value.startswith("!") else interface == value)
            elif key == "in-interface-list":
                members = self.list_members(value)
                outcomes.append(None if members is None else interface in members)
            elif key == "dst-port":
                outcomes.append(port_match(value, port))
            elif key == "connection-state":
                values = words(value)
                known_states = {"new", "established", "related", "invalid", "untracked"}
                outcomes.append("new" in values if values and set(values).issubset(known_states) else None)
            else:
                # src-address/list, dst-address, connection-nat-state, time,
                # limit, marks, tcp-flags, ipsec-policy, unknown future fields.
                outcomes.append(None)
        if False in outcomes:
            return False
        if None in outcomes:
            return None
        return True

    def layer2(self):
        bridges = self.table("bridge_ports")
        for section, field in (("mac_winbox", "allowed-interface-list"),
                               ("mac_telnet", "allowed-interface-list"),
                               ("neighbor", "discover-interface-list")):
            name = self.field(section, field)
            members = self.list_members(name)
            if members is None:
                self.add("L2-SCOPE", "UNKNOWN", "info", "Не визначено інтерфейси L2-сервісу", {"service": section, "list": name})
                continue
            if not members:
                self.add("L2-SCOPE", "PASS", "info", "L2-сервіс не має дозволених інтерфейсів", {"service": section})
                continue
            expanded = set(members)
            # Bridge master may expose its members. Report potential only;
            # VLAN/switch ACL/bonding topology is intentionally not simulated.
            for _ in range(16):
                newer = expanded | {x.get("interface") for x in bridges or []
                                    if x.get("bridge") in expanded and boolean(x.get("disabled")) is not True}
                if newer == expanded:
                    break
                expanded = newer
            exposed = sorted((expanded - {None}) & self.untrusted)
            self.add("L2-SCOPE", "POTENTIAL_EXPOSURE" if exposed else "REVIEW",
                     "medium" if exposed else "info", "Область роботи L2-сервісу",
                     {"service": section, "list": name, "members": sorted(members), "untrusted_overlap": exposed},
                     "Звірити довірені VLAN, bridge/bonding та switch ACL. Відсутність перетину не є доказом ізоляції.")

    def configuration(self):
        remote_dns = boolean(self.field("dns", "allow-remote-requests"))
        self.add("DNS-RECURSION", "PASS" if remote_dns is False else ("REVIEW" if remote_dns else "UNKNOWN"),
                 "info", "DNS-запити до роутера", {"allow-remote-requests": remote_dns},
                 "Для LAN DNS це нормальна функція; не допускати рекурсію для недовірених клієнтів.")
        if remote_dns:
            for interface in sorted(self.untrusted):
                for family in (4, 6):
                    for protocol in ("udp", "tcp"):
                        state, reason = self.firewall(family, interface, protocol, 53)
                        self.add("DNS-INPUT", "POTENTIAL_EXPOSURE" if state == "POSSIBLE" else
                                 ("CONFIGURED_BLOCK" if state == "BLOCK" else "UNKNOWN"), "medium",
                                 "Доступ до DNS за input firewall", {"interface": interface, "ip_version": family,
                                 "protocol": protocol, "reason": reason}, "Відкритий resolver/ампліфікацію активними запитами не перевірено.")
        doh = boolean(self.field("dns", "doh-configured"))
        if doh is True:
            verified = boolean(self.field("dns", "verify-doh-cert"))
            self.add("DOH-CERT", "PASS" if verified else ("MISCONFIGURATION" if verified is False else "UNKNOWN"),
                     "medium", "Перевірка сертифіката DoH", {"verify-doh-cert": verified}, "Увімкнути перевірку сертифіката DoH.")
        for section in ("mac_ping", "bandwidth", "socks", "proxy", "upnp", "romon", "snmp", "smb"):
            enabled = boolean(self.field(section, "enabled"))
            self.add("OPTIONAL-SERVICE", "PASS" if enabled is False else ("REVIEW" if enabled else "UNKNOWN"),
                     "info", "Додаткова служба", {"service": section, "enabled": self.field(section, "enabled")},
                     "Якщо потрібна — перевірити ACL/сегментацію; сам факт увімкнення не є CVE.")
        if boolean(self.field("bandwidth", "enabled")) is True:
            auth = boolean(self.field("bandwidth", "authenticate"))
            if auth is not True:
                self.add("BTEST-AUTH", "MISCONFIGURATION" if auth is False else "UNKNOWN", "high",
                         "Автентифікація bandwidth-server", {"authenticate": auth}, "Вимкнути непотрібний bandwidth-server.")
        strong = boolean(self.field("ssh", "strong-crypto"))
        self.add("SSH-CRYPTO", "PASS" if strong else ("HARDENING" if strong is False else "UNKNOWN"), "medium",
                 "Профіль SSH strong-crypto", {"strong-crypto": strong},
                 "Перевірити сумісність і ввімкнути сильний криптографічний профіль; це не перевірка всіх negotiated algorithms.")
        forwarding = self.field("ssh", "forwarding-enabled")
        if forwarding not in (None, "no"):
            self.add("SSH-FORWARD", "REVIEW", "medium", "Дозволений SSH forwarding", {"forwarding-enabled": forwarding})
        if boolean(self.field("snmp", "enabled")) is True:
            for row in self.table("snmp_communities") or []:
                if row.get("security") != "private" or boolean(row.get("write-access")) is True:
                    self.add("SNMP-ACCESS", "REVIEW", "medium", "Перевірити SNMP захист/запис",
                             {"security": row.get("security"), "write-access": row.get("write-access"),
                              "scope": self.scope(row.get("addresses"))}, "Для SNMPv3 перевірити authPriv та мінімальні ACL.")

    def compromise(self):
        flagged = boolean(self.field("device_mode", "flagged"))
        self.add("DEVICE-FLAGGED", "INDICATOR" if flagged else ("OBSERVED" if flagged is False else "UNKNOWN"),
                 "high" if flagged else "info", "Device-mode flagged",
                 {"flagged": flagged, "flagging-enabled": self.field("device_mode", "flagging-enabled")},
                 "flagged=no не доводить відсутності компрометації. За flagged=yes зберегти докази й розслідувати; скрипт нічого не скидає.", INCIDENT)
        if boolean(self.field("device_mode", "flagging-enabled")) is False:
            self.add("FLAGGING-DISABLED", "HARDENING", "medium", "Вбудовану перевірку підозрілої конфігурації вимкнено", source=INCIDENT)
        for section in ("scripts", "scheduler", "netwatch"):
            rows = self.table(section)
            if rows:
                hints = [{"name": x.get("name"), "disabled": x.get("disabled"),
                          "fetch-hint": x.get("fetch-hint"), "url-hint": x.get("url-hint")}
                         for x in rows if boolean(x.get("disabled")) is not True]
                if hints:
                    self.add("AUTOMATION-REVIEW", "REVIEW", "info", "Автоматизації потребують звірки з довіреною конфігурацією",
                             {"section": section, "active_or_unknown": len(hints), "examples": hints[:20]},
                             "Не запускати. Тіла скриптів не передаються; відсутність підрядка fetch не доводить безпеки.", INCIDENT)
        logs = self.table("logs")
        if logs is not None:
            matches = [x for x in logs if any(boolean(x.get(k)) is True
                       for k in ("flagged-hint", "login-hint", "creation-hint"))]
            self.add("LOG-INDICATORS", "INDICATOR" if matches else "OBSERVED", "high" if matches else "info",
                     "Індикатори в поточному буфері журналу", {"matching_entries": len(matches)},
                     "Збіг потребує розслідування. Відсутність збігів не виключає атаки, очищення журналів чи ротації.", INCIDENT)

    def run(self, today=None, offline=False):
        today = today or datetime.now(timezone.utc).date()
        self.versions()
        for key in SECTIONS:
            if self.table(key) is None:
                self.add("COLLECTION", "UNKNOWN", "info", "Розділ не перевірено",
                         {"section": key, "reason": self.snapshot["errors"].get(key, "Дані відсутні")},
                         "Перевірити права, підтримку команди та ліміти. Не надавати full автоматично.")
        for key, error in self.snapshot["errors"].items():
            if key not in SECTIONS:
                self.add("COLLECTION", "UNKNOWN", "info", "Обмеження збору даних", {"section": key, "reason": safe_text(error)})
        if self.untrusted:
            known = {x.get("name") for x in self.table("interfaces") or []}
            for missing in sorted(self.untrusted - known):
                self.add("INTERFACE-NOT-FOUND", "UNKNOWN", "info", "Недовірений інтерфейс не підтверджено", {"name": missing})
        else:
            self.add("UNTRUSTED-SCOPE", "UNKNOWN", "info", "Недовірені інтерфейси не задано",
                     recommendation="--untrusted-interface задає реальний інтерфейс, а не назву interface list. WAN не вгадується.")
        self.users()
        self.services()
        self.layer2()
        self.configuration()
        self.compromise()
        self.add("COVERAGE-LIMIT", "UNKNOWN", "info", "Непокриті перевірки",
                 ["CVE, яких ще немає в локальному каталозі", "фактична доступність з Інтернету",
                  "NAT/raw/mangle, маршрути, upstream ACL, VRF і повна VLAN/bonding топологія",
                  "слабкі паролі, TLS handshake/ланцюжки сертифікатів, повний аналіз скриптів",
                  "приховані/видалені сліди компрометації та цілісність бінарних файлів",
                  "Wi-Fi/VPN/RADIUS/tunnel-політики, IPv6 ND/RA, відкладене застосування disable-ipv6",
                  "бета/rc поза діапазоном і поза явним правилом 7.25.0 дає UNKNOWN, не PASS",
                  "CVE без меж версій у NVD"],
                 "PASS стосується лише конкретного правила, не пристрою загалом.")
        updated_at = self.catalog.get("updated_at")
        age = _catalog_age(updated_at, today)
        self.add("CATALOG", "UNKNOWN" if age is None or age > 7 or age < 0 or self.catalog_note else "OBSERVED",
                 "info", "Локальний каталог CVE",
                 {"updated_at": updated_at, "age_days": age,
                  "count": len(self.catalog.get("cves", [])),
                  "path": str(default_catalog_path()), "update_error": self.catalog_note},
                 "Файл лежить поруч зі скриптом. Онлайн-аудит оновлює його з NVD, коли вік більший за тиждень.",
                 CERT)
        counts = dict(Counter(x["status"] for x in self.findings))
        actionable = {"VULNERABLE_VERSION", "MISCONFIGURATION", "POTENTIAL_EXPOSURE", "INDICATOR"}
        exit_code = (1 if any(x["status"] in actionable for x in self.findings) else 0)
        if counts.get("UNKNOWN"):
            exit_code |= 2
        return {"schema": 1, "tool_version": VERSION, "generated_at": datetime.now(timezone.utc).isoformat(),
                "target": self.snapshot.get("host", "unknown"), "source": "offline_unverified" if offline else "ssh_host_key_verified",
                "collected_at": self.snapshot.get("collected_at"), "routeros_version": self.snapshot.get("routeros_version"),
                "read_only": True, "no_exploits": True, "counts": counts, "exit_code": exit_code,
                "verdict": "PARTIAL_WITH_FINDINGS" if exit_code & 1 else "PARTIAL_NO_CONFIRMED_FINDINGS",
                "cve_catalog_updated_at": self.catalog.get("updated_at"),
                "cve_catalog_count": len(self.catalog.get("cves", [])),
                "cve_catalog_path": str(default_catalog_path()),
                "findings": self.findings}


def _catalog_age(updated_at, today):
    """Whole days from the catalog timestamp to ``today``. None if the stamp is unusable."""
    if not isinstance(updated_at, str):
        return None
    try:
        stamp = datetime.fromisoformat(updated_at)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        return None
    return (today - stamp.astimezone(timezone.utc).date()).days


def port_match(value, port):
    values = words(value)
    if not values:
        return None
    try:
        found = False
        for item in values:
            if not re.fullmatch(r"\d+(?:-\d+)?", item):
                return None
            parts = item.split("-")
            lo, hi = int(parts[0]), int(parts[-1])
            if not 1 <= lo <= hi <= 65535:
                return None
            found |= lo <= port <= hi
        return found
    except (ValueError, TypeError):
        return None


def write_private(path, value):
    """Create only, no overwrite/symlink following. File contains network metadata."""
    payload = (json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def console_report(report):
    print(f"MikroTik Audit {VERSION} | {safe_text(report['target'])} | RouterOS {safe_text(report['routeros_version'])}")
    print("Лише читання. Без експлойтів. Повну відсутність вразливостей не підтверджує.")
    print("Каталог CVE: " + str(report.get("cve_catalog_count"))
          + " | " + safe_text(report.get("cve_catalog_updated_at"))
          + " | " + safe_text(report.get("cve_catalog_path")))
    print("Джерело: " + report["source"])
    for finding in report["findings"]:
        if finding["status"] in {"PASS", "OBSERVED", "NOT_APPLICABLE"}:
            continue
        print(f"[{finding['status']}/{finding['severity']}] {finding['id']}: {finding['title']}")
        if finding["evidence"] is not None:
            print("  " + safe_text(json.dumps(finding["evidence"], ensure_ascii=False), 600))
    print("Підсумок: " + json.dumps(report["counts"], sort_keys=True))
    print(f"Результат: {report['verdict']}; exit={report['exit_code']} (bit 1: знахідки, bit 2: неповне покриття)")


def parser():
    result = argparse.ArgumentParser(description="Read-only аудит MikroTik: версії, конфігурація, потенційні ризики. Без експлойтів.")
    target = result.add_mutually_exclusive_group(required=False)
    target.add_argument("--host", help="Один IP/FQDN власного маршрутизатора")
    target.add_argument("--offline", metavar="SNAPSHOT.json", help="Перевірити раніше зібрані дані без мережі")
    result.add_argument("--user", help="Обліковий запис RouterOS з мінімальними потрібними правами")
    result.add_argument("--port", type=int, default=22)
    authentication = result.add_mutually_exclusive_group()
    authentication.add_argument("--identity", help="Приватний ключ; зашифрований ключ попередньо додати в ssh-agent")
    authentication.add_argument("--ask-password", action="store_true", help="Пароль запитує OpenSSH через термінал; не CLI/файл")
    result.add_argument("--known-hosts", help="Попередньо перевірений known_hosts (без автодовіри)")
    result.add_argument("--untrusted-interface", action="append", default=[], help="WAN/guest інтерфейс, повторюваний параметр")
    result.add_argument("--trusted-network", action="append", default=[], help="Довірений management CIDR IPv4/IPv6, повторюваний")
    result.add_argument("--timeout", type=int, default=120, help="Загальний бюджет двох SSH-команд, секунди (15..600)")
    result.add_argument("--max-rows", type=int, default=MAX_ROWS, help="Ліміт записів на таблицю (1..1000)")
    result.add_argument("--update-cve", action="store_true",
                        help="Оновити cve_catalog.json поруч зі скриптом з NVD. Без --host лише записує каталог")
    result.add_argument("--no-cve-update", action="store_true",
                        help="Не оновлювати локальний каталог CVE під час аудиту")
    result.add_argument("--cve-max-age", type=int, default=7,
                        help="Оновити каталог, якщо він старший за N днів; 0 оновлює щоразу (0..365)")
    result.add_argument("--report", metavar="NEW.json", help="Новий JSON-звіт; наявні файли не перезаписуються")
    result.add_argument("--snapshot", metavar="NEW.json", help="Зберегти санітизовані дані для offline-аудиту")
    result.add_argument("--version", action="version", version=VERSION)
    return result


def prepare_catalog(args):
    """Refresh the sibling catalog when requested or stale, then load it.

    A failed refresh keeps the previous file. The returned note is shown to the
    operator and forces the CATALOG finding to UNKNOWN.
    """
    path = default_catalog_path()
    note = None
    should_update = args.update_cve or (
        bool(args.host) and not args.no_cve_update and catalog_is_stale(path, args.cve_max_age)
    )
    if should_update:
        try:
            update_catalog(path)
        except (CatalogError, OSError) as exc:
            note = safe_text(exc)
    catalog, load_note = load_catalog(path)
    return catalog, note or load_note


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    if args.update_cve and args.no_cve_update:
        cli.error("--update-cve і --no-cve-update разом не використовуються")
    if args.offline and args.update_cve:
        cli.error("Оновлення CVE не виконується разом з --offline")
    if not args.host and not args.offline and not args.update_cve:
        cli.error("Потрібні --host, --offline або --update-cve")
    if not args.host and not args.offline and (args.report or args.snapshot or args.untrusted_interface or args.trusted_network):
        cli.error("Параметри аудиту доступні лише разом з --host або --offline")
    if args.host and (not valid_host(args.host) or not args.user or
                      not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.#@-]*[A-Za-z0-9])?", args.user)):
        cli.error("Потрібні коректні --host і --user; керівні символи та RouterOS login modifiers не дозволені")
    if not 1 <= args.port <= 65535 or not 15 <= args.timeout <= 600 or not 1 <= args.max_rows <= MAX_ROWS:
        cli.error("Некоректний порт/таймаут/ліміт")
    if not 0 <= args.cve_max_age <= 365:
        cli.error("Некоректний --cve-max-age")
    if args.offline and (args.user or args.identity or args.ask_password or args.known_hosts):
        cli.error("SSH-параметри не використовуються в offline-режимі")
    if any(not x or len(x) > 128 or any(unicodedata.category(c).startswith("C") for c in x)
           for x in args.untrusted_interface):
        cli.error("Некоректна назва інтерфейсу")
    try:
        for network in args.trusted_network:
            ipaddress.ip_network(network, strict=False)
        outputs = [Path(p).expanduser().resolve() for p in (args.report, args.snapshot) if p]
        if len(set(outputs)) != len(outputs):
            raise AuditError("Звіт і snapshot мають бути різними файлами")
        for path in outputs:
            if path.exists():
                raise AuditError("Файл уже існує: " + str(path))
        catalog, catalog_note = prepare_catalog(args)
        if not args.host and not args.offline:
            if catalog_note:
                print("[ERROR] " + catalog_note + ". Каталог не змінено.", file=sys.stderr)
                return 2
            print("Каталог CVE збережено: " + str(default_catalog_path())
                  + " (" + str(len(catalog["cves"])) + " записів, " + str(catalog["updated_at"]) + ")")
            return 0
        if catalog_note:
            if catalog.get("source", {}).get("name") == "embedded":
                print("[WARN] Каталог CVE недоступний: " + catalog_note
                      + ". Використано вбудовану підлогу бюлетеня 2026-10-06.", file=sys.stderr)
            else:
                print("[WARN] Каталог CVE не оновлено: " + catalog_note
                      + ". Використано збережену копію.", file=sys.stderr)
        snapshot = read_snapshot(args.offline) if args.offline else collect(args)
        report = Checks(snapshot, args.untrusted_interface, args.trusted_network,
                        catalog=catalog, catalog_note=catalog_note).run(offline=bool(args.offline))
        report["snapshot_sha256"] = hashlib.sha256(json.dumps(snapshot, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
        if args.snapshot:
            write_private(Path(args.snapshot).expanduser(), snapshot)
        if args.report:
            write_private(Path(args.report).expanduser(), report)
        console_report(report)
        return report["exit_code"]
    except (AuditError, CatalogError, OSError, ValueError) as exc:
        print("[ERROR] " + safe_text(exc) + ". Аудит не підтверджено.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[ERROR] Аудит перервано; відсутність вразливостей не підтверджено.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
