"""Tests for Investigation Agent feature expansion.

Capabilities tested:
  A. Authentication investigation
  B. Cross-event correlation / EvidenceRelationship
  C. ActivityChain
  D. MITRE ATT&CK mapping
  E. IOC extraction
  F. Investigation coverage reporting
  G. Adaptive loop integration
  H. Safety
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from aegis_core.investigation.agent import InvestigationAgent
from aegis_core.investigation.result import (
    ActivityChainStep,
    AttackTechnique,
    Classification,
    EvidenceRelationship,
    IOC,
    InvestigationCoverage,
    InvestigationResult,
    InvestigationStatus,
)
from aegis_core.investigation.state import InvestigationBudget
from aegis_core.investigation.tools import InvestigationTools
from aegis_core.models import Event, EventKind
from aegis_core.storage import EvidenceStore
from aegis_core.triage import InvestigationCase, TriageEngine

_UTC = timezone.utc


def _ts(offset: float = 0.0) -> datetime:
    return datetime(2026, 6, 1, 9, 0, 0, tzinfo=_UTC) + timedelta(seconds=offset)


def _proc(pid, name, ppid=None, action="start", user=None, offset=0.0,
          exe=None, cmdline=None):
    data = {"pid": pid, "name": name, "action": action}
    if ppid is not None:
        data["ppid"] = ppid
    if user:
        data["user"] = user
    if exe:
        data["exe"] = exe
    if cmdline:
        data["cmdline"] = cmdline
    return Event(kind=EventKind.PROCESS, source="fixture", data=data,
                 observed_at=_ts(offset), host_id="test-host")


def _file(path, action="create", pid=None, suffix=".txt", offset=0.0):
    data = {"path": path, "action": action, "suffix": suffix}
    if pid is not None:
        data["pid"] = pid
    return Event(kind=EventKind.FILE, source="fixture", data=data,
                 observed_at=_ts(offset), host_id="test-host")


def _net(remote_ip, remote_port=443, pid=None, action="connection_open",
         direction="outbound", offset=0.0):
    data = {"remote_ip": remote_ip, "remote_port": remote_port,
            "action": action, "direction": direction}
    if pid is not None:
        data["pid"] = pid
    return Event(kind=EventKind.NETWORK, source="fixture", data=data,
                 observed_at=_ts(offset), host_id="test-host")


def _auth(action, user, source_ip="", mechanism="password", offset=0.0):
    data = {"action": action, "user": user, "auth_mechanism": mechanism}
    if source_ip:
        data["source_ip"] = source_ip
    return Event(kind=EventKind.AUTHENTICATION, source="fixture", data=data,
                 observed_at=_ts(offset), host_id="test-host")


def _dns(query_name, pid=None, offset=0.0):
    data = {"action": "dns_query", "query_name": query_name}
    if pid is not None:
        data["pid"] = pid
    return Event(kind=EventKind.NETWORK, source="fixture", data=data,
                 observed_at=_ts(offset), host_id="test-host")


def _make_store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.sqlite3")


def _make_case(store, events, trigger=None, signals=None):
    for ev in events:
        store.append_event(ev)
    trig = trigger or events[0]
    triage = TriageEngine(case_threshold=0.0)
    finding = {
        "rule_id": "TEST-FEAT-001", "severity": "high", "confidence": 0.9,
        "evidence_event_ids": [trig.event_id], "explanation": "Feature test",
        "recommendation": "Review", "run_id": "feat-test",
    }
    if signals:
        finding["detection_signals"] = signals
    case_events = [ev.canonical() for ev in events]
    case = triage.create_case(finding, case_events, host_id="test-host",
                              hostname="test-host")
    store.append_case(case)
    return case


def _run(store, case, max_calls=30):
    budget = InvestigationBudget(max_tool_calls=max_calls,
                                 max_investigation_time_seconds=60.0)
    agent = InvestigationAgent(store, budget=budget)
    return agent.investigate(case.case_id)


# ===========================================================================
# A. Authentication investigation
# ===========================================================================

class TestAuthInvestigation:
    def test_auth_success_appears_in_result(self, tmp_path):
        store = _make_store(tmp_path)
        auth = _auth("login_success", "alice", source_ip="192.168.1.10", offset=0)
        proc = _proc(1000, "powershell.exe", ppid=4, user="alice", offset=1)
        case = _make_case(store, [proc, auth], trigger=proc)
        result = _run(store, case)
        assert isinstance(result, InvestigationResult)
        assert result.authentication_activity
        actions = [r["action"] for r in result.authentication_activity]
        assert "login_success" in actions

    def test_auth_failure_in_evidence(self, tmp_path):
        store = _make_store(tmp_path)
        auth = _auth("login_failure", "bob", offset=0)
        proc = _proc(2000, "cmd.exe", ppid=4, offset=1)
        case = _make_case(store, [proc, auth], trigger=proc)
        result = _run(store, case)
        assert auth.event_id in result.evidence_ids_used

    def test_unavailable_auth_recorded_as_uncertainty(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(3000, "svchost.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        assert result.investigation_coverage.authentication_covered is True
        auth_uncertain = any("authentication" in u.lower() for u in result.uncertainties)
        assert auth_uncertain, f"Got: {result.uncertainties}"

    def test_auth_user_preserved(self, tmp_path):
        store = _make_store(tmp_path)
        auth = _auth("login_success", "carol", offset=0)
        proc = _proc(4000, "explorer.exe", ppid=4, user="carol", offset=1)
        case = _make_case(store, [proc, auth], trigger=proc)
        result = _run(store, case)
        users = [r["user"] for r in result.authentication_activity]
        assert "carol" in users

    def test_auth_coverage_flag_set(self, tmp_path):
        store = _make_store(tmp_path)
        auth = _auth("login_success", "dave", offset=0)
        proc = _proc(5000, "notepad.exe", ppid=4, offset=1)
        case = _make_case(store, [proc, auth], trigger=proc)
        result = _run(store, case)
        assert result.investigation_coverage.authentication_covered is True


# ===========================================================================
# B. Cross-event correlation / EvidenceRelationship
# ===========================================================================

class TestEvidenceRelationships:
    def test_parent_child_relationship_extracted(self, tmp_path):
        store = _make_store(tmp_path)
        parent = _proc(100, "WINWORD.EXE", ppid=4, offset=0)
        child = _proc(200, "powershell.exe", ppid=100, offset=1)
        case = _make_case(store, [parent, child], trigger=child)
        result = _run(store, case)
        rel_types = [r.relationship_type for r in result.relationships]
        assert "parent_process" in rel_types, f"Got: {rel_types}"

    def test_parent_child_entities_correct(self, tmp_path):
        store = _make_store(tmp_path)
        parent = _proc(100, "WINWORD.EXE", ppid=4, offset=0)
        child = _proc(200, "powershell.exe", ppid=100, offset=1)
        case = _make_case(store, [parent, child], trigger=child)
        result = _run(store, case)
        parent_rels = [r for r in result.relationships
                       if r.relationship_type == "parent_process"]
        assert any("100" in r.from_entity for r in parent_rels)
        assert any("200" in r.to_entity for r in parent_rels)

    def test_process_file_relationship(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(300, "powershell.exe", ppid=4, offset=0)
        f = _file("/tmp/malware.exe", pid=300, suffix=".exe", offset=1)
        case = _make_case(store, [proc, f], trigger=proc)
        result = _run(store, case)
        rel_types = [r.relationship_type for r in result.relationships]
        assert "process_file" in rel_types, f"Got: {rel_types}"

    def test_process_network_relationship(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(400, "powershell.exe", ppid=4, offset=0)
        net = _net("10.0.0.1", 4444, pid=400, offset=1)
        case = _make_case(store, [proc, net], trigger=proc)
        result = _run(store, case)
        rel_types = [r.relationship_type for r in result.relationships]
        assert "process_network" in rel_types, f"Got: {rel_types}"

    def test_relationships_have_evidence_ids(self, tmp_path):
        store = _make_store(tmp_path)
        parent = _proc(500, "word.exe", ppid=4, offset=0)
        child = _proc(600, "cmd.exe", ppid=500, offset=1)
        case = _make_case(store, [parent, child], trigger=child)
        result = _run(store, case)
        for rel in result.relationships:
            assert rel.evidence_event_ids
            assert rel.structural_basis

    def test_unrelated_events_not_falsely_correlated(self, tmp_path):
        store = _make_store(tmp_path)
        proc_a = _proc(700, "explorer.exe", ppid=4, offset=0)
        proc_b = _proc(800, "notepad.exe", ppid=4, offset=5)
        case = _make_case(store, [proc_a, proc_b], trigger=proc_a)
        result = _run(store, case)
        false_rels = [r for r in result.relationships
                      if r.relationship_type == "parent_process"
                      and "700" in r.from_entity and "800" in r.to_entity]
        assert not false_rels


# ===========================================================================
# C. Activity chain
# ===========================================================================

class TestActivityChain:
    def test_chain_ordered_chronologically(self, tmp_path):
        store = _make_store(tmp_path)
        e0 = _proc(100, "WINWORD.EXE", ppid=4, offset=0)
        e1 = _proc(200, "powershell.exe", ppid=100, offset=2)
        e2 = _file("/tmp/drop.exe", pid=200, suffix=".exe", offset=4)
        e3 = _net("185.10.10.1", 4444, pid=200, offset=6)
        case = _make_case(store, [e0, e1, e2, e3], trigger=e1)
        result = _run(store, case)
        assert len(result.activity_chain) > 0
        timestamps = [s.timestamp for s in result.activity_chain]
        assert timestamps == sorted(timestamps)

    def test_chain_references_real_event_ids(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "cmd.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        for step in result.activity_chain:
            assert step.event_id
            assert step.event_id in result.evidence_ids_used

    def test_chain_step_fields_populated(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        for step in result.activity_chain:
            assert isinstance(step.step_index, int)
            assert step.description
            assert step.timestamp
            assert step.entity

    def test_uncertain_steps_are_bool(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "explorer.exe", ppid=4, offset=0)
        net = _net("1.2.3.4", 80, pid=None, offset=5)
        case = _make_case(store, [proc, net], trigger=proc)
        result = _run(store, case)
        for step in result.activity_chain:
            assert isinstance(step.is_uncertain, bool)

    def test_empty_chain_safe_on_tight_budget(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "svchost.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        budget = InvestigationBudget(max_tool_calls=2,
                                     max_investigation_time_seconds=5.0)
        agent = InvestigationAgent(store, budget=budget)
        result = agent.investigate(case.case_id)
        assert isinstance(result.activity_chain, list)


# ===========================================================================
# D. MITRE ATT&CK mapping
# ===========================================================================

class TestMITREMapping:
    def test_powershell_maps_to_T1059_001(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4,
                     exe="C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                     cmdline="powershell.exe -enc JABz...", offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        technique_ids = [t.technique_id for t in result.attack_techniques]
        assert "T1059.001" in technique_ids, f"Got: {technique_ids}"

    def test_powershell_evidence_ids_present(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        ps = [t for t in result.attack_techniques if t.technique_id == "T1059.001"]
        assert ps
        for t in ps:
            assert t.evidence_ids
            assert 0.0 <= t.confidence <= 1.0

    def test_encoded_ps_has_higher_confidence(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4,
                     cmdline="powershell -enc JABzAA==", offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        ps = next((t for t in result.attack_techniques
                   if t.technique_id == "T1059.001"), None)
        assert ps is not None
        assert ps.confidence >= 0.80

    def test_exe_file_drop_maps_to_T1105(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        f = _file("/tmp/update.exe", action="create", pid=100,
                  suffix=".exe", offset=1)
        case = _make_case(store, [proc, f], trigger=proc)
        result = _run(store, case)
        technique_ids = [t.technique_id for t in result.attack_techniques]
        assert "T1105" in technique_ids, f"Got: {technique_ids}"

    def test_office_child_maps_to_T1566(self, tmp_path):
        store = _make_store(tmp_path)
        word = _proc(1234, "WINWORD.EXE", ppid=4, offset=0)
        ps = _proc(5678, "powershell.exe", ppid=1234, offset=1)
        case = _make_case(store, [word, ps], trigger=ps)
        result = _run(store, case)
        technique_ids = [t.technique_id for t in result.attack_techniques]
        assert "T1566" in technique_ids, f"Got: {technique_ids}"

    def test_brute_force_maps_to_T1110(self, tmp_path):
        store = _make_store(tmp_path)
        auth_fails = [_auth("login_failure", "admin", offset=float(i))
                      for i in range(5)]
        proc = _proc(100, "sshd", ppid=1, offset=10)
        case = _make_case(store, auth_fails + [proc], trigger=proc,
                          signals=["authentication_failure_burst"])
        result = _run(store, case)
        technique_ids = [t.technique_id for t in result.attack_techniques]
        assert "T1110" in technique_ids, f"Got: {technique_ids}"

    def test_no_speculative_mapping_for_svchost(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "svchost.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        ps = [t for t in result.attack_techniques if t.technique_id == "T1059.001"]
        assert not ps

    def test_technique_evidence_ids_in_result_evidence(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        for technique in result.attack_techniques:
            for eid in technique.evidence_ids:
                assert eid in result.evidence_ids_used


# ===========================================================================
# E. IOC extraction
# ===========================================================================

class TestIOCExtraction:
    def test_ip_ioc_extracted(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        net = _net("185.220.101.10", 4444, pid=100, offset=1)
        case = _make_case(store, [proc, net], trigger=proc)
        result = _run(store, case)
        ip_iocs = [i for i in result.iocs if i.type == "ip"]
        assert ip_iocs
        assert "185.220.101.10" in [i.value for i in ip_iocs]

    def test_domain_ioc_extracted(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        dns = _dns("evil.example.com", pid=100, offset=1)
        case = _make_case(store, [proc, dns], trigger=proc)
        result = _run(store, case)
        domain_iocs = [i for i in result.iocs if i.type == "domain"]
        assert domain_iocs
        assert any("evil.example.com" in i.value for i in domain_iocs)

    def test_file_path_ioc_extracted(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        f = _file("/tmp/update.exe", pid=100, suffix=".exe", offset=1)
        case = _make_case(store, [proc, f], trigger=proc)
        result = _run(store, case)
        path_iocs = [i for i in result.iocs if i.type == "file_path"]
        assert path_iocs
        assert any("/tmp/update.exe" in i.value for i in path_iocs)

    def test_cmdline_indicator_for_encoded_command(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4,
                     cmdline="powershell.exe -enc JABzAA==", offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        cmdline_iocs = [i for i in result.iocs if i.type == "cmdline_indicator"]
        assert cmdline_iocs

    def test_iocs_deduplicated(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        net1 = _net("10.0.0.1", 443, pid=100, offset=1)
        net2 = _net("10.0.0.1", 443, pid=100, offset=2)
        case = _make_case(store, [proc, net1, net2], trigger=proc)
        result = _run(store, case)
        ip_iocs = [i for i in result.iocs
                   if i.type == "ip" and i.value == "10.0.0.1"]
        assert len(ip_iocs) == 1, f"Got {len(ip_iocs)} copies"

    def test_ioc_source_event_ids_preserved(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        net = _net("1.2.3.4", 4444, pid=100, offset=1)
        case = _make_case(store, [proc, net], trigger=proc)
        result = _run(store, case)
        for ioc in result.iocs:
            assert ioc.source_event_ids

    def test_iocs_serialisable(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        net = _net("2.3.4.5", 4444, pid=100, offset=1)
        case = _make_case(store, [proc, net], trigger=proc)
        result = _run(store, case)
        canonical = result.canonical()
        assert "iocs" in canonical
        json.dumps(canonical)


# ===========================================================================
# F. Investigation coverage reporting
# ===========================================================================

class TestInvestigationCoverage:
    def test_coverage_object_present(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "cmd.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        assert isinstance(result.investigation_coverage, InvestigationCoverage)

    def test_coverage_fields_are_booleans(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "cmd.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        cov = result.investigation_coverage
        for field_name in InvestigationCoverage.__dataclass_fields__:
            val = getattr(cov, field_name)
            assert isinstance(val, bool), f"coverage.{field_name} must be bool"

    def test_coverage_serialisable(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "cmd.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        canonical = result.canonical()
        assert "investigation_coverage" in canonical
        cov_dict = canonical["investigation_coverage"]
        assert isinstance(cov_dict, dict)
        json.dumps(cov_dict)

    def test_ioc_extracted_flag_set(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        assert result.investigation_coverage.ioc_extracted is True

    def test_activity_chain_built_flag_set(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "cmd.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        assert result.investigation_coverage.activity_chain_built is True

    def test_attack_techniques_mapped_flag_set(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        result = _run(store, case)
        assert result.investigation_coverage.attack_techniques_mapped is True

    def test_partial_coverage_still_has_coverage_object(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "svchost.exe", ppid=4, offset=0)
        case = _make_case(store, [proc], trigger=proc)
        budget = InvestigationBudget(max_tool_calls=3,
                                     max_investigation_time_seconds=5.0)
        agent = InvestigationAgent(store, budget=budget)
        result = agent.investigate(case.case_id)
        assert isinstance(result.investigation_coverage, InvestigationCoverage)


# ===========================================================================
# G. Adaptive loop integration
# ===========================================================================

class TestAdaptiveIntegration:
    def test_auth_tool_called_in_loop(self, tmp_path):
        store = _make_store(tmp_path)
        auth = _auth("login_success", "eve", offset=0)
        proc = _proc(100, "bash", ppid=4, user="eve", offset=1)
        case = _make_case(store, [proc, auth], trigger=proc)
        budget = InvestigationBudget(max_tool_calls=25,
                                     max_investigation_time_seconds=30.0)
        agent = InvestigationAgent(store, budget=budget)
        result = agent.investigate(case.case_id)
        assert agent.last_state is not None
        tool_names = [tc.tool_name for tc in agent.last_state.tool_calls]
        assert "get_auth_activity" in tool_names, f"Tools: {tool_names}"

    def test_auth_not_called_twice(self, tmp_path):
        store = _make_store(tmp_path)
        auth = _auth("login_success", "frank", offset=0)
        proc = _proc(100, "python.exe", ppid=4, offset=1)
        case = _make_case(store, [proc, auth], trigger=proc)
        budget = InvestigationBudget(max_tool_calls=25,
                                     max_investigation_time_seconds=30.0)
        agent = InvestigationAgent(store, budget=budget)
        agent.investigate(case.case_id)
        assert agent.last_state is not None
        auth_calls = [tc for tc in agent.last_state.tool_calls
                      if tc.tool_name == "get_auth_activity"]
        assert len(auth_calls) <= 1, f"Called {len(auth_calls)} times"

    def test_new_fields_in_canonical(self, tmp_path):
        store = _make_store(tmp_path)
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        net = _net("5.6.7.8", 4444, pid=100, offset=1)
        case = _make_case(store, [proc, net], trigger=proc)
        result = _run(store, case)
        canonical = result.canonical()
        for key in ["authentication_activity", "activity_chain", "relationships",
                    "attack_techniques", "iocs", "investigation_coverage"]:
            assert key in canonical, f"Key {key!r} missing from canonical"


# ===========================================================================
# H. Safety
# ===========================================================================

class TestSafety:
    def test_prompt_injection_in_auth_user_is_data(self, tmp_path):
        store = _make_store(tmp_path)
        evil_user = "admin'; DROP TABLE events; --"
        auth = _auth("login_success", evil_user, offset=0)
        proc = _proc(100, "sshd", ppid=1, offset=1)
        case = _make_case(store, [proc, auth], trigger=proc)
        result = _run(store, case)
        assert isinstance(result, InvestigationResult)

    def test_prompt_injection_in_dns_is_data(self, tmp_path):
        store = _make_store(tmp_path)
        evil_domain = "evil.com'; import os #"
        proc = _proc(100, "powershell.exe", ppid=4, offset=0)
        dns = _dns(evil_domain, pid=100, offset=1)
        case = _make_case(store, [proc, dns], trigger=proc)
        result = _run(store, case)
        assert isinstance(result, InvestigationResult)
        domain_iocs = [i for i in result.iocs if i.type == "domain"]
        for i in domain_iocs:
            assert isinstance(i.value, str)

    def test_malformed_auth_event_handled(self, tmp_path):
        store = _make_store(tmp_path)
        malformed = Event(kind=EventKind.AUTHENTICATION, source="fixture",
                          data={}, observed_at=_ts(0), host_id="test-host")
        proc = _proc(100, "sshd", ppid=1, offset=1)
        case = _make_case(store, [malformed, proc], trigger=proc)
        result = _run(store, case)
        assert isinstance(result, InvestigationResult)

    def test_no_forbidden_patterns_in_agent(self, tmp_path):
        import inspect
        import aegis_core.investigation.agent as agent_module
        source = inspect.getsource(agent_module)
        for pattern in ["subprocess", "os.system", "shell=True",
                        "eval(", "exec(", "os.popen"]:
            assert pattern not in source, f"Forbidden: {pattern!r} in agent.py"
