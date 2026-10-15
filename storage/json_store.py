"""
Local Persistent JSON Quarantine Store for Phase 8A / Phase 8C.
Project: Self-Adaptive Zero Trust Cybersecurity Architecture for Industry 5.0

Implements the BaseQuarantineStore interface backed by an atomic local JSON file
(data/incidents_db.json) for 100% deterministic, offline-resilient review panel demos.
Validates all status transitions against the Phase 8A finite state machine.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Union

from storage.exceptions import (
    DuplicateIncidentError,
    IncidentNotFoundError,
    InvalidStatusTransitionError,
)
from storage.quarantine_store import BaseQuarantineStore
from storage.schemas import (
    IncidentStatus,
    QuarantineIncident,
    StatusHistoryEntry,
    validate_status_transition,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_JSON_PATH = BASE_DIR / "data/incidents_db.json"


def get_default_seed_incidents() -> List[Dict[str, Any]]:
    """
    Returns realistic, logically consistent benchmark incidents derived from the 4 frozen
    capstone scenarios and genuine Edge-IIoTset test records.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    return [
        {
            "incident_id": "INC-DEMO-004-AMBIGUOUS",
            "event_id": "DEMO-SCENARIO-4-AMBIGUOUS-HITL",
            "timestamp": "2026-10-13T12:00:00Z",
            "source_ip": "192.168.1.188",
            "destination_ip": "192.168.1.8",
            "protocol": "http",
            "asset_id": "SAFETY-PLC-CELL-1",
            "asset_criticality": 5,
            "human_worker_present": True,
            "worker_distance_m": 1.5,
            "human_proximity_factor": 1.85,
            "edge_prediction": "Attack",
            "edge_confidence": 0.8842,
            "fast_tracked": False,
            "fog_prediction": "DDoS_HTTP",
            "fog_confidence": 0.4857,
            "risk_score": 72.71,
            "risk_level": "HIGH",
            "risk_components": {
                "normalized_threat_severity": 0.65,
                "normalized_confidence": 0.49,
                "normalized_asset_criticality": 1.0,
                "normalized_human_proximity": 0.85,
                "normalized_xai_alignment": 0.65,
            },
            "xai_top_features": [
                {"feature_name": "http.content_length", "shap_value": 0.3821, "baseline_value": 0.0},
                {"feature_name": "tcp.dstport", "shap_value": 0.2915, "baseline_value": 80.0},
                {"feature_name": "ip.hdr_len", "shap_value": 0.1844, "baseline_value": 20.0},
                {"feature_name": "tcp.srcport", "shap_value": 0.1422, "baseline_value": 49152.0},
                {"feature_name": "http.response", "shap_value": -0.0812, "baseline_value": 0.0},
            ],
            "xai_alignment_score": 0.65,
            "policy_action": "ESCALATE_TO_HUMAN_AMBIGUOUS",
            "hitl_required": True,
            "pdp_rule_triggered": "PDP-RULE-04-HITL_AMBIGUOUS",
            "safety_advisory": None,
            "simulated_enforcement": [
                "SIMULATED_ENFORCEMENT_COMMAND: iptables -I FORWARD 1 -s 192.168.1.188 -m state --state NEW -j TARPIT",
                "SIMULATED_ENFORCEMENT_COMMAND: curl -X POST -H 'Content-Type: application/json' -d '{\"event_id\":\"DEMO-SCENARIO-4-AMBIGUOUS-HITL\",\"source_ip\":\"192.168.1.188\",\"status\":\"PENDING_ANALYST\"}' https://soc.industry5.internal/api/v1/escalations",
            ],
            "incident_status": "PENDING_REVIEW",
            "status_history": [
                {
                    "from_status": "DETECTED",
                    "to_status": "PENDING_REVIEW",
                    "timestamp": now_iso,
                    "updated_by": "system",
                    "comment": "Low model certainty (conf=0.4857 < 0.70) with elevated risk 72.71 near worker (1.5m). Dispatched for human verification.",
                }
            ],
            "created_at": now_iso,
            "updated_at": now_iso,
        },
        {
            "incident_id": "INC-DEMO-003-MITM",
            "event_id": "DEMO-SCENARIO-3-POISONING",
            "timestamp": "2026-10-13T11:45:00Z",
            "source_ip": "192.168.1.205",
            "destination_ip": "192.168.1.5",
            "protocol": "arp/ip",
            "asset_id": "ROBOT-ARM-CELL-3",
            "asset_criticality": 5,
            "human_worker_present": True,
            "worker_distance_m": 1.2,
            "human_proximity_factor": 1.88,
            "edge_prediction": "Attack",
            "edge_confidence": 0.9991,
            "fast_tracked": False,
            "fog_prediction": "MITM",
            "fog_confidence": 0.9923,
            "risk_score": 92.96,
            "risk_level": "CRITICAL",
            "risk_components": {
                "normalized_threat_severity": 0.95,
                "normalized_confidence": 0.99,
                "normalized_asset_criticality": 1.0,
                "normalized_human_proximity": 0.88,
                "normalized_xai_alignment": 0.92,
            },
            "xai_top_features": [
                {"feature_name": "arp.opcode", "shap_value": 0.4812, "baseline_value": 1.0},
                {"feature_name": "arp.hw.size", "shap_value": 0.3120, "baseline_value": 6.0},
                {"feature_name": "icmp.checksum", "shap_value": 0.2241, "baseline_value": 0.0},
                {"feature_name": "tcp.dstport", "shap_value": 0.1511, "baseline_value": 502.0},
            ],
            "xai_alignment_score": 0.92,
            "policy_action": "QUARANTINE_AND_ESTOP_RECOMMENDATION",
            "hitl_required": True,
            "pdp_rule_triggered": "PDP-RULE-05-CRITICAL_SAFETY_ESTOP",
            "safety_advisory": "ADVISORY: Emergency Stop recommended. Autonomous physical actuation disabled by safety policy. Operator confirmation required.",
            "simulated_enforcement": [
                "SIMULATED_ENFORCEMENT_COMMAND: iptables -I FORWARD 1 -s 192.168.1.205 -j DROP",
                "SIMULATED_ENFORCEMENT_COMMAND: bpftool map update id 42 key 0xc0a801cd value 0x01",
                "SIMULATED_ENFORCEMENT_COMMAND: echo 'ADVISORY_RECOMMEND_ESTOP: asset=ROBOT-ARM-CELL-3, flow=DEMO-SCENARIO-3-POISONING' >> /var/log/safety_advisory.log",
            ],
            "incident_status": "PENDING_REVIEW",
            "status_history": [
                {
                    "from_status": "DETECTED",
                    "to_status": "PENDING_REVIEW",
                    "timestamp": now_iso,
                    "updated_by": "system",
                    "comment": "High-confidence MITM poisoning attack on critical robot arm near worker (1.2m). Quarantined; awaiting operator confirmation for machinery halt.",
                }
            ],
            "created_at": now_iso,
            "updated_at": now_iso,
        },
        {
            "incident_id": "INC-HIST-005-SQLI",
            "event_id": "FLOW-TEST-SQLI-089",
            "timestamp": "2026-10-13T11:15:00Z",
            "source_ip": "192.168.1.177",
            "destination_ip": "192.168.1.15",
            "protocol": "http/sql",
            "asset_id": "HMI-PORTAL-01",
            "asset_criticality": 4,
            "human_worker_present": False,
            "worker_distance_m": 8.0,
            "human_proximity_factor": 1.2,
            "edge_prediction": "Attack",
            "edge_confidence": 0.9650,
            "fast_tracked": False,
            "fog_prediction": "SQL_injection",
            "fog_confidence": 0.8120,
            "risk_score": 68.40,
            "risk_level": "HIGH",
            "risk_components": {
                "normalized_threat_severity": 0.80,
                "normalized_confidence": 0.81,
                "normalized_asset_criticality": 0.8,
                "normalized_human_proximity": 0.2,
                "normalized_xai_alignment": 0.78,
            },
            "xai_top_features": [
                {"feature_name": "http.request.uri", "shap_value": 0.4215, "baseline_value": 0.0},
                {"feature_name": "tcp.dstport", "shap_value": 0.2840, "baseline_value": 80.0},
                {"feature_name": "http.content_length", "shap_value": 0.1633, "baseline_value": 0.0},
            ],
            "xai_alignment_score": 0.78,
            "policy_action": "QUARANTINE",
            "hitl_required": False,
            "pdp_rule_triggered": "PDP-RULE-03-AUTOMATED_QUARANTINE",
            "safety_advisory": None,
            "simulated_enforcement": [
                "SIMULATED_ENFORCEMENT_COMMAND: iptables -I FORWARD 1 -s 192.168.1.177 -j DROP",
                "SIMULATED_ENFORCEMENT_COMMAND: bpftool map update id 42 key 0xc0a801b1 value 0x01",
            ],
            "incident_status": "QUARANTINED",
            "status_history": [
                {
                    "from_status": "DETECTED",
                    "to_status": "QUARANTINED",
                    "timestamp": now_iso,
                    "updated_by": "system",
                    "comment": "Automated zero-trust quarantine enforced for SQL injection against HMI portal.",
                }
            ],
            "created_at": now_iso,
            "updated_at": now_iso,
        },
        {
            "incident_id": "INC-HIST-002-RECON",
            "event_id": "DEMO-SCENARIO-2-RECON",
            "timestamp": "2026-10-13T10:30:00Z",
            "source_ip": "192.168.1.150",
            "destination_ip": "192.168.1.20",
            "protocol": "tcp",
            "asset_id": "SENSOR-GATEWAY-02",
            "asset_criticality": 2,
            "human_worker_present": False,
            "worker_distance_m": 15.0,
            "human_proximity_factor": 1.0,
            "edge_prediction": "Attack",
            "edge_confidence": 0.9992,
            "fast_tracked": False,
            "fog_prediction": "Port_Scanning",
            "fog_confidence": 0.9992,
            "risk_score": 39.48,
            "risk_level": "MEDIUM",
            "risk_components": {
                "normalized_threat_severity": 0.35,
                "normalized_confidence": 1.0,
                "normalized_asset_criticality": 0.4,
                "normalized_human_proximity": 0.0,
                "normalized_xai_alignment": 0.85,
            },
            "xai_top_features": [
                {"feature_name": "tcp.flags.syn", "shap_value": 0.3512, "baseline_value": 0.0},
                {"feature_name": "tcp.dstport", "shap_value": 0.2541, "baseline_value": 80.0},
                {"feature_name": "tcp.len", "shap_value": 0.1210, "baseline_value": 0.0},
            ],
            "xai_alignment_score": 0.85,
            "policy_action": "MONITOR",
            "hitl_required": False,
            "pdp_rule_triggered": "PDP-RULE-01-ENHANCED_MONITOR",
            "safety_advisory": None,
            "simulated_enforcement": [
                "SIMULATED_ENFORCEMENT_COMMAND: tcpdump -i eth0 -n -s 0 -w /var/log/audit/flow_DEMO-SCENARIO-2-RECON.pcap host 192.168.1.150",
                "SIMULATED_ENFORCEMENT_COMMAND: iptables -A FORWARD -s 192.168.1.150 -j LOG --log-prefix 'ZERO_TRUST_MONITOR: '",
            ],
            "incident_status": "RELEASED",
            "status_history": [
                {
                    "from_status": "DETECTED",
                    "to_status": "RELEASED",
                    "timestamp": now_iso,
                    "updated_by": "analyst",
                    "comment": "Reconnaissance probe from internal authorized vulnerability scanner. Deemed benign research probe.",
                }
            ],
            "created_at": now_iso,
            "updated_at": now_iso,
        },
        {
            "incident_id": "INC-HIST-001-NORMAL",
            "event_id": "DEMO-SCENARIO-1-NORMAL",
            "timestamp": "2026-10-13T10:00:00Z",
            "source_ip": "192.168.1.101",
            "destination_ip": "192.168.1.10",
            "protocol": "modbus_tcp",
            "asset_id": "HMI-STATION-01",
            "asset_criticality": 2,
            "human_worker_present": False,
            "worker_distance_m": 10.0,
            "human_proximity_factor": 1.0,
            "edge_prediction": "Normal",
            "edge_confidence": 1.0,
            "fast_tracked": True,
            "fog_prediction": None,
            "fog_confidence": None,
            "risk_score": 5.0,
            "risk_level": "LOW",
            "risk_components": {
                "normalized_threat_severity": 0.0,
                "normalized_confidence": 0.0,
                "normalized_asset_criticality": 0.4,
                "normalized_human_proximity": 0.0,
                "normalized_xai_alignment": 0.0,
            },
            "xai_top_features": [],
            "xai_alignment_score": 0.0,
            "policy_action": "ALLOW",
            "hitl_required": False,
            "pdp_rule_triggered": "PDP-RULE-01-FAST_TRACK_ALLOW",
            "safety_advisory": None,
            "simulated_enforcement": [
                "SIMULATED_ENFORCEMENT_COMMAND: iptables -C FORWARD -s 192.168.1.101 -j ACCEPT 2>/dev/null || iptables -A FORWARD -s 192.168.1.101 -d 192.168.1.10 -j ACCEPT"
            ],
            "incident_status": "RELEASED",
            "status_history": [
                {
                    "from_status": "DETECTED",
                    "to_status": "RELEASED",
                    "timestamp": now_iso,
                    "updated_by": "system",
                    "comment": "Tier 1 Edge fast-tracked normal flow. Line-rate access granted.",
                }
            ],
            "created_at": now_iso,
            "updated_at": now_iso,
        },
    ]


class JsonQuarantineStore(BaseQuarantineStore):
    """
    Local JSON-backed persistent store for quarantine incidents.
    Provides identical interface to MongoQuarantineStore and InMemoryQuarantineStore.
    """

    def __init__(self, file_path: Optional[Union[str, Path]] = None, auto_seed: bool = True):
        self.file_path = Path(file_path or DEFAULT_JSON_PATH)
        self._lock = threading.Lock()
        if auto_seed and (not self.file_path.exists() or self.file_path.stat().st_size == 0):
            self.seed_defaults()

    def _read_data(self) -> Dict[str, Dict[str, Any]]:
        if not self.file_path.exists():
            return {}
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return {item["incident_id"]: item for item in data if "incident_id" in item}
                elif isinstance(data, dict):
                    return data
                return {}
        except Exception:
            return {}

    def _write_data(self, data: Dict[str, Dict[str, Any]]) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        # Write atomically using a temporary file
        temp_path = self.file_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(list(data.values()), f, indent=2)
        temp_path.replace(self.file_path)

    def health_check(self) -> bool:
        return True

    def seed_defaults(self, force: bool = False) -> None:
        """Seed the store with benchmark incidents."""
        with self._lock:
            data = self._read_data()
            if force or not data:
                defaults = get_default_seed_incidents()
                data = {item["incident_id"]: item for item in defaults}
                self._write_data(data)

    def insert_quarantine_incident(self, incident: QuarantineIncident) -> str:
        with self._lock:
            data = self._read_data()
            if incident.incident_id in data:
                raise DuplicateIncidentError(
                    f"Quarantine incident '{incident.incident_id}' already exists in store."
                )
            data[incident.incident_id] = incident.model_dump(mode="json")
            self._write_data(data)
            return incident.incident_id

    def get_incident_by_id(self, incident_id: str) -> Optional[QuarantineIncident]:
        with self._lock:
            data = self._read_data()
            doc = data.get(incident_id)
            if not doc:
                return None
            return QuarantineIncident(**doc)

    def list_quarantine_incidents(
        self,
        status: Optional[Union[IncidentStatus, str]] = None,
        limit: int = 100,
    ) -> List[QuarantineIncident]:
        with self._lock:
            data = self._read_data()
            results = []
            target = IncidentStatus(status).value if status else None
            for doc in data.values():
                if target is None or doc.get("incident_status") == target:
                    try:
                        results.append(QuarantineIncident(**doc))
                    except Exception:
                        pass
            # Sort by created_at descending
            results.sort(key=lambda x: x.created_at, reverse=True)
            return results[:limit]

    def update_incident_status(
        self,
        incident_id: str,
        new_status: Union[IncidentStatus, str],
        comment: Optional[str] = None,
        updated_by: Optional[str] = "analyst",
    ) -> QuarantineIncident:
        with self._lock:
            data = self._read_data()
            doc = data.get(incident_id)
            if not doc:
                raise IncidentNotFoundError(f"Quarantine incident '{incident_id}' not found in store.")

            current_incident = QuarantineIncident(**doc)
            target_status = IncidentStatus(new_status) if isinstance(new_status, str) else new_status

            # Validate lifecycle FSM transition
            validate_status_transition(current_incident.incident_status, target_status)

            now_iso = datetime.now(timezone.utc).isoformat()
            history_entry = StatusHistoryEntry(
                from_status=current_incident.incident_status.value,
                to_status=target_status.value,
                timestamp=now_iso,
                updated_by=updated_by or "analyst",
                comment=comment,
            )

            doc["incident_status"] = target_status.value
            doc["updated_at"] = now_iso
            doc.setdefault("status_history", []).append(history_entry.model_dump(mode="json"))

            data[incident_id] = doc
            self._write_data(data)
            return QuarantineIncident(**doc)
