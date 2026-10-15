"""
Dashboard Service Layer for Phase 8C.
Project: Self-Adaptive Zero Trust Cybersecurity Architecture for Industry 5.0

Provides high-level helpers for the Streamlit SOC Dashboard:
- Persistent incident listing, filtering, and retrieval via JsonQuarantineStore
- Approval (RELEASED) and Rejection (KEEP_QUARANTINED) workflows with audit logging
- Live flow injection and simulation of benchmark test scenarios
- High-level KPI aggregations for review panel presentations
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import random
from typing import Any, Dict, List, Optional
import uuid

from storage.json_store import JsonQuarantineStore
from storage.schemas import (
    DecisionAction,
    IncidentStatus,
    QuarantineIncident,
    StatusHistoryEntry,
)

BASE_DIR = Path(__file__).resolve().parent.parent
INCIDENTS_DIR = BASE_DIR / "experiments/incidents"


class DashboardService:
    """Service providing incident management and simulation for the SOC Dashboard."""

    def __init__(self, store: Optional[JsonQuarantineStore] = None):
        self.store = store or JsonQuarantineStore()

    def get_kpis(self) -> Dict[str, Any]:
        """Calculates high-level metrics for dashboard header cards."""
        incidents = self.store.list_quarantine_incidents(limit=500)
        total = len(incidents)
        pending = sum(1 for i in incidents if i.incident_status == IncidentStatus.PENDING_REVIEW)
        quarantined = sum(1 for i in incidents if i.incident_status in [IncidentStatus.QUARANTINED, IncidentStatus.KEEP_QUARANTINED])
        released = sum(1 for i in incidents if i.incident_status == IncidentStatus.RELEASED)
        
        avg_risk = (
            sum(i.risk_score for i in incidents) / total
            if total > 0 else 0.0
        )
        return {
            "total_incidents": total,
            "pending_review": pending,
            "quarantined": quarantined,
            "released": released,
            "avg_risk": round(avg_risk, 2),
        }

    def list_incidents(
        self,
        status_filter: Optional[str] = None,
        risk_filter: Optional[str] = None,
        search_query: Optional[str] = None,
    ) -> List[QuarantineIncident]:
        """Returns filtered incidents sorted chronologically (newest first)."""
        incidents = self.store.list_quarantine_incidents(limit=200)

        if status_filter and status_filter != "ALL":
            incidents = [i for i in incidents if i.incident_status.value == status_filter]

        if risk_filter and risk_filter != "ALL":
            incidents = [i for i in incidents if i.risk_level == risk_filter]

        if search_query:
            q = search_query.strip().lower()
            filtered = []
            for i in incidents:
                searchable_text = f"{i.incident_id} {i.event_id} {i.source_ip} {i.destination_ip} {i.asset_id} {i.fog_prediction} {i.edge_prediction}".lower()
                if q in searchable_text:
                    filtered.append(i)
            incidents = filtered

        return incidents

    def get_incident(self, incident_id: str) -> Optional[QuarantineIncident]:
        return self.store.get_incident_by_id(incident_id)

    def approve_incident(
        self,
        incident_id: str,
        analyst_name: str = "Analyst Lead",
        comment: Optional[str] = None,
    ) -> QuarantineIncident:
        """
        Approves an incident: transitions from PENDING_REVIEW or QUARANTINED to RELEASED.
        Appends an immutable audit log entry with analyst rationale.
        """
        note = comment or "Operator manual review completed. Traffic classified as legitimate operational flow / authorized exception. Isolation released."
        return self.store.update_incident_status(
            incident_id=incident_id,
            new_status=IncidentStatus.RELEASED,
            comment=note,
            updated_by=analyst_name,
        )

    def reject_incident(
        self,
        incident_id: str,
        analyst_name: str = "Analyst Lead",
        comment: Optional[str] = None,
    ) -> QuarantineIncident:
        """
        Rejects an incident: confirms attack containment, transitioning PENDING_REVIEW to KEEP_QUARANTINED.
        """
        note = comment or "Operator confirmed malicious activity based on XAI feature attributions. Network isolation permanently retained."
        return self.store.update_incident_status(
            incident_id=incident_id,
            new_status=IncidentStatus.KEEP_QUARANTINED,
            comment=note,
            updated_by=analyst_name,
        )

    def reset_database(self) -> None:
        """Restores default benchmark demonstration incidents."""
        self.store.seed_defaults(force=True)

    def inject_simulated_scenario(self, scenario_type: str) -> QuarantineIncident:
        """
        Injects a newly simulated live flow into the persistent database.
        Uses realistic parameters matching the 4 research paper evaluation scenarios.
        """
        uid = f"LIVE-{uuid.uuid4().hex[:6].upper()}"
        now_iso = datetime.now(timezone.utc).isoformat()

        if scenario_type == "AMBIGUOUS":
            incident = QuarantineIncident(
                incident_id=f"INC-{uid}-AMBIGUOUS",
                event_id=f"FLOW-{uid}-HITL",
                timestamp=now_iso,
                source_ip="192.168.1.188",
                destination_ip="192.168.1.8",
                protocol="http",
                asset_id="SAFETY-PLC-CELL-1",
                asset_criticality=5,
                human_worker_present=True,
                worker_distance_m=1.5,
                human_proximity_factor=1.85,
                edge_prediction="Attack",
                edge_confidence=0.8842,
                fast_tracked=False,
                fog_prediction="DDoS_HTTP",
                fog_confidence=0.4857,
                risk_score=72.71,
                risk_level="HIGH",
                risk_components={
                    "normalized_threat_severity": 0.65,
                    "normalized_confidence": 0.49,
                    "normalized_asset_criticality": 1.0,
                    "normalized_human_proximity": 0.85,
                    "normalized_xai_alignment": 0.65,
                },
                xai_top_features=[
                    {"feature_name": "http.content_length", "shap_value": 0.3821, "baseline_value": 0.0},
                    {"feature_name": "tcp.dstport", "shap_value": 0.2915, "baseline_value": 80.0},
                    {"feature_name": "ip.hdr_len", "shap_value": 0.1844, "baseline_value": 20.0},
                    {"feature_name": "tcp.srcport", "shap_value": 0.1422, "baseline_value": 49152.0},
                ],
                xai_alignment_score=0.65,
                policy_action=DecisionAction.ESCALATE_TO_HUMAN_AMBIGUOUS,
                hitl_required=True,
                pdp_rule_triggered="PDP-RULE-04-HITL_AMBIGUOUS",
                safety_advisory=None,
                simulated_enforcement=[
                    "SIMULATED_ENFORCEMENT_COMMAND: iptables -I FORWARD 1 -s 192.168.1.188 -m state --state NEW -j TARPIT",
                    "SIMULATED_ENFORCEMENT_COMMAND: curl -X POST -H 'Content-Type: application/json' -d '{\"status\":\"PENDING_ANALYST\"}' https://soc.industry5.internal/api/v1/escalations",
                ],
                incident_status=IncidentStatus.PENDING_REVIEW,
                status_history=[
                    StatusHistoryEntry(
                        from_status="DETECTED",
                        to_status=IncidentStatus.PENDING_REVIEW.value,
                        timestamp=now_iso,
                        updated_by="system",
                        comment="Live stream injection: Low model certainty with elevated risk near worker. Escalate to human.",
                    )
                ],
                created_at=now_iso,
                updated_at=now_iso,
            )

        elif scenario_type == "MITM_CRITICAL":
            incident = QuarantineIncident(
                incident_id=f"INC-{uid}-MITM",
                event_id=f"FLOW-{uid}-POISON",
                timestamp=now_iso,
                source_ip="192.168.1.205",
                destination_ip="192.168.1.5",
                protocol="arp/ip",
                asset_id="ROBOT-ARM-CELL-3",
                asset_criticality=5,
                human_worker_present=True,
                worker_distance_m=1.2,
                human_proximity_factor=1.88,
                edge_prediction="Attack",
                edge_confidence=0.9991,
                fast_tracked=False,
                fog_prediction="MITM",
                fog_confidence=0.9923,
                risk_score=92.96,
                risk_level="CRITICAL",
                risk_components={
                    "normalized_threat_severity": 0.95,
                    "normalized_confidence": 0.99,
                    "normalized_asset_criticality": 1.0,
                    "normalized_human_proximity": 0.88,
                    "normalized_xai_alignment": 0.92,
                },
                xai_top_features=[
                    {"feature_name": "arp.opcode", "shap_value": 0.4812, "baseline_value": 1.0},
                    {"feature_name": "arp.hw.size", "shap_value": 0.3120, "baseline_value": 6.0},
                    {"feature_name": "icmp.checksum", "shap_value": 0.2241, "baseline_value": 0.0},
                ],
                xai_alignment_score=0.92,
                policy_action=DecisionAction.QUARANTINE_AND_ESTOP_RECOMMENDATION,
                hitl_required=True,
                pdp_rule_triggered="PDP-RULE-05-CRITICAL_SAFETY_ESTOP",
                safety_advisory="ADVISORY: Emergency Stop recommended. Autonomous physical actuation disabled by safety policy. Operator confirmation required.",
                simulated_enforcement=[
                    "SIMULATED_ENFORCEMENT_COMMAND: iptables -I FORWARD 1 -s 192.168.1.205 -j DROP",
                    "SIMULATED_ENFORCEMENT_COMMAND: bpftool map update id 42 key 0xc0a801cd value 0x01",
                    "SIMULATED_ENFORCEMENT_COMMAND: echo 'ADVISORY_RECOMMEND_ESTOP: asset=ROBOT-ARM-CELL-3' >> /var/log/safety_advisory.log",
                ],
                incident_status=IncidentStatus.PENDING_REVIEW,
                status_history=[
                    StatusHistoryEntry(
                        from_status="DETECTED",
                        to_status=IncidentStatus.PENDING_REVIEW.value,
                        timestamp=now_iso,
                        updated_by="system",
                        comment="Live stream injection: ARP/MITM poisoning near human worker (1.2m). E-STOP advisory pending operator authorization.",
                    )
                ],
                created_at=now_iso,
                updated_at=now_iso,
            )

        elif scenario_type == "RECONNAISSANCE":
            incident = QuarantineIncident(
                incident_id=f"INC-{uid}-RECON",
                event_id=f"FLOW-{uid}-PROBE",
                timestamp=now_iso,
                source_ip="192.168.1.150",
                destination_ip="192.168.1.20",
                protocol="tcp",
                asset_id="SENSOR-GATEWAY-02",
                asset_criticality=2,
                human_worker_present=False,
                worker_distance_m=15.0,
                human_proximity_factor=1.0,
                edge_prediction="Attack",
                edge_confidence=0.9992,
                fast_tracked=False,
                fog_prediction="Port_Scanning",
                fog_confidence=0.9992,
                risk_score=39.48,
                risk_level="MEDIUM",
                risk_components={
                    "normalized_threat_severity": 0.35,
                    "normalized_confidence": 1.0,
                    "normalized_asset_criticality": 0.4,
                    "normalized_human_proximity": 0.0,
                    "normalized_xai_alignment": 0.85,
                },
                xai_top_features=[
                    {"feature_name": "tcp.flags.syn", "shap_value": 0.3512, "baseline_value": 0.0},
                    {"feature_name": "tcp.dstport", "shap_value": 0.2541, "baseline_value": 80.0},
                ],
                xai_alignment_score=0.85,
                policy_action=DecisionAction.MONITOR,
                hitl_required=False,
                pdp_rule_triggered="PDP-RULE-01-ENHANCED_MONITOR",
                safety_advisory=None,
                simulated_enforcement=[
                    f"SIMULATED_ENFORCEMENT_COMMAND: tcpdump -i eth0 -n -s 0 -w /var/log/audit/flow_{uid}.pcap host 192.168.1.150",
                    "SIMULATED_ENFORCEMENT_COMMAND: iptables -A FORWARD -s 192.168.1.150 -j LOG --log-prefix 'ZERO_TRUST_MONITOR: '",
                ],
                incident_status=IncidentStatus.RELEASED,
                status_history=[
                    StatusHistoryEntry(
                        from_status="DETECTED",
                        to_status=IncidentStatus.RELEASED.value,
                        timestamp=now_iso,
                        updated_by="system",
                        comment="Low-risk port scanning flow permitted with enhanced packet logging.",
                    )
                ],
                created_at=now_iso,
                updated_at=now_iso,
            )

        else:  # BENIGN_FAST_TRACK
            incident = QuarantineIncident(
                incident_id=f"INC-{uid}-NORMAL",
                event_id=f"FLOW-{uid}-BENIGN",
                timestamp=now_iso,
                source_ip="192.168.1.101",
                destination_ip="192.168.1.10",
                protocol="modbus_tcp",
                asset_id="HMI-STATION-01",
                asset_criticality=2,
                human_worker_present=False,
                worker_distance_m=10.0,
                human_proximity_factor=1.0,
                edge_prediction="Normal",
                edge_confidence=1.0,
                fast_tracked=True,
                fog_prediction=None,
                fog_confidence=None,
                risk_score=5.0,
                risk_level="LOW",
                risk_components={
                    "normalized_threat_severity": 0.0,
                    "normalized_confidence": 0.0,
                    "normalized_asset_criticality": 0.4,
                    "normalized_human_proximity": 0.0,
                    "normalized_xai_alignment": 0.0,
                },
                xai_top_features=[],
                xai_alignment_score=0.0,
                policy_action=DecisionAction.ALLOW,
                hitl_required=False,
                pdp_rule_triggered="PDP-RULE-01-FAST_TRACK_ALLOW",
                safety_advisory=None,
                simulated_enforcement=[
                    "SIMULATED_ENFORCEMENT_COMMAND: iptables -C FORWARD -s 192.168.1.101 -j ACCEPT 2>/dev/null || iptables -A FORWARD -s 192.168.1.101 -d 192.168.1.10 -j ACCEPT"
                ],
                incident_status=IncidentStatus.RELEASED,
                status_history=[
                    StatusHistoryEntry(
                        from_status="DETECTED",
                        to_status=IncidentStatus.RELEASED.value,
                        timestamp=now_iso,
                        updated_by="system",
                        comment="Tier 1 Edge validated normal baseline flow. Fast-tracked line-rate bypass.",
                    )
                ],
                created_at=now_iso,
                updated_at=now_iso,
            )

        self.store.insert_quarantine_incident(incident)
        return incident
