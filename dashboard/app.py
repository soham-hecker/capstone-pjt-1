"""
Streamlit SOC Dashboard for Phase 8C: Human-in-the-Loop Zero Trust Operations.
Project: Self-Adaptive Zero Trust Cybersecurity Architecture for Industry 5.0

Author Team: Ishan Verma, Sanskar Pandey, Soham Sinha
Faculty Guide: Dr. Manjula V | VIT Chennai
"""

from datetime import datetime
import json
from pathlib import Path
import sys
from typing import Any, Dict, List

import altair as alt
import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from dashboard.service import DashboardService
from storage.schemas import IncidentStatus

# -----------------------------------------------------------------------------
# PAGE CONFIGURATION & STYLING
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Industry 5.0 Zero Trust SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom High-Tech Cyber SOC Styling
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.1rem;
        font-weight: 800;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #64748B;
        margin-bottom: 1.2rem;
    }
    .metric-card {
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 16px 20px;
        text-align: center;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        color: #0F172A;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.8rem;
        font-weight: 600;
        text-align: center;
    }
    .badge-critical { background-color: #FEE2E2; color: #991B1B; border: 1px solid #F87171; }
    .badge-high { background-color: #FFEDD5; color: #9A3412; border: 1px solid #FB923C; }
    .badge-medium { background-color: #FEF9C3; color: #854D0E; border: 1px solid #FACC15; }
    .badge-low { background-color: #DCFCE7; color: #166534; border: 1px solid #4ADE80; }
    .badge-pending { background-color: #EDE9FE; color: #5B21B6; border: 1px solid #A78BFA; }
    .badge-quarantined { background-color: #FEE2E2; color: #991B1B; border: 1px solid #EF4444; }
    .badge-released { background-color: #E0E7FF; color: #3730A3; border: 1px solid #818CF8; }
    .badge-keep { background-color: #FFE4E6; color: #881337; border: 1px solid #FB7185; }
    .cmd-box {
        background: #0F172A;
        color: #38BDF8;
        font-family: 'Courier New', Courier, monospace;
        font-size: 0.82rem;
        padding: 10px 14px;
        border-radius: 6px;
        overflow-x: auto;
        margin-top: 6px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_service() -> DashboardService:
    return DashboardService()


service = get_service()

# -----------------------------------------------------------------------------
# SIDEBAR: LIVE SIMULATION & CONTROLS FOR REVIEW PANEL
# -----------------------------------------------------------------------------
with st.sidebar:
    st.image("https://img.shields.io/badge/Industry%205.0-Zero%20Trust%20SOC-blue?style=for-the-badge", use_container_width=True)
    st.markdown("### 🔬 Live Flow Simulation")
    st.caption("Inject authentic Edge-IIoTset test partition flows into the Multi-Agent pipeline for review panel demonstration:")

    if st.button("⚡ Inject Scenario 1: Benign HMI", help="Tier 1 Edge Fast-Track -> ALLOW (1.9ms)", use_container_width=True):
        inc = service.inject_simulated_scenario("BENIGN_FAST_TRACK")
        st.success(f"Ingested {inc.incident_id} (Fast-Tracked Normal)")
        st.rerun()

    if st.button("🔍 Inject Scenario 2: Port Scanning", help="Tier 2 Fog Escalated -> MONITOR (39.48 Risk)", use_container_width=True):
        inc = service.inject_simulated_scenario("RECONNAISSANCE")
        st.info(f"Ingested {inc.incident_id} (Monitored Recon)")
        st.rerun()

    if st.button("🚨 Inject Scenario 3: MITM Near Worker", help="Tier 2 Fog Escalated -> QUARANTINE + E-STOP", use_container_width=True):
        inc = service.inject_simulated_scenario("MITM_CRITICAL")
        st.warning(f"Ingested {inc.incident_id} (Quarantined with E-STOP)")
        st.rerun()

    if st.button("❓ Inject Scenario 4: Ambiguous Threat", help="Low Confidence (0.48) -> ESCALATE TO HUMAN", use_container_width=True):
        inc = service.inject_simulated_scenario("AMBIGUOUS")
        st.error(f"Ingested {inc.incident_id} (Pending Human Review)")
        st.rerun()

    st.markdown("---")
    if st.button("🔄 Reset to Benchmark Defaults", use_container_width=True):
        service.reset_database()
        st.success("Database restored to frozen benchmark scenarios.")
        st.rerun()

    st.markdown("---")
    st.markdown("### 🎯 Filter & Search")
    status_filter = st.selectbox(
        "Incident Status",
        ["ALL", "PENDING_REVIEW", "QUARANTINED", "KEEP_QUARANTINED", "RELEASED"],
        index=0,
    )
    risk_filter = st.selectbox(
        "Risk Tier",
        ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        index=0,
    )
    search_query = st.text_input("Search (IP, Event, Asset, Class)", "")

    st.markdown("---")
    st.caption("**Research Project:** A Self-Adaptive Zero Trust Architecture for Industry 5.0 Enabled by Multi-Agent AI")
    st.caption("**Authors:** Ishan Verma (`23BAI1198`), Sanskar Pandey (`23BAI1197`), Soham Sinha (`23BAI1223`)")
    st.caption("**Faculty Guide:** Dr. Manjula V | SCOPE, VIT Chennai")

# -----------------------------------------------------------------------------
# MAIN DASHBOARD HEADER & KPI METRICS
# -----------------------------------------------------------------------------
st.markdown('<div class="main-header">🛡️ Industry 5.0 Zero Trust Operations Center</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Human-in-the-Loop Detection Dashboard • Two-Tier Edge/Fog ML • Explainable AI (SHAP) • Autonomous PDP</div>',
    unsafe_allow_html=True,
)

kpis = service.get_kpis()
c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    st.markdown(
        f'<div class="metric-card"><div class="metric-value">{kpis["total_incidents"]}</div><div class="metric-label">Total Flows Evaluated</div></div>',
        unsafe_allow_html=True,
    )
with c2:
    st.markdown(
        f'<div class="metric-card"><div class="metric-value" style="color: #7C3AED;">{kpis["pending_review"]}</div><div class="metric-label">Pending Human Review</div></div>',
        unsafe_allow_html=True,
    )
with c3:
    st.markdown(
        f'<div class="metric-card"><div class="metric-value" style="color: #DC2626;">{kpis["quarantined"]}</div><div class="metric-label">Actively Quarantined</div></div>',
        unsafe_allow_html=True,
    )
with c4:
    st.markdown(
        f'<div class="metric-card"><div class="metric-value" style="color: #2563EB;">{kpis["released"]}</div><div class="metric-label">Released / Permitted</div></div>',
        unsafe_allow_html=True,
    )
with c5:
    st.markdown(
        f'<div class="metric-card"><div class="metric-value">{kpis["avg_risk"]:.1f} <span style="font-size:1rem;color:#64748B">/ 100</span></div><div class="metric-label">Avg Composite Risk</div></div>',
        unsafe_allow_html=True,
    )

st.markdown("<br/>", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# SECTION: INCIDENT QUEUE (TABULAR OVERVIEW)
# -----------------------------------------------------------------------------
incidents = service.list_incidents(
    status_filter=status_filter,
    risk_filter=risk_filter,
    search_query=search_query,
)

st.subheader(f"📋 Detection & Verification Queue ({len(incidents)} items)")

if not incidents:
    st.info("No network incidents match the current filters.")
else:
    table_rows = []
    for inc in incidents:
        det_label = inc.fog_prediction if inc.fog_prediction else inc.edge_prediction
        det_conf = inc.fog_confidence if inc.fog_confidence is not None else inc.edge_confidence
        
        # Format top 2 XAI features
        xai_summary = "Bypassed (Fast-Track)"
        if inc.xai_top_features:
            feats = [f"{f['feature_name']} ({f['shap_value']:+.2f})" for f in inc.xai_top_features[:2]]
            xai_summary = ", ".join(feats)

        worker_txt = f"{inc.worker_distance_m}m" if inc.human_worker_present else "None"

        table_rows.append({
            "Incident ID": inc.incident_id,
            "Event ID": inc.event_id,
            "Source IP": inc.source_ip,
            "Destination IP": inc.destination_ip,
            "Protocol": (inc.protocol or "").upper(),
            "Asset Target": f"{inc.asset_id} (Crit {inc.asset_criticality})",
            "Worker Dist": worker_txt,
            "Detection Verdict": f"{det_label} ({det_conf*100:.1f}%)",
            "Risk Score": f"{inc.risk_score:.1f}",
            "Risk Level": inc.risk_level,
            "Top XAI Reasons": xai_summary,
            "Policy Action": inc.policy_action.value if hasattr(inc.policy_action, "value") else str(inc.policy_action),
            "Status": inc.incident_status.value,
        })

    df = pd.DataFrame(table_rows)

    # Let the user select which incident to inspect in detail
    selected_incident_id = st.selectbox(
        "🔍 Select Request to Inspect, Review XAI Explanations & Perform Human Action:",
        options=[inc.incident_id for inc in incidents],
        format_func=lambda x: f"{x} | {next((i.fog_prediction or i.edge_prediction) for i in incidents if i.incident_id == x)} | Risk: {next(i.risk_score for i in incidents if i.incident_id == x):.1f} | Status: {next(i.incident_status.value for i in incidents if i.incident_id == x)}",
        index=0,
    )

    # Render high-level summary table
    st.dataframe(
        df[["Incident ID", "Source IP", "Protocol", "Asset Target", "Worker Dist", "Detection Verdict", "Risk Score", "Risk Level", "Top XAI Reasons", "Status"]],
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("<hr/>", unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # SECTION: DETAILED INCIDENT INSPECTION & HUMAN DECISION PANEL
    # -------------------------------------------------------------------------
    target_incident = next((i for i in incidents if i.incident_id == selected_incident_id), None)

    if target_incident:
        st.markdown(f"### 🔎 Deep Inspection: `{target_incident.incident_id}`")

        col_left, col_right = st.columns([1, 1], gap="large")

        # LEFT COLUMN: TELEMETRY, TWO-TIER DETECTION & ZERO TRUST RISK
        with col_left:
            st.markdown("#### 1. Telemetry & Cyber-Physical Context")
            m1, m2, m3 = st.columns(3)
            m1.metric("Source IP", target_incident.source_ip or "N/A")
            m2.metric("Destination IP", target_incident.destination_ip or "N/A")
            m3.metric("Protocol", (target_incident.protocol or "N/A").upper())

            c_asset1, c_asset2, c_asset3 = st.columns(3)
            c_asset1.metric("Asset ID", target_incident.asset_id)
            c_asset2.metric("Criticality Tier", f"{target_incident.asset_criticality} / 5")
            worker_display = f"{target_incident.worker_distance_m}m (Active)" if target_incident.human_worker_present else "No Worker Present"
            c_asset3.metric("Worker Proximity", worker_display)

            st.markdown("#### 2. Two-Tier Hierarchical Detection")
            d1, d2 = st.columns(2)
            with d1:
                st.write(f"**Tier 1 Edge (Decision Tree):**")
                st.write(f"• Prediction: `{target_incident.edge_prediction}`")
                st.write(f"• Confidence: `{target_incident.edge_confidence * 100:.2f}%`")
                st.write(f"• Fast-Tracked: `{'Yes' if target_incident.fast_tracked else 'No (Escalated to Fog)'}`")
            with d2:
                st.write(f"**Tier 2 Fog (PyTorch DNN):**")
                if target_incident.fog_prediction:
                    st.write(f"• Prediction: `{target_incident.fog_prediction}`")
                    st.write(f"• Confidence: `{target_incident.fog_confidence * 100:.2f}%`")
                    st.write(f"• Multiclass Model: `FogDNN (15 Classes)`")
                else:
                    st.write("• *Bypassed by Tier 1 Fast-Track (Benign Line-Rate Bypass)*")

            st.markdown("#### 3. Bounded Zero Trust Composite Risk")
            st.markdown(
                f"""
                <div style="background: #F1F5F9; padding: 12px 16px; border-radius: 8px; margin-bottom: 10px;">
                    <div style="font-size: 1.25rem; font-weight: 700; color: #0F172A;">
                        Composite Risk: {target_incident.risk_score:.2f} / 100.00
                        <span class="badge badge-{target_incident.risk_level.lower()}">{target_incident.risk_level}</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #475569; margin-top: 4px;">
                        Formula: R = 100 × (0.35·S + 0.20·C + 0.20·A + 0.15·H + 0.10·X)
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Risk breakdown metrics
            if target_incident.risk_components:
                rc = target_incident.risk_components
                r1, r2, r3, r4, r5 = st.columns(5)
                r1.metric("Threat (S)", f"{rc.get('normalized_threat_severity', 0.0):.2f}")
                r2.metric("Conf (C)", f"{rc.get('normalized_confidence', 0.0):.2f}")
                r3.metric("Asset (A)", f"{rc.get('normalized_asset_criticality', 0.0):.2f}")
                r4.metric("Worker (H)", f"{rc.get('normalized_human_proximity', 0.0):.2f}")
                r5.metric("XAI (X)", f"{rc.get('normalized_xai_alignment', 0.0):.2f}")

            st.markdown("#### 4. Policy Decision Point (PDP)")
            st.info(f"**Policy Action Enforced:** `{target_incident.policy_action}`\n\n**Rule Triggered:** `{target_incident.pdp_rule_triggered}`")
            if target_incident.safety_advisory:
                st.warning(f"⚠️ **Safety Advisory Notice:** {target_incident.safety_advisory}")

            with st.expander("💻 View Simulated Enforcement Commands"):
                for cmd in target_incident.simulated_enforcement:
                    st.markdown(f'<div class="cmd-box">{cmd}</div>', unsafe_allow_html=True)

        # RIGHT COLUMN: EXPLAINABLE AI (SHAP) & HUMAN IN THE LOOP ACTIONS
        with col_right:
            st.markdown("#### 5. Explainable AI (XAI) Attribution Reasons")
            st.write(f"**SHAP Alignment Score:** `{target_incident.xai_alignment_score if target_incident.xai_alignment_score is not None else 0.0:.2f} / 1.00`")

            if target_incident.xai_top_features:
                xai_df = pd.DataFrame(target_incident.xai_top_features)
                chart = (
                    alt.Chart(xai_df)
                    .mark_bar()
                    .encode(
                        x=alt.X("shap_value:Q", title="SHAP Attribution (Impact on Attack Prediction)"),
                        y=alt.Y("feature_name:N", sort="-x", title="Network Telemetry Feature"),
                        color=alt.condition(
                            alt.datum.shap_value > 0,
                            alt.value("#EF4444"),  # Red for pushing towards attack
                            alt.value("#10B981"),  # Green for pushing towards benign
                        ),
                        tooltip=["feature_name", "shap_value", "baseline_value"],
                    )
                    .properties(height=220)
                )
                st.altair_chart(chart, use_container_width=True)
                st.caption("🔴 Red bars indicate features pushing the neural network towards attack prediction.")
            else:
                st.info("No XAI feature attributions generated (Flow was fast-tracked at Tier 1 Edge Decision Tree).")

            st.markdown("---")
            st.markdown("#### 6. Human-in-the-Loop (HITL) Authorization")
            curr_status = target_incident.incident_status.value
            st.markdown(f"**Current Status:** <span class=\"badge badge-{curr_status.lower().replace('_', '-')}\">{curr_status}</span>", unsafe_allow_html=True)

            analyst_name = st.text_input(
                "SOC Analyst / Operator Identity",
                value="Ishan Verma (SOC Analyst)",
                key=f"analyst_{target_incident.incident_id}",
            )
            analyst_comment = st.text_area(
                "Review Rationale & Decision Justification",
                placeholder="Enter justification for approving/releasing flow or confirming malicious quarantine...",
                key=f"comment_{target_incident.incident_id}",
            )

            btn_col1, btn_col2 = st.columns(2)
            with btn_col1:
                approve_enabled = curr_status in [IncidentStatus.PENDING_REVIEW.value, IncidentStatus.QUARANTINED.value, IncidentStatus.KEEP_QUARANTINED.value]
                if st.button(
                    "✅ Approve & Release Flow",
                    disabled=not approve_enabled,
                    help="Release network isolation and grant access. Records false-positive or authorized exception.",
                    use_container_width=True,
                    type="primary",
                ):
                    updated = service.approve_incident(
                        incident_id=target_incident.incident_id,
                        analyst_name=analyst_name,
                        comment=analyst_comment or "Operator verified flow as legitimate. Manual permit granted.",
                    )
                    st.success(f"Incident {target_incident.incident_id} successfully RELEASED.")
                    st.rerun()

            with btn_col2:
                reject_enabled = curr_status in [IncidentStatus.PENDING_REVIEW.value, IncidentStatus.QUARANTINED.value]
                if st.button(
                    "🚫 Reject & Enforce Quarantine",
                    disabled=not reject_enabled,
                    help="Confirm attack and permanently retain isolation. Blocks flow.",
                    use_container_width=True,
                ):
                    updated = service.reject_incident(
                        incident_id=target_incident.incident_id,
                        analyst_name=analyst_name,
                        comment=analyst_comment or "Operator verified attack. Permanent quarantine locked.",
                    )
                    st.error(f"Incident {target_incident.incident_id} locked in KEEP_QUARANTINED state.")
                    st.rerun()

            st.markdown("---")
            st.markdown("#### 7. Immutable Audit Trail & Status History")
            if target_incident.status_history:
                for entry in reversed(target_incident.status_history):
                    st.markdown(
                        f"""
                        <div style="border-left: 3px solid #6366F1; padding-left: 10px; margin-bottom: 8px;">
                            <span style="font-size:0.75rem; color:#64748B;">{entry.timestamp}</span><br/>
                            <b>{entry.from_status} → {entry.to_status}</b> by <i>{entry.updated_by}</i><br/>
                            <span style="font-size:0.85rem; color:#334155;">{entry.comment or 'No comment provided.'}</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.caption("No lifecycle history entries recorded.")
