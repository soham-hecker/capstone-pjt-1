# Review Panel Presentation Guide & Viva Defense Cheat Sheet
**Project Title:** *A Self-Adaptive Zero Trust Cybersecurity Architecture for Industry 5.0 Enabled by Multi-Agent AI*  
**Academic Institution:** Vellore Institute of Technology (VIT), Chennai Campus  
**Authors:** Ishan Verma (`23BAI1198`), Sanskar Pandey (`23BAI1197`), Soham Sinha (`23BAI1223`)  
**Faculty Guide:** Dr. Manjula V (Associate Professor, SCOPE)

---

## 1. Executive Summary for Evaluators

Industry 5.0 integrates human workers and collaborative robots (cobots) into shared physical workspaces. Traditional perimeter firewalls and black-box ML systems fail because:
1. They cannot adapt to cyber-physical risks (worker distance, machine velocity).
2. Deep learning "black boxes" cannot be audited during safety-critical incidents.
3. Edge devices cannot afford the latency of heavy models, while Fog servers require multi-class categorization.

### What Our Architecture Solves:
1. **Two-Tier Detection:**
   - **Tier 1 Edge:** Ultra-fast Decision Tree ($0.047\ \mu\text{s}$, $99.77\%$ accuracy). Verified benign flows bypass deep models via **Fast-Track Line-Rate Routing** ($1.75\ \text{ms}$ total pipeline latency).
   - **Tier 2 Fog:** 15-class PyTorch Deep Neural Network ($95.11\%$ accuracy, $0.9934$ ROC-AUC) classifying complex exploits.
2. **Explainable AI (XAI):**
   - Local SHAP (`DeepExplainer`) attributions against $K=100$ training background centroids with verified additivity consistency (mean abs discrepancy $0.1189$).
3. **Mathematically Bounded Zero Trust Composite Risk:**
   - Evaluates continuous risk $R \in [0.0, 100.0]$ across Threat Severity ($S$), Detection Confidence ($C$), Asset Criticality ($A$), Human Proximity ($H$), and XAI Alignment ($X$).
4. **Human-in-the-Loop (HITL) Web Dashboard (Phase 8C):**
   - High-risk threats near workers or ambiguous model inferences ($conf < 0.70$) trigger Policy Decision Point (PDP) escalation.
   - Operators inspect requests in structured tabular rows with live XAI explanations and execute auditable **Approve (Release)** or **Reject (Keep Quarantined)** actions.

---

## 2. Review Presentation Structure (12–15 Minutes Total)

| Time | Slide / Topic | Key Points to Highlight | Presenter |
| :--- | :--- | :--- | :--- |
| **0:00 – 2:00** | **Problem Statement & Dataset** | IT/OT convergence, Edge-IIoTset benchmark dataset (2.2M flows, 15 classes), cyber-physical hazards in Industry 5.0. | Team Member 1 |
| **2:00 – 4:30** | **Two-Tier ML & XAI Formulation** | Tier 1 Edge DT ($0.047\ \mu\text{s}$) vs Tier 2 Fog PyTorch DNN ($95.11\%$). SHAP DeepExplainer additivity audit. | Team Member 2 |
| **4:30 – 6:30** | **Multi-Agent Orchestration & Risk Engine** | LangGraph StateGraph (6 nodes). Mathematically bounded risk $R \in [0, 100]$. Deterministic Policy Decision Point (PDP). | Team Member 3 |
| **6:30 – 11:30** | **LIVE DASHBOARD VIVA DEMO** | Launch `run_dashboard.py`. Demonstrate all 4 production scenarios, SHAP visualizer, and Human Approve/Reject actions. | All Members |
| **11:30 – 15:00** | **Panel Q&A Defense** | Answer faculty questions using the cheat sheet below. | All Members |

---

## 3. Step-by-Step Viva Live Demonstration Script

### Preparation Before the Panel Arrives:
1. Open terminal in project root:
   ```bash
   python experiments/run_dashboard.py
   ```
2. Open browser at `http://localhost:8501`.
3. Click **"Reset to Benchmark Defaults"** in the sidebar to ensure clean starting data.

---

### Step 1: Explain the High-Level Dashboard Interface (1 Minute)
* **What to say to the panel:**  
  *"Respected panel members, this is our Phase 8C Human-in-the-Loop Security Operations Center (SOC) dashboard. At the top, you can see live operational KPIs: total flows evaluated, pending human reviews, active quarantines, and average composite risk across the industrial cell. In the center is our Active Detection Queue, where each telemetry event is presented in a separate row with its network flow, target asset, worker distance, detection verdict, risk score, and XAI feature reasons."*

---

### Step 2: Demonstrate Scenario 4 — Ambiguous Threat & Human Approval (2 Minutes)
1. In the sidebar, click **"❓ Inject Scenario 4: Ambiguous Threat"** or select `INC-DEMO-004-AMBIGUOUS` from the dropdown.
2. *Point to the screen:*
   - **Explain the Ambiguity:** The Fog DNN prediction is `DDoS_HTTP`, but the model confidence is only **$48.57\%$** (under our $70\%$ ambiguity threshold). Because the target is a safety-critical PLC (`SAFETY-PLC-CELL-1`) with a human worker at $1.5\ \text{m}$, the autonomous agent **refuses to take a unilateral guess**.
   - **PDP Action:** Triggers `ESCALATE_TO_HUMAN_AMBIGUOUS` and places the request in `PENDING_REVIEW` with an iptables `TARPIT` hold.
3. *Show the XAI Panel:*
   - Look at the horizontal SHAP bar chart: Top features are `http.content_length` ($+0.38$) and `tcp.dstport` ($+0.29$).
4. *Perform the Human Approval Action:*
   - In **SOC Analyst Identity**, type your name: `Ishan Verma (SOC Analyst)`.
   - In **Review Rationale**, type: `Verified as scheduled HTTP diagnostic health check from engineering workstation. False positive confirmed.`
   - Click **"✅ Approve & Release Flow"**.
   - *Result to show the panel:* The status badge immediately updates to **`RELEASED`**, and the immutable **Status History** logs the transition with timestamp and rationale.

---

### Step 3: Demonstrate Scenario 3 — Critical Poisoning Near Worker & E-STOP (2 Minutes)
1. In the sidebar, click **"🚨 Inject Scenario 3: MITM Near Worker"** or select `INC-DEMO-003-MITM`.
2. *Point to the screen:*
   - **Risk Score:** **$92.96 / 100$ (CRITICAL)**.
   - **Context:** An active ARP/MITM poisoning attack targeting `ROBOT-ARM-CELL-3` with a human worker at **$1.2\ \text{m}$**.
   - **Safety Advisory:** Notice the banner:  
     `ADVISORY: Emergency Stop recommended. Autonomous physical actuation disabled by safety policy. Operator confirmation required.`
   - **Explain the Industry 5.0 Safety Guarantee:**  
     *"In our research paper, we enforce the rule that software AI agents must NEVER autonomously trigger emergency machinery stops (E-STOP) without human operator confirmation, as abrupt halts can damage multi-ton industrial robotic joints or injure nearby operators."*
3. *Perform the Rejection Action:*
   - Click **"🚫 Reject & Enforce Quarantine"**.
   - *Result to show the panel:* Status transitions to **`KEEP_QUARANTINED`**, locking down the source IP with eBPF drop rules.

---

### Step 4: Demonstrate Scenario 1 — Tier 1 Edge Fast-Tracking (1 Minute)
1. Select `INC-HIST-001-NORMAL`.
2. *Point to the screen:*
   - Prediction is `Normal` with $100\%$ confidence.
   - **Fast-Track Indicator:** `Yes (Bypassed Fog DL & XAI)`.
   - **Latency:** Executed in sub-millisecond line-rate speed ($1.75\ \text{ms}$ total pipeline latency).
   - This proves our two-tier architecture preserves real-time manufacturing throughput.

---

## 4. Anticipated Review Panel Questions & Model Answers

### Q1: Why is Human-in-the-Loop necessary if your neural network has 95%+ accuracy?
> **Answer:**  
> *"In safety-critical Industry 5.0 manufacturing cells, even a $1\%$ or $5\%$ error rate is unacceptable because false positives can shut down production lines costing thousands of dollars per minute, and false negatives near human workers can cause physical injury. Furthermore, AI models experience covariate shift and adversarial evasion in industrial environments. Our architecture autonomously handles obvious benign traffic and routine attacks, but reserves human cognitive judgment specifically for ambiguous flows (confidence $< 0.70$) and safety-critical machine stops."*

---

### Q2: What is the exact mathematical formulation of your Zero Trust Risk Score?
> **Answer:**  
> *"Our composite risk formula is strictly bounded to $[0.0, 100.0]$:  
> $$R = 100.0 \times \Big( 0.35 \cdot S + 0.20 \cdot C + 0.20 \cdot A + 0.15 \cdot H + 0.10 \cdot X \Big)$$  
> Where $S$ is threat severity, $C$ is detection confidence, $A$ is asset criticality ($1$ to $5$), $H$ is human proximity calculated from physical worker distance in meters, and $X$ is XAI domain alignment. The constituent weights sum to exactly $1.00$, preventing overflow or heuristic drift."*

---

### Q3: How does SHAP help the human operator make a decision?
> **Answer:**  
> *"Deep neural networks produce a raw classification label like `DDoS_HTTP` or `Port_Scanning`. A human operator cannot trust a raw label without context. Our XAI tool generates local Shapley attributions using SHAP `DeepExplainer` against $K=100$ training centroids. The operator can visually see which specific packet attributes (e.g., `arp.opcode`, `tcp.dstport`, `http.content_length`) pushed the model toward the prediction, allowing the human to determine whether it is an authentic exploit or a benign maintenance artifact."*

---

### Q4: Why did you use LangGraph instead of a standard sequential script or an LLM?
> **Answer:**  
> *"First, LLMs are non-deterministic, have high latency ($500\text{ms}-2000\text{ms}$), and can hallucinate security decisions—making them unsuitable for hard real-time network containment.  
> Second, a linear script cannot handle conditional routing. We used **LangGraph StateGraph** because it compiles a deterministic, typed state machine that supports conditional branching: verified benign flows fast-track directly from Tier 1 Edge to Decision, skipping Fog DL and XAI, while suspicious flows branch to deep forensic analysis."*

---

### Q5: How do you handle data persistence if the database is offline during an evaluation?
> **Answer:**  
> *"We implemented an abstracted repository pattern with a `BaseQuarantineStore` interface. While MongoDB is supported for production environments, our dashboard uses a persistent atomic local JSON store (`data/incidents_db.json`) adhering strictly to the same finite state machine. This ensures $100\%$ deterministic persistence across browser refreshes and system restarts without external network dependencies."*

---

## 5. Verification Checklist for the Presentation

- [x] All 8 tests in `tests/test_dashboard_service.py` pass.
- [x] All 18 tests in `experiments/validate_phase8a.py` pass.
- [x] All 16 tests in `experiments/validate_phase7.py` pass.
- [x] All 10 tests in `pytest tests/` pass.
- [x] Dashboard launches cleanly via `python experiments/run_dashboard.py`.
- [x] Streamlit opens at `http://localhost:8501`.
- [x] Approval and Rejection actions persist to `data/incidents_db.json`.
