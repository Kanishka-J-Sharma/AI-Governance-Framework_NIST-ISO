# AI Governance Framework: NIST AI RMF to ISO 27001 Crosswalk

## 🎯 Project Overview
This repository hosts a high-impact governance framework designed to bridge the gap between emerging **Adversarial AI risks** and established **Information Security Management Systems (ISMS)**.

As an extension of my **Cybersecurity Engineering** studies at UWB, this project demonstrates how to architect a "Secure-by-Design" environment for **LLM Coding Assistants** using the **NIST AI RMF 1.0** and **ISO/IEC 27001:2022**.

---

## 📂 Project Artifacts (`/docs`)
| Artifact | Description |
|---|---|
| [Project Charter](./docs/Project_Charter.pdf) | Strategic scope and risk appetite for AI adoption |
| [NIST-ISO Mapping Matrix](./docs/NIST_ISO_Mapping.pdf) | Technical crosswalk between NIST AI RMF functions and ISO 27001:2022 controls |
| [Acceptable Use Policy (AUP)](./docs/Gen_AI_Acceptable_Use_Policy.pdf) | Enforceable corporate standards for Generative AI usage |
| [Technical Risk Brief](./docs/Technical_Risk_Brief.pdf) | Engineering-level analysis of Prompt Injection and Data Leakage |
| [AI Risk Register](./docs/AI_Risk_Register_and_Treatment_Plan.pdf) | Operational tracking of LLM-specific vulnerabilities and treatment plans |

---

## 🤖 Automated Risk Workflow (`/scripts`)

### `ai_governance_evaluator.py`
A Python script that evaluates AI agent outputs against the governance control registry, automatically flagging violations and generating a structured compliance report.

**Detects:**
- 🚨 **Prompt Injection** — jailbreak attempts, instruction overrides (maps to MAP-1.5, MANAGE-2.2)
- 🔐 **Data Leakage** — PII, emails, SSNs, confidential markers (maps to MEASURE-2.5, MAP-1.5)
- 🛋️ **Policy Violations** — GenAI AUP breaches, harmful content generation (maps to GOVERN-1.1, MAP-2.2)
- 📉 **Drift Anomalies** — unexplainable model behavior patterns (maps to MEASURE-2.5, MEASURE-2.6)

**Run demo:**
```bash
python scripts/ai_governance_evaluator.py
```

**Run against your own CSV** (columns: `agent_id`, `output`):
```bash
python scripts/ai_governance_evaluator.py scripts/sample_agents.csv
```

**Sample output:**
```
============================================================
  AI Governance Risk Evaluator
  NIST AI RMF 1.0 x ISO/IEC 27001:2022
============================================================

[-->] Running demo evaluation...

  [PASS] AGENT-001: 0 finding(s)
  [FAIL] AGENT-002: 3 finding(s)
  [FAIL] AGENT-003: 3 finding(s)
  [PASS] AGENT-004: 0 finding(s)
  [FAIL] AGENT-005: 3 finding(s)

[OK] Report saved to: governance_report.json
     Agents: 5 evaluated | 2 PASS | 3 FAIL
     Compliance rate: 40.0%
     CRITICAL findings: 6 -- immediate remediation required
```

The generated `governance_report.json` maps every finding to its NIST AI RMF function and ISO 27001:2022 control, enabling direct traceability from AI behavior to governance requirement.

---

## 🛠️ Core Competencies Demonstrated
- **Framework Interoperability**: NIST AI RMF 1.0, ISO/IEC 27001:2022, GDPR/CCPA
- **Threat Modeling**: Prompt Injection, Jailbreaking, Inference Telemetry Leakage
- **GRC Engineering**: Translating high-level policy into technical control implementations
- **Security Automation**: Python-based risk workflow evaluation and compliance reporting

---

## 📊 NIST AI RMF Core Function Mapping

| NIST Function | Controls Implemented | ISO 27001 Mapping |
|---|---|---|
| GOVERN | 1.1 — Policy documentation & approval | A.5.1 |
| MAP | 1.5 — Threat source identification | A.8.8 |
| MAP | 2.2 — AI risk identification practices | A.5.23 |
| MEASURE | 2.5 — Output evaluation (bias, drift, leakage) | A.8.16 |
| MEASURE | 2.6 — Risk metrics tracking | A.5.36 |
| MANAGE | 1.3 — Risk prioritization by impact | A.5.29 |
| MANAGE | 2.2 — Incident response activation | A.5.26 |
