# CyberTrace SOC Platform — Deployment & Judge Evaluation Guide
## Smart India Hackathon 2026 // Problem Statement 26106

---

## 🚀 Quick Start (1-Command Docker Deployment)

Run the entire platform with pre-bundled frontend, backend, and deterministic forensic pipelines:

```bash
# 1. Build and run container
docker compose up --build

# 2. Open in browser
http://localhost:3000
```

---

## 💻 Local Development Setup

```bash
# 1. Install dependencies
npm install

# 2. Run local development server (with Vite HMR)
npm run dev
# Server listens at http://localhost:3000

# 3. Run production build
npm run build

# 4. Run production server
npm run start

# 5. Run full automated test suite (245/245 tests across 16 suites)
npm test

# 6. Run TypeScript static type check
npm run lint
```

---

## 👥 Seeded Role-Based Access Control (RBAC) Accounts

| Role | Name | Email | Password | Scope & Permissions |
|---|---|---|---|---|
| **ADMIN** | Chief SOC Admin | `admin@soc.internal` | `Admin@SOC2026!` | Full enterprise access, manage cases, tamper simulation & ledger reseal |
| **SENIOR_ANALYST** | Aditi Rao | `senior@soc.internal` | `Senior@SOC2026!` | Case investigations, priority escalation, notes, reassignments |
| **ANALYST** | Vikramaditya Sharma | `analyst@soc.internal` | `Analyst@SOC2026!` | Primary forensic investigator, case ownership, evidence submission |
| **ANALYST** | Neha Patel | `analyst2@soc.internal` | `Analyst2@SOC2026!` | Secondary investigator (used for multi-tenant isolation testing) |
| **AUDITOR** | Rohan Gupta | `auditor@soc.internal` | `Auditor@SOC2026!` | **Read-only compliance**, inspect evidence, verify ledger, view reports |

---

## 📋 Judge 10-Minute Demonstration Script

### Step 1: SOC Executive Dashboard & Telemetry
1. Log in or open `http://localhost:3000`.
2. View **SOC Dashboard**: Threat categories, risk distribution charts, priority campaigns, and recent threats.
3. Notice **100% deterministic scoring** with explainable factor breakdown.

### Step 2: Email Forensic Investigation & Parser
1. Click **"Analyze Email"** in the sidebar.
2. Select **"Load BEC Scenario"** or paste any RFC-822 raw email.
3. Review:
   - Header authentication (SPF, DKIM, DMARC)
   - Originating IP geolocation & hop analysis
   - Threat classification & confidence
   - MITRE ATT&CK technique mappings
   - Automated timeline reconstruction

### Step 3: Blockchain Evidence Ledger & Tamper Detection
1. Navigate to **"Evidence Ledger"** in the sidebar.
2. Observe cryptographic SHA-256 hash chains locking each evidence block.
3. Switch to **Admin profile** via profile icon in TopBar.
4. Click **"Simulate Tampering"** on Block #1.
   - Watch the chain break in real-time.
   - Auditor and analysts immediately see tampering warnings.
5. Click **"Cryptographic Repair & Reseal"** to restore immutable chain integrity.

### Step 4: Real-time Threat Alerting (Phase 11)
1. Trigger a high-risk analysis or Gmail sync.
2. Observe the real-time **Server-Sent Events (SSE)** floating threat toast in the top-right.
3. Click **"Inspect Case"** on the toast to jump directly into the case.

### Step 5: Threat Hunting & Indicator Correlation (Phase 12)
1. Click **"Threat Hunting"** in the sidebar.
2. Search for `hxxp://evil-login[.]com` or `198.51.100.22`.
3. Notice:
   - Automatic defang detection & refang normalization.
   - Correlation across cases, extracted IOCs, and active threat campaigns.
   - Microsecond query latency (<5ms).

### Step 6: Evidence-Grade Forensic Report Export (Phase 10)
1. Navigate to **"Forensic Reports"** in the sidebar.
2. Review the ISO/IEC 27037 compliant 18-section dossier.
3. Click **"Print / Save as PDF"** for a clean, court-ready printable document.
4. Click **"Download JSON"** for raw structured SIEM export.

---

## 🛡️ Architecture Highlights
- **Deterministic Risk Engine**: Weighted 6-factor Bayesian composite.
- **Strict Zero-Gemini Boundary**: All core forensic pipelines execute deterministically with zero third-party cloud API dependencies.
- **Enterprise RBAC & Multi-Tenant Isolation**: Verified with automated tests preventing cross-tenant leakage.
- **Evidence Immutability**: Blockchain-backed SHA-256 ledger with cryptographic tamper detection.
