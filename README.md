# TrustVault — Secure Sharing, Smarter Access, Verifiable Accountability

> **TrustVault** is a secure, multi-tenant document management and sharing platform engineered to empower organizations to securely upload, categorize, and distribute confidential files with granular, role-based access control (RBAC) and immutable audit logging.

---

## 📌 The Problem

Modern enterprises and teams frequently handle sensitive documentation (financial reports, legal contracts, proprietary designs, and identity records). Traditional sharing tools often lack:
1. **Granular Access Boundaries**: Difficulty distinguishing between global administrators, resource owners, and read-only viewers.
2. **Unauthorized Privilege Escalation**: Inadequate permission checks that allow non-owners to modify or revoke access rules.
3. **Accountability Gaps**: Missing or fragmented visibility into user session lifecycles, unauthorized access attempts, and document interactions.

**TrustVault** solves this by enforcing a strict **3-Tier Role Hierarchy** (Admin, Owner, Viewer), guaranteeing that only authenticated document owners and platform administrators can grant or revoke file privileges, preventing unauthorized access with strict boundary enforcement.

---

## 🚀 Key Features & What Was Built

### 1. Robust Authentication & User Lifecycle
- **Secure Registration & Login**: User authentication with password hashing and session validation.
- **Profile Management**: Capabilities for users to update personal credentials and profile avatars securely.

### 2. Strict Role-Based Access Control (RBAC)
- **Admin**: Full oversight over platform metrics, registered users, system-wide documents, and security audit logs.
- **Owner**: Full lifecycle control over self-uploaded documents, including granting/revoking viewer permissions and deletion rights.
- **Viewer**: Read-only access to documents explicitly shared with them, without access to administrative controls or owner-level settings.

### 3. Document Management Engine
- **My Documents**: Dedicated dashboard view summarizing uploaded assets, metadata, category tags, and direct deletion options.
- **Filtered Search**: Multi-parameter search capability filtering by date range, category tags, document title, and document owner.
- **Secure Document Upload & Sharing**: Upload pipeline with immediate permission mapping to assign viewers securely.

### 4. Verifiable Accountability & Security Dashboard
- **Admin Metrics**: Overview of uploaded documents, active users, shared records, and real-time security posture.
- **Audit Logging**: Comprehensive login/logout activity logs reserved strictly for administrator oversight to maintain auditability.

---

## 🛠️ Technology Stack

- **Backend**: Python, Flask, Flask-Login, Werkzeug Security
- **Database**: SQLite / SQLAlchemy ORM
- **Frontend**: HTML5, CSS3, JavaScript (Custom Dark Theme with Emerald Green Accents)
- **AI-Assisted Development**: Prompt-engineered workflows using ChatGPT for design validation, Flask debugging, and route structuring.

---

## 💻 Installation & Setup

### Prerequisites
- Python 3.8+ installed
- PowerShell or Terminal environment

### Step-by-Step Setup

1. **Navigate to the Project Directory**:
   ```powershell
   cd "D:\Jahnavi_certificates\synovasis project"
   ```

2. **Create & Activate Virtual Environment**:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **Install Dependencies**:
   ```powershell
   python -m pip install -r requirements.txt
   ```

4. **Launch Application**:
   ```powershell
   python run.py
   ```

5. **Access TrustVault**:
   Open your browser and navigate to:
   ```
   http://127.0.0.1:5000/
   ```

6. **Run Automated Security Tests**:
   Verify document isolation and RBAC security invariants:
   ```powershell
   python test_security.py
   ```

---

## 🤖 AI Tools & Human-in-the-Loop Refinements

### AI Tools Utilized
- **ChatGPT**: Architecture brainstorming, Flask route debugging, initial boilerplate scaffolding, and dependency configuration.

### What the AI Got Wrong & My Fixes
- **Theme & Design Consistency**: AI generated palettes using mismatched accents (e.g., high-contrast neon yellow over black). I restructured the design system to a custom, professional **dark slate and emerald green** color scheme suited for an enterprise security tool.
- **Redundant Scaffolding & File Structure**: AI initially suggested auxiliary, bloated boilerplate files that complicated the architecture. I eliminated unnecessary files and established a lean, modular structure.
- **Permission Bug Fixes**: AI-generated access rules occasionally had loose edge cases around privilege verification. I manually implemented robust permission checks to prevent non-owners from managing access rules.
- **Prompt Iteration**: Iteratively refined engineering prompts to obtain targeted backend logic and clean SQLAlchemy queries rather than accepting generic templates.

---

## 🔮 Current Limitations & Future Roadmap

- **Completed**: End-to-end user authentication, document upload/download lifecycle, granular document sharing with RBAC, filtered search, and admin audit logging.
- **Desktop vs. Mobile Responsiveness**: The desktop web experience is fully functional and styled; however, responsive layouts for compact mobile screens need further refinement.
- **Next Milestones**:
  - Implement full responsive breakpoints and a mobile-first sidebar drawer.
  - End-to-end file encryption at rest (AES-256).
  - Time-limited expiring access links with one-time view tokens.
