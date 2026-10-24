# TrustVault — Complete Code Explanation & Presentation Guide

> **Created for:** Jahnavi  
> **Use this guide to:** Confidently explain your project architecture, code logic, and role-based security system during your presentation and evaluation tomorrow.

---

## 📋 Table of Contents
1. [Project Overview in 60 Seconds (Opening Pitch)](#1-project-overview-in-60-seconds)
2. [Architecture & Technology Stack](#2-architecture--technology-stack)
3. [Project Directory Structure](#3-project-directory-structure)
4. [Line-by-Line Code Explanation](#4-line-by-line-code-explanation)
   - [A. Entry Point: `run.py`](#a-entry-point-runpy)
   - [B. Application Factory: `app/__init__.py`](#b-application-factory-app__init__py)
   - [C. Database Models: `app/models.py`](#c-database-models-appmodelspy)
   - [D. Controller Logic: `app/routes.py`](#d-controller-logic-approutespy)
   - [E. UI & Templates](#e-ui--templates)
5. [Live Demo Walkthrough (Step-by-Step)](#5-live-demo-walkthrough-step-by-step)
6. [Expected Questions & Winning Answers](#6-expected-questions--winning-answers)

---

## 1. Project Overview in 60 Seconds
*(Read or memorize this opening pitch for tomorrow)*

> *"Good morning/afternoon. Today I am presenting **TrustVault**, a multi-tenant, secure document-sharing platform engineered to deliver **Secure Sharing, Smarter Access, and Verifiable Accountability**.*
>
> *In enterprise environments, sensitive records—like financial audits, contracts, and IP—are often mishandled due to loose permission boundaries and a lack of audit visibility.*
>
> *TrustVault solves this by enforcing a strict **3-Tier Role-Based Access Control (RBAC)** architecture:*
> 1. ***Admin***: *Has full system telemetry, security status oversight, user management, and exclusive access to tamper-evident activity logs.*
> 2. ***Owner***: *Can securely upload documents, categorize them, and exclusively grant or revoke viewing rights to specific users.*
> 3. ***Viewer***: *Possesses strictly read-only access to documents explicitly shared with them, with zero access to admin dashboards, logs, or permission management.*
>
> *Let me walk you through how the code works and demonstrate the live system."*

---

## 2. Architecture & Technology Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3 + Flask | Lightweight, modular WSGI application handling routing and requests. |
| **Authentication** | Flask-Login + Werkzeug | Session persistence, secure cookie management, and salted password hashing (PBKDF2/SHA-256). |
| **ORM & Database** | SQLAlchemy + SQLite | Relational database mapping with foreign key cascades and relational integrity. |
| **Frontend UI** | HTML5, CSS3, JavaScript | Custom dark theme with obsidian black and emerald green accents, fully responsive with SVG icons. |
| **Security Controls** | Custom Python Decorators | `@admin_required` and `@owner_or_admin_required` route guards. |

---

## 3. Project Directory Structure

```text
synovasis project/
│
├── run.py                 # Main execution script to launch the local web server
├── requirements.txt       # Dependencies (Flask, Flask-Login, Flask-SQLAlchemy, etc.)
├── trustvault.db          # SQLite relational database file
├── README.md              # Project documentation
├── SUBMISSION.md          # Polished answers for the hackathon submission portal
├── EXPLANATION_GUIDE.md   # This presentation and code breakdown guide
│
└── app/
    ├── __init__.py        # App factory, database config, and automatic initial data seeder
    ├── models.py          # Database schema (User, Document, Permission, ActivityLog, Category)
    ├── routes.py          # Route handlers, RBAC logic, upload/download, search, and logs
    │
    ├── static/
    │   ├── css/
    │   │   └── style.css  # Obsidian black & emerald green design system
    │   ├── js/
    │   │   └── main.js    # Client-side helpers (modal popups, auto-dismissing alerts)
    │   └── uploads/
    │       ├── documents/ # Encrypted/stored document binaries
    │       └── avatars/   # User profile images
    │
    └── templates/
        ├── base.html          # Base layout with role-aware dynamic navigation bar
        ├── index.html         # Landing page highlighting 3-tier RBAC architecture
        ├── login.html         # Login form with instant 1-click role demo switchers
        ├── register.html      # User registration with Owner vs. Viewer role selection
        ├── dashboard.html     # Adaptive dashboard (Admin telemetry vs. Owner/Viewer views)
        ├── my_documents.html  # Document management table with upload, delete & share modal
        ├── shared_with_me.html# Read-only documents shared with the logged-in viewer
        ├── upload.html        # Secure document upload with immediate sharing permissions
        ├── search.html        # Multi-filter search (keyword, category, owner, date)
        ├── categories.html    # Departmental classification breakdown
        ├── activity_logs.html # Admin-only tamper-evident audit trail
        ├── profile.html       # Profile image upload and secure password change
        └── admin_users.html   # Admin user table for changing tenant roles
```

---

## 4. Line-by-Line Code Explanation

### A. Entry Point: `run.py`
```python
from app import create_app
app = create_app()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
```
- **What to explain**:
  - `create_app()` follows the standard **Flask Application Factory Pattern**. It initializes the database, configures file upload directories, sets secret keys, and registers blueprints.
  - `app.run(debug=True)` runs the local server on port `5000` with hot-reloading enabled.

---

### B. Application Factory: `app/__init__.py`
- **Key Concepts**:
  1. `app.config['UPLOAD_FOLDER']` points to `app/static/uploads/documents` where uploaded files are safely stored.
  2. `login_manager = LoginManager()` binds Flask-Login to handle session cookies.
  3. `seed_initial_data()` runs automatically when the database is empty:
     - Pre-seeds 5 enterprise categories (*Financial, Legal & Contracts, HR, Confidential / IP, Technical Specs*).
     - Pre-seeds 3 demo accounts (*Admin, Owner, Viewer*) and sample files so you never have to start with an empty screen.

---

### C. Database Models: `app/models.py`
Here is how to explain the 5 core tables:

#### 1. `User` Model
```python
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='owner') # admin, owner, viewer
```
- `UserMixin` gives us helper properties like `is_authenticated`.
- `set_password()` uses `generate_password_hash()` so passwords are never stored in plain text.
- Helper properties `is_admin`, `is_owner`, and `is_viewer` make route guard checks clean and readable.

#### 2. `Document` Model
- Stores `filename` (unique UUID-based safe name on disk) and `original_filename` (the human-readable file name when downloaded).
- `owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))` establishes a one-to-many relationship with the owner.
- `permissions = db.relationship('DocumentPermission', cascade="all, delete-orphan")` ensures that if a document is deleted, all sharing records are cleaned up automatically without leaving orphan database rows.

#### 3. `DocumentPermission` Model
- Represents an explicit sharing record between a document and a viewer: `document_id` + `user_id`.
- Has a `UniqueConstraint('document_id', 'user_id')` to prevent duplicate permissions.

#### 4. `ActivityLog` Model & `log_activity()` Helper
- Logs:
  - `action`: `USER_LOGIN`, `USER_LOGOUT`, `DOCUMENT_UPLOAD`, `DOCUMENT_DELETE`, `ACCESS_GRANTED`, `ACCESS_REVOKED`, `UNAUTHORIZED_ACCESS_ATTEMPT`.
  - `status`: `SUCCESS`, `WARNING`, or `FAILED`.
  - `ip_address` and `timestamp`.
- This ensures **Verifiable Accountability** for compliance and audits.

---

### D. Controller Logic: `app/routes.py`

#### 1. Custom Security Decorators:
```python
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            log_activity(action="UNAUTHORIZED_ACCESS_ATTEMPT", status="WARNING")
            flash("Access Denied: Admin privileges required.", "danger")
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated_function
```
- **What to explain**: Any route tagged with `@admin_required` checks if the user is an administrator. If a viewer or owner tries to force the URL `/activity-logs`, the decorator intercepts it, logs a security warning in the audit table, and redirects them away.

#### 2. Ownership Verification in `delete_document` & `manage_access`:
```python
if doc.owner_id != current_user.id and not current_user.is_admin:
    flash("Access Denied: Only the document owner or an administrator can manage access.", "danger")
    return redirect(url_for('main.my_documents'))
```
- **What to explain**: Even if someone crafts a malicious POST request to delete or modify another user's document, this backend check guarantees that only the authentic owner or admin can execute the action.

#### 3. Multi-Filter Search (`/search`):
- Explain how SQLAlchemy builds dynamic queries:
  - If keyword is typed: filters `Document.title.ilike()` and `description.ilike()`.
  - If category is picked: filters `Document.category_id == category_id`.
  - If date ranges are selected: filters `Document.uploaded_at >= date_from`.
  - Enforces role boundaries: Admins search all documents, Owners search their files + shared files, and Viewers search strictly shared files.

---

## 5. Live Demo Walkthrough (Step-by-Step)

Follow these exact steps when demonstrating the project:

### Step 1: Open the Application
1. In your terminal:
   ```powershell
   python run.py
   ```
2. Open browser at: `http://127.0.0.1:5000/`
3. Point out the **Landing Page** with the emerald green theme and 3-role cards.

### Step 2: Login as Admin
1. Click **Sign In**.
2. Click the quick button **"Admin"** (`admin@trustvault.com` / `Admin@123`).
3. Click **Sign In**.
4. Show the **System Dashboard**:
   - Total Documents Uploaded counter
   - Registered Users counter
   - Active Sharing Records counter
   - Security Status: **OPTIMAL** with RBAC Enforced
5. Click **Activity Logs** in the menu:
   - Show the live audit records (logins, uploads, access grants) with color-coded status badges.
6. Click **User Management**:
   - Show how an Admin can easily change any user's role from Viewer to Owner or Admin.

### Step 3: Login as Document Owner
1. Sign out and click **"Owner"** on the login page (`owner@trustvault.com` / `Owner@123`).
2. Show how the dashboard is personalized for the Owner (showing their files, not admin controls).
3. Click **Upload Document**:
   - Browse any file (PDF, image, text file).
   - Enter title: *"Confidential Project Specifications"*.
   - Select category: *"Technical Specs"*.
   - Check the box for `sarah_viewer` to grant them immediate access.
   - Click **Upload & Secure Document**.
4. Go to **My Documents**:
   - Show the file listed with size, category, and `sarah_viewer` in the "Shared With" column.
   - Click the **Share** button to demonstrate how an owner can grant access to another user or revoke it with one click.
5. Demonstrate Security:
   - Show that Owners cannot see the Activity Logs tab in the navbar.
   - Try typing `http://127.0.0.1:5000/activity-logs` in the address bar: the system instantly blocks access with an *Access Denied* flash banner and logs the unauthorized attempt!

### Step 4: Login as Viewer
1. Sign out and click **"Viewer"** on the login page (`viewer@trustvault.com` / `Viewer@123`).
2. Notice the navigation bar: "My Documents" and "Upload Document" are hidden because viewers have read-only privileges.
3. Click **Shared With Me**:
   - Show that the document shared by the Owner appears here.
   - Click **Download** to show that downloading works smoothly.

---

## 6. Expected Questions & Winning Answers

### Q1: *"How does TrustVault protect against unauthorized access or privilege escalation?"*
> **Your Answer:** *"We enforce security at three levels:*
> 1. *Route guards using Python decorators (`@login_required`, `@admin_required`).*
> 2. *Resource-level ownership checks inside controllers—ensuring a user can only delete or share a document if their `user.id` matches the document's `owner_id` or if they have an admin role.*
> 3. *Query filtering in the ORM so viewers only retrieve documents mapped in the `DocumentPermission` table."*

### Q2: *"Why did you use SQLite and SQLAlchemy?"*
> **Your Answer:** *"SQLAlchemy provides an Object Relational Mapping (ORM) layer that protects against SQL injection through parameterized queries. It also allows seamless portability: during development and local testing we use SQLite for zero-config persistence, but in production we can switch to PostgreSQL simply by updating the database URI in `app/__init__.py` without altering any model code."*

### Q3: *"How are file uploads securely handled?"*
> **Your Answer:** *"We use `werkzeug.utils.secure_filename` to sanitize input filenames and prevent path traversal attacks. In addition, when saving files to disk, we prepend a unique `uuid.uuid4()` hex string to prevent filename collisions and avoid exposing internal server paths."*

### Q4: *"How are passwords stored?"*
> **Your Answer:** *"Passwords are never stored in plain text. We utilize Werkzeug's `generate_password_hash` which implements salted SHA-256 password hashing. During authentication, `check_password_hash` verifies the hash in constant time to prevent timing attacks."*

---

*Good luck with your presentation tomorrow, Jahnavi! You have a complete, polished, and fully functional project.*
