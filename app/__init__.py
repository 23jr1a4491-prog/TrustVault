
import os

from flask import Flask
from flask_login import LoginManager

from app.models import db, User, Category, ActivityLog


def create_app():
    app = Flask(__name__)

    # Security configuration
    app.config["SECRET_KEY"] = os.environ.get("TRUSTVAULT_SECRET_KEY")

    if not app.config["SECRET_KEY"]:
        raise RuntimeError(
            "TRUSTVAULT_SECRET_KEY is not configured. "
            "Set this environment variable before starting the application."
        )

    # Database configuration
    db_path = os.path.join(
        os.path.abspath(os.path.dirname(__file__)),
        "..",
        "trustvault.db",
    )

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"sqlite:///{os.path.abspath(db_path)}"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Upload configuration
    doc_upload_folder = os.path.join(
        app.root_path, "static", "uploads", "documents"
    )
    avatar_upload_folder = os.path.join(
        app.root_path, "static", "uploads", "avatars"
    )

    os.makedirs(doc_upload_folder, exist_ok=True)
    os.makedirs(avatar_upload_folder, exist_ok=True)

    app.config["UPLOAD_FOLDER"] = doc_upload_folder
    app.config["AVATAR_FOLDER"] = avatar_upload_folder
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

    # Initialize database
    db.init_app(app)

    # Initialize login manager
    login_manager = LoginManager()
    login_manager.login_view = "main.login"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "warning"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register application routes
    from app.routes import main_bp

    app.register_blueprint(main_bp)

    # Create database tables and initialize sample data
    with app.app_context():
        db.create_all()
        if os.environ.get("TRUSTVAULT_SEED_DEMO", "false").lower() == "true":
            seed_initial_data()

    return app


def seed_initial_data():
    """Create initial categories, demo accounts, and sample documents."""

    # Seed document categories
    if Category.query.count() == 0:
        categories = [
            Category(
                name="Financial",
                description="Audit reports, invoices, balances, and payroll",
                icon="dollar-sign",
            ),
            Category(
                name="Legal & Contracts",
                description="Non-disclosure agreements, terms of service, compliance",
                icon="file-text",
            ),
            Category(
                name="Human Resources",
                description="Employee policies, onboarding documents, resumes",
                icon="users",
            ),
            Category(
                name="Confidential / IP",
                description="Trade secrets, patent filings, proprietary schematics",
                icon="shield",
            ),
            Category(
                name="Technical Specs",
                description="Architecture blueprints, API specs, security audits",
                icon="cpu",
            ),
        ]

        db.session.add_all(categories)
        db.session.commit()
        print("Default categories seeded successfully.")

    # Seed demonstration accounts
    if User.query.count() == 0:
        admin_user = User(
            username="admin",
            email="admin@trustvault.com",
            role="admin",
            profile_pic="default_avatar.png",
        )
        admin_user.set_password("Admin@123")

        owner_user = User(
            username="john_owner",
            email="owner@trustvault.com",
            role="owner",
            profile_pic="default_avatar.png",
        )
        owner_user.set_password("Owner@123")

        viewer_user = User(
            username="sarah_viewer",
            email="viewer@trustvault.com",
            role="viewer",
            profile_pic="default_avatar.png",
        )
        viewer_user.set_password("Viewer@123")

        db.session.add_all([admin_user, owner_user, viewer_user])
        db.session.commit()
        print("Default demonstration accounts created.")

    # Seed sample documents and permissions
    from app.models import Document, DocumentPermission

    if Document.query.count() == 0:
        owner = User.query.filter_by(role="owner").first()
        viewer = User.query.filter_by(role="viewer").first()
        admin = User.query.filter_by(role="admin").first()

        if owner is None:
            print("Sample documents skipped: no owner account exists.")
            return

        fin_cat = Category.query.filter_by(name="Financial").first()
        legal_cat = Category.query.filter_by(
            name="Legal & Contracts"
        ).first()
        tech_cat = Category.query.filter_by(
            name="Technical Specs"
        ).first()

        doc_dir = os.path.join(
            os.path.abspath(os.path.dirname(__file__)),
            "static",
            "uploads",
            "documents",
        )
        os.makedirs(doc_dir, exist_ok=True)

        # Create demonstration files
        sample_files = [
            (
                "sample_financial_audit.pdf",
                b"%PDF-1.4 TrustVault Sample Financial Audit Report\n"
                b"1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF",
            ),
            (
                "sample_employee_nda.docx",
                b"PK\x03\x04 TrustVault Sample Confidential Employee "
                b"Non-Disclosure Agreement Document",
            ),
            (
                "sample_infrastructure_spec.pdf",
                b"%PDF-1.4 TrustVault Zero-Trust Security Architecture "
                b"Specification\n%%EOF",
            ),
        ]

        for filename, content in sample_files:
            file_path = os.path.join(doc_dir, filename)
            if not os.path.exists(file_path):
                with open(file_path, "wb") as file:
                    file.write(content)

        doc1 = Document(
            title="Q4 Financial Audit Report 2026",
            description=(
                "Confidential quarterly ledger, revenue breakdown, "
                "and tax compliance summary."
            ),
            filename="sample_financial_audit.pdf",
            original_filename="Q4_Financial_Audit_2026.pdf",
            file_size=os.path.getsize(
                os.path.join(doc_dir, "sample_financial_audit.pdf")
            ),
            file_type="PDF",
            category_id=fin_cat.id if fin_cat else None,
            owner_id=owner.id,
        )

        doc2 = Document(
            title="Mutual Non-Disclosure Agreement (NDA)",
            description=(
                "Standard bilateral NDA agreement protecting "
                "company proprietary assets."
            ),
            filename="sample_employee_nda.docx",
            original_filename="Mutual_NDA_Agreement_Template.docx",
            file_size=os.path.getsize(
                os.path.join(doc_dir, "sample_employee_nda.docx")
            ),
            file_type="Word Document",
            category_id=legal_cat.id if legal_cat else None,
            owner_id=owner.id,
        )

        doc3 = Document(
            title="Zero-Trust Architecture Blueprint",
            description=(
                "Technical schematics, RBAC boundary definitions, "
                "and network access rules."
            ),
            filename="sample_infrastructure_spec.pdf",
            original_filename="Zero_Trust_Architecture_v2.pdf",
            file_size=os.path.getsize(
                os.path.join(doc_dir, "sample_infrastructure_spec.pdf")
            ),
            file_type="PDF",
            category_id=tech_cat.id if tech_cat else None,
            owner_id=owner.id,
        )

        db.session.add_all([doc1, doc2, doc3])
        db.session.flush()

        # Share the first two documents with the viewer
        if viewer:
            permissions = [
                DocumentPermission(
                    document_id=doc1.id,
                    user_id=viewer.id,
                    permission_level="view",
                    granted_by_id=owner.id,
                ),
                DocumentPermission(
                    document_id=doc2.id,
                    user_id=viewer.id,
                    permission_level="view",
                    granted_by_id=owner.id,
                ),
            ]
            db.session.add_all(permissions)

        # Record initialization activity
        logs = [
            ActivityLog(
                user_id=admin.id if admin else None,
                action="SYSTEM_INIT",
                details="TrustVault initialized with configured access policies.",
                status="SUCCESS",
            ),
            ActivityLog(
                user_id=owner.id,
                action="DOCUMENT_UPLOAD",
                details="Uploaded Q4 Financial Audit Report 2026.",
                status="SUCCESS",
            ),
            ActivityLog(
                user_id=owner.id,
                action="ACCESS_GRANTED",
                details=(
                    "Granted viewing access on the financial audit "
                    f"report to {viewer.username if viewer else 'viewer'}."
                ),
                status="SUCCESS",
            ),
            ActivityLog(
                user_id=owner.id,
                action="DOCUMENT_UPLOAD",
                details="Uploaded Mutual Non-Disclosure Agreement.",
                status="SUCCESS",
            ),
        ]

        db.session.add_all(logs)
        db.session.commit()
        print("Sample documents, permissions, and audit logs initialized.")
