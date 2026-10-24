from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='owner') # 'admin', 'owner', 'viewer'
    profile_pic = db.Column(db.String(200), default='default_avatar.png')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    documents = db.relationship('Document', backref='owner', lazy=True, foreign_keys='Document.owner_id', cascade="all, delete-orphan")
    granted_permissions = db.relationship('DocumentPermission', backref='grantor', lazy=True, foreign_keys='DocumentPermission.granted_by_id')
    received_permissions = db.relationship('DocumentPermission', backref='user', lazy=True, foreign_keys='DocumentPermission.user_id', cascade="all, delete-orphan")
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role.lower() == 'admin'

    @property
    def is_owner(self):
        return self.role.lower() == 'owner'

    @property
    def is_viewer(self):
        return self.role.lower() == 'viewer'

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class Category(db.Model):
    __tablename__ = 'categories'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), unique=True, nullable=False)
    description = db.Column(db.String(200))
    icon = db.Column(db.String(50), default='folder') # lucide/fontawesome style icon name
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    documents = db.relationship('Document', backref='category', lazy=True)

    def __repr__(self):
        return f'<Category {self.name}>'


class Document(db.Model):
    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, default=0) # bytes
    file_type = db.Column(db.String(50), default='OTHER') # PDF, DOCX, XLSX, etc.
    
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Permissions
    permissions = db.relationship('DocumentPermission', backref='document', lazy=True, cascade="all, delete-orphan")

    @property
    def formatted_size(self):
        size = self.file_size or 0
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.2f} MB"

    def is_shared_with(self, user_id):
        return any(p.user_id == user_id for p in self.permissions)

    def has_view_access(self, user):
        if not user or not user.is_authenticated:
            return False
        if user.is_admin or self.owner_id == user.id:
            return True
        return any(p.user_id == user.id for p in self.permissions)

    def has_edit_access(self, user):
        if not user or not user.is_authenticated:
            return False
        if user.is_admin or self.owner_id == user.id:
            return True
        return any(p.user_id == user.id and p.permission_level == 'edit' for p in self.permissions)

    def get_user_permission(self, user_id):
        for p in self.permissions:
            if p.user_id == user_id:
                return p.permission_level
        return None

    def __repr__(self):
        return f'<Document {self.title}>'


class DocumentPermission(db.Model):
    __tablename__ = 'document_permissions'

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey('documents.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    permission_level = db.Column(db.String(20), default='view') # 'view', 'edit'
    granted_at = db.Column(db.DateTime, default=datetime.utcnow)
    granted_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    __table_args__ = (
        db.UniqueConstraint('document_id', 'user_id', name='uq_document_user_permission'),
    )

    def __repr__(self):
        return f'<Permission doc={self.document_id} user={self.user_id} level={self.permission_level}>'


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False) # e.g. 'USER_LOGIN', 'USER_LOGOUT', 'DOCUMENT_UPLOAD', 'DOCUMENT_DELETE', 'ACCESS_GRANTED', 'ACCESS_REVOKED', 'ACCESS_DENIED'
    details = db.Column(db.String(255))
    ip_address = db.Column(db.String(50), default='127.0.0.1')
    status = db.Column(db.String(20), default='SUCCESS') # 'SUCCESS', 'WARNING', 'FAILED'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ActivityLog {self.action} status={self.status} at={self.timestamp}>'


def log_activity(action, details="", user_id=None, ip_address="127.0.0.1", status="SUCCESS"):
    """Helper utility to write audit logs effortlessly across routes."""
    try:
        log_entry = ActivityLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=ip_address,
            status=status,
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Failed to record activity log: {e}")
