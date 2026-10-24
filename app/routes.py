import os
import uuid
from datetime import datetime
from functools import wraps
from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    current_app, send_from_directory, abort
)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import or_, and_

from app.models import db, User, Document, DocumentPermission, ActivityLog, Category, log_activity

main_bp = Blueprint('main', __name__)

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'doc', 'txt', 'png', 'jpg', 'jpeg', 'xlsx', 'xls', 'csv', 'zip'}
ALLOWED_AVATAR_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

# Decorator for Admin-only routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            user_id = current_user.id if current_user.is_authenticated else None
            log_activity(
                action="UNAUTHORIZED_ACCESS_ATTEMPT",
                details=f"Unauthorized access attempt to {request.path} by user {current_user.username if current_user.is_authenticated else 'Anonymous'}",
                user_id=user_id,
                ip_address=get_client_ip(),
                status="WARNING"
            )
            flash("Access Denied: You do not possess Administrator privileges for this area.", "danger")
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Decorator for Owner or Admin routes
def owner_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (not current_user.is_owner and not current_user.is_admin):
            flash("Access Denied: Viewer accounts cannot upload or manage documents.", "danger")
            return redirect(url_for('main.shared_with_me'))
        return f(*args, **kwargs)
    return decorated_function


# =========================================================================
# PUBLIC & AUTHENTICATION ROUTES
# =========================================================================

@main_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return render_template('index.html')


@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        login_input = request.form.get('login_input', '').strip() # can be email or username
        password = request.form.get('password', '')
        remember = True if request.form.get('remember') else False

        user = User.query.filter(
            or_(User.email.ilike(login_input), User.username.ilike(login_input))
        ).first()

        if not user or not user.check_password(password):
            log_activity(
                action="USER_LOGIN_FAILED",
                details=f"Failed login attempt for identifier: {login_input}",
                user_id=user.id if user else None,
                ip_address=get_client_ip(),
                status="FAILED"
            )
            flash("Invalid credentials. Please verify your username/email and password.", "danger")
            return render_template('login.html', login_input=login_input)

        login_user(user, remember=remember)
        log_activity(
            action="USER_LOGIN",
            details=f"User {user.username} successfully logged in as {user.role.upper()}.",
            user_id=user.id,
            ip_address=get_client_ip(),
            status="SUCCESS"
        )
        flash(f"Welcome back, {user.username}! Logged in as {user.role.capitalize()}.", "success")
        
        # If new non-admin user lands on dashboard vs my_documents
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('main.dashboard'))

    return render_template('login.html')


@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', 'owner').lower()

        # Input validations
        if role not in ['owner', 'viewer']:
            role = 'owner'

        if not username or not email or not password:
            flash("All fields are required.", "warning")
            return render_template('register.html', username=username, email=email, role=role)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html', username=username, email=email, role=role)

        if len(password) < 6:
            flash("Password must be at least 6 characters in length.", "warning")
            return render_template('register.html', username=username, email=email, role=role)

        if User.query.filter_by(username=username).first():
            flash("Username is already registered. Please choose another.", "warning")
            return render_template('register.html', email=email, role=role)

        if User.query.filter_by(email=email).first():
            flash("Email address is already registered. Please log in.", "warning")
            return render_template('register.html', username=username, role=role)

        # Create new user
        new_user = User(
            username=username,
            email=email,
            role=role,
            profile_pic="default_avatar.png"
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        log_activity(
            action="USER_REGISTER",
            details=f"New user registered: {username} ({role})",
            user_id=new_user.id,
            ip_address=get_client_ip(),
            status="SUCCESS"
        )

        flash("Registration successful! You may now sign in with your credentials.", "success")
        return redirect(url_for('main.login'))

    return render_template('register.html')


@main_bp.route('/logout')
@login_required
def logout():
    username = current_user.username
    user_id = current_user.id
    log_activity(
        action="USER_LOGOUT",
        details=f"User {username} logged out.",
        user_id=user_id,
        ip_address=get_client_ip(),
        status="SUCCESS"
    )
    logout_user()
    flash("You have been signed out safely.", "info")
    return redirect(url_for('main.login'))


# =========================================================================
# DASHBOARD
# =========================================================================

@main_bp.route('/dashboard')
@login_required
def dashboard():
    total_docs = Document.query.count()
    total_users = User.query.count()
    total_shares = DocumentPermission.query.count()
    total_categories = Category.query.count()

    # User specific counts
    my_docs_count = Document.query.filter_by(owner_id=current_user.id).count()
    shared_with_me_count = DocumentPermission.query.filter_by(user_id=current_user.id).count()

    recent_logs = []
    if current_user.is_admin:
        recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(8).all()
        recent_users = User.query.order_by(User.created_at.desc()).limit(6).all()
        recent_docs = Document.query.order_by(Document.uploaded_at.desc()).limit(6).all()
    else:
        recent_users = []
        if current_user.is_owner:
            recent_docs = Document.query.filter_by(owner_id=current_user.id).order_by(Document.uploaded_at.desc()).limit(6).all()
        else: # viewer
            doc_ids = [p.document_id for p in current_user.received_permissions]
            recent_docs = Document.query.filter(Document.id.in_(doc_ids)).order_by(Document.uploaded_at.desc()).limit(6).all() if doc_ids else []

    # Category breakdown stats
    categories = Category.query.all()
    category_stats = []
    for cat in categories:
        count = len(cat.documents)
        category_stats.append({'name': cat.name, 'count': count, 'icon': cat.icon})

    return render_template(
        'dashboard.html',
        total_docs=total_docs,
        total_users=total_users,
        total_shares=total_shares,
        total_categories=total_categories,
        my_docs_count=my_docs_count,
        shared_with_me_count=shared_with_me_count,
        recent_logs=recent_logs,
        recent_users=recent_users,
        recent_docs=recent_docs,
        category_stats=category_stats
    )


# =========================================================================
# DOCUMENTS: MY DOCUMENTS, SHARED WITH ME, UPLOAD, DOWNLOAD, DELETE
# =========================================================================

@main_bp.route('/my-documents')
@login_required
def my_documents():
    # Admin sees all documents or can filter; Owner sees self-uploaded documents; Viewer sees none or is redirected to shared
    if current_user.is_viewer:
        flash("Viewers do not own uploaded documents. Viewing documents shared with you.", "info")
        return redirect(url_for('main.shared_with_me'))

    category_id = request.args.get('category', type=int)

    if current_user.is_admin:
        query = Document.query
    else:
        query = Document.query.filter_by(owner_id=current_user.id)

    if category_id:
        query = query.filter_by(category_id=category_id)

    documents = query.order_by(Document.uploaded_at.desc()).all()
    categories = Category.query.all()
    all_users = User.query.filter(User.id != current_user.id).all()

    return render_template(
        'my_documents.html',
        documents=documents,
        categories=categories,
        all_users=all_users,
        selected_category=category_id
    )


@main_bp.route('/shared-with-me')
@login_required
def shared_with_me():
    # Documents that have been shared with current user
    permissions = DocumentPermission.query.filter_by(user_id=current_user.id).all()
    shared_docs = [p.document for p in permissions]

    return render_template('shared_with_me.html', documents=shared_docs)


@main_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    # Viewers cannot upload documents
    if current_user.is_viewer:
        flash("Access Denied: Viewer accounts do not have upload privileges. Upgrade or log in as Owner.", "danger")
        return redirect(url_for('main.shared_with_me'))

    categories = Category.query.all()
    users_to_share = User.query.filter(User.id != current_user.id).all()

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category_id = request.form.get('category_id', type=int)
        shared_user_ids = request.form.getlist('share_with') # list of user IDs

        if 'file' not in request.files:
            flash("No file part provided in request.", "danger")
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash("No file was selected for upload.", "warning")
            return redirect(request.url)

        if not title:
            title = os.path.splitext(file.filename)[0].replace('_', ' ').title()

        if file and allowed_file(file.filename, ALLOWED_EXTENSIONS):
            orig_filename = secure_filename(file.filename)
            extension = orig_filename.rsplit('.', 1)[1].lower() if '.' in orig_filename else 'bin'
            unique_name = f"{uuid.uuid4().hex}_{orig_filename}"
            save_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_name)

            file.save(save_path)
            file_size = os.path.getsize(save_path)

            # Determine file type
            type_mapping = {
                'pdf': 'PDF',
                'docx': 'Word Document',
                'doc': 'Word Document',
                'txt': 'Text File',
                'xlsx': 'Excel Spreadsheet',
                'xls': 'Excel Spreadsheet',
                'csv': 'CSV Data',
                'png': 'PNG Image',
                'jpg': 'JPEG Image',
                'jpeg': 'JPEG Image',
                'zip': 'ZIP Archive'
            }
            file_type = type_mapping.get(extension, extension.upper())

            new_doc = Document(
                title=title,
                description=description,
                filename=unique_name,
                original_filename=orig_filename,
                file_size=file_size,
                file_type=file_type,
                category_id=category_id if category_id else None,
                owner_id=current_user.id,
                uploaded_at=datetime.utcnow()
            )
            db.session.add(new_doc)
            db.session.flush() # get new_doc.id

            # Add shared permissions if selected
            shared_names = []
            for uid in shared_user_ids:
                try:
                    target_user = db.session.get(User, int(uid))
                    if target_user and target_user.id != current_user.id:
                        perm = DocumentPermission(
                            document_id=new_doc.id,
                            user_id=target_user.id,
                            permission_level='view',
                            granted_by_id=current_user.id
                        )
                        db.session.add(perm)
                        shared_names.append(target_user.username)
                except (ValueError, TypeError):
                    continue

            db.session.commit()

            share_note = f" and shared with: {', '.join(shared_names)}" if shared_names else ""
            log_activity(
                action="DOCUMENT_UPLOAD",
                details=f"Uploaded '{title}' ({file_type}, {new_doc.formatted_size}){share_note}",
                user_id=current_user.id,
                ip_address=get_client_ip(),
                status="SUCCESS"
            )

            flash(f"Document '{title}' uploaded successfully!{share_note}", "success")
            return redirect(url_for('main.my_documents'))
        else:
            flash(f"Invalid file extension. Allowed extensions are: {', '.join(sorted(ALLOWED_EXTENSIONS))}", "danger")

    return render_template('upload.html', categories=categories, users=users_to_share)


@main_bp.route('/documents/<int:doc_id>/download')
@login_required
def download_document(doc_id):
    doc = db.session.get(Document, doc_id)
    if not doc:
        abort(404)

    if not doc.has_view_access(current_user):
        log_activity(
            action="UNAUTHORIZED_DOWNLOAD_ATTEMPT",
            details=f"Attempted download on document #{doc.id} ('{doc.title}') by {current_user.username}",
            user_id=current_user.id,
            ip_address=get_client_ip(),
            status="WARNING"
        )
        flash("Security Alert: You do not possess permission to access or download this document.", "danger")
        return redirect(url_for('main.dashboard'))

    log_activity(
        action="DOCUMENT_DOWNLOAD",
        details=f"Downloaded '{doc.title}' ({doc.original_filename})",
        user_id=current_user.id,
        ip_address=get_client_ip(),
        status="SUCCESS"
    )

    return send_from_directory(
        current_app.config['UPLOAD_FOLDER'],
        doc.filename,
        as_attachment=True,
        download_name=doc.original_filename
    )


@main_bp.route('/documents/<int:doc_id>/delete', methods=['POST'])
@login_required
def delete_document(doc_id):
    doc = db.session.get(Document, doc_id)
    if not doc:
        flash("Document not found.", "warning")
        return redirect(url_for('main.my_documents'))

    # Only document owner or admin can delete
    if doc.owner_id != current_user.id and not current_user.is_admin:
        log_activity(
            action="UNAUTHORIZED_DELETE_ATTEMPT",
            details=f"User {current_user.username} attempted to delete document #{doc_id} owned by User #{doc.owner_id}",
            user_id=current_user.id,
            ip_address=get_client_ip(),
            status="FAILED"
        )
        flash("Access Denied: You do not possess authority to delete this document.", "danger")
        return redirect(url_for('main.my_documents'))

    doc_title = doc.title
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], doc.filename)

    # Delete physical file if exists
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception as e:
            print(f"Error removing physical file: {e}")

    db.session.delete(doc)
    db.session.commit()

    log_activity(
        action="DOCUMENT_DELETE",
        details=f"Deleted document '{doc_title}' (ID: {doc_id})",
        user_id=current_user.id,
        ip_address=get_client_ip(),
        status="SUCCESS"
    )
    flash(f"Document '{doc_title}' was permanently deleted.", "success")
    return redirect(url_for('main.my_documents'))


@main_bp.route('/documents/<int:doc_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_document(doc_id):
    doc = db.session.get(Document, doc_id)
    if not doc:
        flash("Document not found.", "warning")
        return redirect(url_for('main.my_documents'))

    # Verify edit access
    if not doc.has_edit_access(current_user):
        log_activity(
            action="UNAUTHORIZED_EDIT_ATTEMPT",
            details=f"User {current_user.username} attempted to edit document #{doc.id} without edit permission",
            user_id=current_user.id,
            ip_address=get_client_ip(),
            status="FAILED"
        )
        flash("Access Denied: You do not possess edit permissions for this document.", "danger")
        return redirect(url_for('main.dashboard'))

    categories = Category.query.all()
    if request.method == 'POST':
        new_title = request.form.get('title', '').strip()
        new_description = request.form.get('description', '').strip()
        category_id = request.form.get('category_id', type=int)

        if not new_title:
            flash("Document title cannot be empty.", "warning")
            return render_template('edit_document.html', doc=doc, categories=categories)

        old_title = doc.title
        doc.title = new_title
        doc.description = new_description
        doc.category_id = category_id if category_id else None
        db.session.commit()

        log_activity(
            action="DOCUMENT_EDIT",
            details=f"Updated document metadata for '{doc.title}' (formerly '{old_title}')",
            user_id=current_user.id,
            ip_address=get_client_ip(),
            status="SUCCESS"
        )
        flash("Document details updated successfully.", "success")
        if doc.owner_id == current_user.id or current_user.is_admin:
            return redirect(url_for('main.my_documents'))
        return redirect(url_for('main.shared_with_me'))

    return render_template('edit_document.html', doc=doc, categories=categories)


@main_bp.route('/documents/<int:doc_id>/manage-access', methods=['POST'])
@login_required
def manage_access(doc_id):
    doc = db.session.get(Document, doc_id)
    if not doc:
        flash("Document not found.", "warning")
        return redirect(url_for('main.my_documents'))

    # Strict RBAC check: only document owner or admin can grant/revoke access
    if doc.owner_id != current_user.id and not current_user.is_admin:
        log_activity(
            action="UNAUTHORIZED_ACCESS_MANAGEMENT",
            details=f"User {current_user.username} tried to modify access for document '{doc.title}'",
            user_id=current_user.id,
            ip_address=get_client_ip(),
            status="FAILED"
        )
        flash("Access Denied: Only the document owner or an administrator can grant or revoke permissions.", "danger")
        return redirect(url_for('main.my_documents'))

    action_type = request.form.get('action_type', 'grant') # 'grant' or 'revoke'
    target_user_id = request.form.get('target_user_id', type=int)
    permission_level = request.form.get('permission_level', 'view').lower()
    if permission_level not in ['view', 'edit']:
        permission_level = 'view'

    target_user = db.session.get(User, target_user_id)
    if not target_user:
        flash("Target user not found.", "warning")
        return redirect(url_for('main.my_documents'))

    if action_type == 'grant':
        existing = DocumentPermission.query.filter_by(document_id=doc.id, user_id=target_user.id).first()
        if not existing:
            new_perm = DocumentPermission(
                document_id=doc.id,
                user_id=target_user.id,
                permission_level=permission_level,
                granted_by_id=current_user.id
            )
            db.session.add(new_perm)
            db.session.commit()
            log_activity(
                action="ACCESS_GRANTED",
                details=f"Granted {permission_level.upper()} access for '{doc.title}' to user {target_user.username}",
                user_id=current_user.id,
                ip_address=get_client_ip(),
                status="SUCCESS"
            )
            flash(f"{permission_level.capitalize()} access successfully granted to {target_user.username}.", "success")
        else:
            existing.permission_level = permission_level
            db.session.commit()
            log_activity(
                action="ACCESS_MODIFIED",
                details=f"Updated access for '{doc.title}' to {permission_level.upper()} for user {target_user.username}",
                user_id=current_user.id,
                ip_address=get_client_ip(),
                status="SUCCESS"
            )
            flash(f"Updated access level to {permission_level.capitalize()} for {target_user.username}.", "success")

    elif action_type == 'revoke':
        perm = DocumentPermission.query.filter_by(document_id=doc.id, user_id=target_user.id).first()
        if perm:
            db.session.delete(perm)
            db.session.commit()
            log_activity(
                action="ACCESS_REVOKED",
                details=f"Revoked access for '{doc.title}' from user {target_user.username}",
                user_id=current_user.id,
                ip_address=get_client_ip(),
                status="SUCCESS"
            )
            flash(f"Access revoked for {target_user.username}.", "info")

    return redirect(url_for('main.my_documents'))


# =========================================================================
# SEARCH WITH MULTI-PARAMETER FILTERS
# =========================================================================

@main_bp.route('/search')
@login_required
def search():
    query_text = request.args.get('q', '').strip()
    category_id = request.args.get('category', type=int)
    owner_username = request.args.get('owner', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    # Determine baseline documents visible to current user
    if current_user.is_admin:
        base_query = Document.query
    elif current_user.is_owner:
        # Owner can see their documents AND documents shared with them
        shared_doc_ids = [p.document_id for p in current_user.received_permissions]
        base_query = Document.query.filter(
            or_(Document.owner_id == current_user.id, Document.id.in_(shared_doc_ids))
        )
    else: # Viewer can ONLY see documents shared with them
        shared_doc_ids = [p.document_id for p in current_user.received_permissions]
        base_query = Document.query.filter(Document.id.in_(shared_doc_ids))

    # Apply text search filter
    if query_text:
        base_query = base_query.filter(
            or_(
                Document.title.ilike(f'%{query_text}%'),
                Document.description.ilike(f'%{query_text}%'),
                Document.original_filename.ilike(f'%{query_text}%')
            )
        )

    # Category filter
    if category_id:
        base_query = base_query.filter(Document.category_id == category_id)

    # Owner filter
    if owner_username:
        owner_users = User.query.filter(User.username.ilike(f'%{owner_username}%')).all()
        owner_ids = [u.id for u in owner_users]
        base_query = base_query.filter(Document.owner_id.in_(owner_ids))

    # Date filters
    if date_from:
        try:
            d_from = datetime.strptime(date_from, '%Y-%m-%d')
            base_query = base_query.filter(Document.uploaded_at >= d_from)
        except ValueError:
            pass

    if date_to:
        try:
            d_to = datetime.strptime(date_to + ' 23:59:59', '%Y-%m-%d %H:%M:%S')
            base_query = base_query.filter(Document.uploaded_at <= d_to)
        except ValueError:
            pass

    results = base_query.order_by(Document.uploaded_at.desc()).all()
    categories = Category.query.all()

    return render_template(
        'search.html',
        results=results,
        categories=categories,
        query_text=query_text,
        selected_category=category_id,
        owner_username=owner_username,
        date_from=date_from,
        date_to=date_to,
        total_results=len(results)
    )


# =========================================================================
# CATEGORIES PAGE
# =========================================================================

@main_bp.route('/categories')
@login_required
def categories():
    all_categories = Category.query.all()
    
    # Calculate visible docs per category for current user
    cat_data = []
    for cat in all_categories:
        if current_user.is_admin:
            docs = [d for d in cat.documents]
        elif current_user.is_owner:
            shared_ids = {p.document_id for p in current_user.received_permissions}
            docs = [d for d in cat.documents if d.owner_id == current_user.id or d.id in shared_ids]
        else:
            shared_ids = {p.document_id for p in current_user.received_permissions}
            docs = [d for d in cat.documents if d.id in shared_ids]

        cat_data.append({
            'category': cat,
            'doc_count': len(docs),
            'documents': docs[:5] # preview top 5
        })

    return render_template('categories.html', categories_data=cat_data)


# =========================================================================
# ACTIVITY LOGS (STRICTLY ADMIN ONLY)
# =========================================================================

@main_bp.route('/activity-logs')
@login_required
def activity_logs():
    # If not admin, strictly deny and log the violation
    if not current_user.is_admin:
        log_activity(
            action="UNAUTHORIZED_LOG_ACCESS",
            details=f"Unauthorized access to Activity Logs by user {current_user.username} ({current_user.role})",
            user_id=current_user.id,
            ip_address=get_client_ip(),
            status="FAILED"
        )
        flash("Access Denied: Activity logs are restricted strictly to System Administrators for security and audit compliance.", "danger")
        return redirect(url_for('main.dashboard'))

    action_filter = request.args.get('action', '').strip()
    status_filter = request.args.get('status', '').strip()

    query = ActivityLog.query
    if action_filter:
        query = query.filter(ActivityLog.action.ilike(f'%{action_filter}%'))
    if status_filter:
        query = query.filter_by(status=status_filter)

    logs = query.order_by(ActivityLog.timestamp.desc()).limit(150).all()

    return render_template(
        'activity_logs.html',
        logs=logs,
        selected_action=action_filter,
        selected_status=status_filter
    )


# =========================================================================
# USER PROFILE & PASSWORD UPDATES
# =========================================================================

@main_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'update_info':
            new_username = request.form.get('username', '').strip()
            new_email = request.form.get('email', '').strip().lower()

            if not new_username or not new_email:
                flash("Username and email cannot be blank.", "warning")
                return redirect(url_for('main.profile'))

            # Check uniqueness if changed
            existing_user = User.query.filter(User.username == new_username, User.id != current_user.id).first()
            if existing_user:
                flash("Username is already taken by another account.", "danger")
                return redirect(url_for('main.profile'))

            existing_email = User.query.filter(User.email == new_email, User.id != current_user.id).first()
            if existing_email:
                flash("Email is already taken by another account.", "danger")
                return redirect(url_for('main.profile'))

            current_user.username = new_username
            current_user.email = new_email

            # Profile picture upload
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and file.filename != '' and allowed_file(file.filename, ALLOWED_AVATAR_EXTENSIONS):
                    ext = secure_filename(file.filename).rsplit('.', 1)[1].lower()
                    avatar_filename = f"avatar_{current_user.id}_{uuid.uuid4().hex[:8]}.{ext}"
                    save_path = os.path.join(current_app.config['AVATAR_FOLDER'], avatar_filename)
                    file.save(save_path)
                    current_user.profile_pic = avatar_filename

            db.session.commit()
            log_activity(
                action="USER_PROFILE_UPDATE",
                details=f"User {current_user.username} updated profile info/avatar.",
                user_id=current_user.id,
                ip_address=get_client_ip(),
                status="SUCCESS"
            )
            flash("Profile information updated successfully!", "success")

        elif action == 'change_password':
            current_pass = request.form.get('current_password', '')
            new_pass = request.form.get('new_password', '')
            confirm_pass = request.form.get('confirm_password', '')

            if not current_user.check_password(current_pass):
                flash("Incorrect current password.", "danger")
                return redirect(url_for('main.profile'))

            if len(new_pass) < 6:
                flash("New password must be at least 6 characters.", "warning")
                return redirect(url_for('main.profile'))

            if new_pass != confirm_pass:
                flash("New passwords do not match.", "danger")
                return redirect(url_for('main.profile'))

            current_user.set_password(new_pass)
            db.session.commit()

            log_activity(
                action="PASSWORD_CHANGED",
                details=f"User {current_user.username} changed account password.",
                user_id=current_user.id,
                ip_address=get_client_ip(),
                status="SUCCESS"
            )
            flash("Your password has been securely updated!", "success")

        return redirect(url_for('main.profile'))

    return render_template('profile.html')


# =========================================================================
# ADMIN USER MANAGEMENT
# =========================================================================

@main_bp.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.id.asc()).all()
    return render_template('admin_users.html', users=users)


@main_bp.route('/admin/users/<int:user_id>/update-role', methods=['POST'])
@login_required
@admin_required
def update_user_role(user_id):
    target_user = db.session.get(User, user_id)
    if not target_user:
        flash("User not found.", "warning")
        return redirect(url_for('main.admin_users'))

    if target_user.id == current_user.id:
        flash("You cannot modify your own administrative role.", "warning")
        return redirect(url_for('main.admin_users'))

    new_role = request.form.get('role', '').lower()
    if new_role in ['admin', 'owner', 'viewer']:
        old_role = target_user.role
        target_user.role = new_role
        db.session.commit()
        log_activity(
            action="USER_ROLE_CHANGED",
            details=f"Admin changed role of {target_user.username} from {old_role} to {new_role}",
            user_id=current_user.id,
            ip_address=get_client_ip(),
            status="SUCCESS"
        )
        flash(f"Updated role for {target_user.username} to {new_role.capitalize()}.", "success")

    return redirect(url_for('main.admin_users'))
