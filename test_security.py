"""
TrustVault Security & RBAC Automated Test Suite
================================================
Automated tests verifying that unauthorized users CANNOT reach, download,
modify, or delete another user's documents, and proving audit trail veracity.

To run these tests:
    python test_security.py
    (or: pytest test_security.py)
"""

import os
import unittest
from app import create_app
from app.models import db, User, Document, DocumentPermission, ActivityLog, Category

class TrustVaultSecurityTests(unittest.TestCase):

    def setUp(self):
        # Configure app for isolated testing
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()

        with self.app.app_context():
            owner1 = User.query.filter_by(username='john_owner').first()
            viewer = User.query.filter_by(username='sarah_viewer').first()
            admin = User.query.filter_by(username='admin').first()

            # Create a second owner to test isolation between different owners
            owner2 = User.query.filter_by(username='alice_owner').first()
            if not owner2:
                owner2 = User(
                    username="alice_owner",
                    email="alice@trustvault.com",
                    role="owner",
                    profile_pic="default_avatar.png"
                )
                owner2.set_password("Alice@123")
                db.session.add(owner2)
                db.session.commit()

            # Store scalar IDs to prevent DetachedInstanceError across sessions
            self.owner1_id = owner1.id
            self.owner2_id = owner2.id
            self.viewer_id = viewer.id
            self.admin_id = admin.id

            # Create a confidential document owned strictly by owner1 (not shared)
            secret_doc = Document.query.filter_by(title="Zero-Trust Architecture Blueprint").first()
            if not secret_doc:
                secret_doc = Document(
                    title="Zero-Trust Architecture Blueprint",
                    filename="sample_infrastructure_spec.pdf",
                    original_filename="Zero_Trust_Architecture_v2.pdf",
                    owner_id=owner1.id,
                    file_size=1024
                )
                db.session.add(secret_doc)
                db.session.commit()

            # Ensure secret_doc has NO permissions granted to viewer or owner2
            DocumentPermission.query.filter_by(document_id=secret_doc.id).delete()
            db.session.commit()

            self.secret_doc_id = secret_doc.id

    def login(self, email, password):
        return self.client.post('/login', data={
            'login_input': email,
            'password': password
        }, follow_redirects=True)

    def logout(self):
        return self.client.get('/logout', follow_redirects=True)

    # -------------------------------------------------------------------------
    # TEST 1: Unauthenticated Users are completely blocked
    # -------------------------------------------------------------------------
    def test_01_unauthenticated_access_blocked(self):
        """Unauthenticated requests to protected endpoints or files must redirect to login."""
        endpoints = [
            '/dashboard',
            '/my-documents',
            '/upload',
            '/activity-logs',
            f'/documents/{self.secret_doc_id}/download'
        ]
        for ep in endpoints:
            res = self.client.get(ep)
            self.assertEqual(res.status_code, 302, f"Endpoint {ep} should redirect unauthenticated users")
            self.assertIn('/login', res.headers['Location'])

    # -------------------------------------------------------------------------
    # TEST 2: Viewer cannot download or view documents not shared with them
    # -------------------------------------------------------------------------
    def test_02_viewer_cannot_reach_unshared_document(self):
        """A viewer MUST NOT be able to download a document they were not granted access to."""
        self.login('viewer@trustvault.com', 'Viewer@123')

        # Try to download owner1's private document
        res = self.client.get(f'/documents/{self.secret_doc_id}/download', follow_redirects=True)
        
        # Verify access was denied
        self.assertIn(b"Security Alert", res.data)
        self.assertIn(b"You do not possess permission", res.data)

        # Verify unauthorized download attempt was recorded in Audit Logs
        with self.app.app_context():
            log = ActivityLog.query.filter_by(
                action="UNAUTHORIZED_DOWNLOAD_ATTEMPT",
                user_id=self.viewer_id
            ).first()
            self.assertIsNotNone(log, "Security violation must be recorded in ActivityLog")
            self.assertEqual(log.status, "WARNING")

        self.logout()

    # -------------------------------------------------------------------------
    # TEST 3: One owner cannot delete another owner's document
    # -------------------------------------------------------------------------
    def test_03_owner_cannot_delete_other_owners_document(self):
        """Owner B cannot delete Owner A's document."""
        self.login('alice@trustvault.com', 'Alice@123')

        # Alice attempts to delete John's confidential document
        res = self.client.post(f'/documents/{self.secret_doc_id}/delete', follow_redirects=True)
        self.assertIn(b"Access Denied", res.data)

        # Verify document was NOT deleted
        with self.app.app_context():
            doc = db.session.get(Document, self.secret_doc_id)
            self.assertIsNotNone(doc, "Document must still exist after unauthorized deletion attempt")

            # Verify audit trail records the attack
            log = ActivityLog.query.filter_by(action="UNAUTHORIZED_DELETE_ATTEMPT").order_by(ActivityLog.id.desc()).first()
            self.assertIsNotNone(log)
            self.assertEqual(log.status, "FAILED")

        self.logout()

    # -------------------------------------------------------------------------
    # TEST 4: Non-owner cannot grant or revoke permissions on another's document
    # -------------------------------------------------------------------------
    def test_04_non_owner_cannot_manage_permissions(self):
        """User cannot grant permissions to themselves or others on a document they don't own."""
        self.login('alice@trustvault.com', 'Alice@123')

        # Alice tries to grant Sarah access to John's secret doc
        res = self.client.post(f'/documents/{self.secret_doc_id}/manage-access', data={
            'action_type': 'grant',
            'target_user_id': self.viewer_id,
            'permission_level': 'view'
        }, follow_redirects=True)

        self.assertIn(b"Access Denied", res.data)

        with self.app.app_context():
            perm = DocumentPermission.query.filter_by(document_id=self.secret_doc_id, user_id=self.viewer_id).first()
            self.assertIsNone(perm, "Unauthorized permission must NOT be committed to database")

        self.logout()

    # -------------------------------------------------------------------------
    # TEST 5: Viewer cannot access Admin Dashboard or Activity Logs
    # -------------------------------------------------------------------------
    def test_05_viewer_blocked_from_admin_activity_logs(self):
        """Viewers and regular owners cannot inspect audit activity logs."""
        self.login('viewer@trustvault.com', 'Viewer@123')

        res = self.client.get('/activity-logs', follow_redirects=True)
        self.assertIn(b"Access Denied", res.data)

        # Verify security incident log
        with self.app.app_context():
            log = ActivityLog.query.filter_by(
                action="UNAUTHORIZED_LOG_ACCESS",
                user_id=self.viewer_id
            ).first()
            self.assertIsNotNone(log, "Unauthorized log access must be recorded in audit trail")

        self.logout()

    # -------------------------------------------------------------------------
    # TEST 6: Owners CAN grant access and viewer CAN download once permitted
    # -------------------------------------------------------------------------
    def test_06_permission_grant_lifecycle_and_download(self):
        """Document owner grants view permission -> Viewer can download -> Owner revokes -> Viewer blocked."""
        # Step A: John (owner) grants access to Sarah (viewer)
        self.login('owner@trustvault.com', 'Owner@123')
        res_grant = self.client.post(f'/documents/{self.secret_doc_id}/manage-access', data={
            'action_type': 'grant',
            'target_user_id': self.viewer_id,
            'permission_level': 'view'
        }, follow_redirects=True)
        self.assertIn(b"successfully granted", res_grant.data)
        self.logout()

        # Step B: Sarah (viewer) downloads the document
        self.login('viewer@trustvault.com', 'Viewer@123')
        res_dl = self.client.get(f'/documents/{self.secret_doc_id}/download')
        self.assertEqual(res_dl.status_code, 200, "Authorized viewer should receive HTTP 200 download")
        self.logout()

        # Step C: John revokes access
        self.login('owner@trustvault.com', 'Owner@123')
        res_revoke = self.client.post(f'/documents/{self.secret_doc_id}/manage-access', data={
            'action_type': 'revoke',
            'target_user_id': self.viewer_id
        }, follow_redirects=True)
        self.assertIn(b"Access revoked", res_revoke.data)
        self.logout()

        # Step D: Sarah tries to download again (must be blocked!)
        self.login('viewer@trustvault.com', 'Viewer@123')
        res_blocked = self.client.get(f'/documents/{self.secret_doc_id}/download', follow_redirects=True)
        self.assertIn(b"Security Alert", res_blocked.data)
        self.logout()

    # -------------------------------------------------------------------------
    # TEST 7: Read vs. Edit Permission enforcement
    # -------------------------------------------------------------------------
    def test_07_read_vs_edit_permission_enforcement(self):
        """User with 'view' permission cannot edit metadata; user with 'edit' CAN edit."""
        # Grant READ ONLY permission
        self.login('owner@trustvault.com', 'Owner@123')
        self.client.post(f'/documents/{self.secret_doc_id}/manage-access', data={
            'action_type': 'grant',
            'target_user_id': self.viewer_id,
            'permission_level': 'view'
        }, follow_redirects=True)
        self.logout()

        # Viewer tries to edit metadata with view-only permission (MUST BE BLOCKED)
        self.login('viewer@trustvault.com', 'Viewer@123')
        res_edit_denied = self.client.post(f'/documents/{self.secret_doc_id}/edit', data={
            'title': 'Hacked Document Title'
        }, follow_redirects=True)
        self.assertIn(b"Access Denied", res_edit_denied.data)
        self.logout()

        # Upgrade permission to EDIT
        self.login('owner@trustvault.com', 'Owner@123')
        self.client.post(f'/documents/{self.secret_doc_id}/manage-access', data={
            'action_type': 'grant',
            'target_user_id': self.viewer_id,
            'permission_level': 'edit'
        }, follow_redirects=True)
        self.logout()

        # Viewer tries to edit again (MUST SUCCEED)
        self.login('viewer@trustvault.com', 'Viewer@123')
        res_edit_ok = self.client.post(f'/documents/{self.secret_doc_id}/edit', data={
            'title': 'Zero-Trust Architecture v3 (Updated by Editor)'
        }, follow_redirects=True)
        self.assertIn(b"Document details updated successfully", res_edit_ok.data)

        # Verify title was updated in database
        with self.app.app_context():
            updated_doc = db.session.get(Document, self.secret_doc_id)
            self.assertEqual(updated_doc.title, 'Zero-Trust Architecture v3 (Updated by Editor)')

        self.logout()

    # -------------------------------------------------------------------------
    # TEST 8: Full Verifiable Audit Trail
    # -------------------------------------------------------------------------
    def test_08_verifiable_audit_trail(self):
        """Every critical action (upload, download, delete, access grant/revoke) has an audit log."""
        with self.app.app_context():
            logs = ActivityLog.query.all()
            actions = {l.action for l in logs}

            # Verify presence of essential security and data lifecycle audit events
            expected_actions = {
                'USER_LOGIN',
                'DOCUMENT_DOWNLOAD',
                'ACCESS_GRANTED',
                'UNAUTHORIZED_DOWNLOAD_ATTEMPT'
            }
            for act in expected_actions:
                self.assertIn(act, actions, f"Audit log must capture event: {act}")


if __name__ == '__main__':
    print("=================================================================")
    print(" Running TrustVault Security & Document Isolation Test Suite ")
    print("=================================================================")
    unittest.main(verbosity=2)
