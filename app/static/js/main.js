/**
 * TrustVault Client UI Helpers
 */

document.addEventListener('DOMContentLoaded', () => {
    // 1. Auto dismiss alert messages after 5 seconds
    const alerts = document.querySelectorAll('.tv-alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.4s ease';
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 400);
        }, 5000);
    });

    // 2. Setup Share / Manage Access Modal
    window.openShareModal = function(docId, docTitle) {
        const modal = document.getElementById('shareModal');
        const form = document.getElementById('shareForm');
        const titleSpan = document.getElementById('modalDocTitle');

        if (modal && form) {
            form.action = `/documents/${docId}/manage-access`;
            if (titleSpan) titleSpan.textContent = docTitle;
            modal.classList.add('show');
        }
    };

    window.closeShareModal = function() {
        const modal = document.getElementById('shareModal');
        if (modal) {
            modal.classList.remove('show');
        }
    };

    // Close modal on outside click
    const shareModal = document.getElementById('shareModal');
    if (shareModal) {
        shareModal.addEventListener('click', (e) => {
            if (e.target === shareModal) {
                closeShareModal();
            }
        });
    }

    // 3. File upload drop zone helper if present
    const fileInput = document.getElementById('fileUploadInput');
    const fileNameDisplay = document.getElementById('selectedFileName');
    if (fileInput && fileNameDisplay) {
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                const name = fileInput.files[0].name;
                const size = (fileInput.files[0].size / (1024 * 1024)).toFixed(2);
                fileNameDisplay.textContent = `Selected: ${name} (${size} MB)`;
                fileNameDisplay.style.color = '#34d399';
            }
        });
    }
});
