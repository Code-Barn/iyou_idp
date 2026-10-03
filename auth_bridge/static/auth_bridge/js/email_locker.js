// Copyright (C) 2026 David Byers dba Byers Brands
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

(function () {
    let currentExportEmail = '';
    let currentExportVc = null;

    function getCsrfToken() {
        return window.csrfToken || '';
    }

    function showToast(message, type = 'success') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `flex items-center gap-3 px-4 py-3 rounded-xl shadow-lg border text-sm font-medium transition-all duration-300 transform translate-y-2 opacity-0 ${
            type === 'error'
                ? 'bg-red-50 text-red-800 border-red-200'
                : 'bg-emerald-50 text-emerald-800 border-emerald-200'
        }`;

        const iconSvg = type === 'error'
            ? `<svg class="w-5 h-5 flex-shrink-0 text-red-600" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/></svg>`
            : `<svg class="w-5 h-5 flex-shrink-0 text-emerald-600" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>`;

        toast.innerHTML = `${iconSvg}<span>${message}</span>`;
        container.appendChild(toast);

        requestAnimationFrame(() => {
            toast.classList.remove('translate-y-2', 'opacity-0');
        });

        setTimeout(() => {
            toast.classList.add('opacity-0', 'translate-y-2');
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    function initClaimModal() {
        const modal = document.getElementById('claim-email-modal');
        const openBtn = document.getElementById('open-claim-email-btn');
        const closeBtns = document.querySelectorAll('.close-claim-email-btn');
        const step1 = document.getElementById('claim-step1-container');
        const step2 = document.getElementById('claim-step2-container');
        const step1Error = document.getElementById('claim-step1-error');
        const step2Error = document.getElementById('claim-step2-error');
        const emailInput = document.getElementById('claim-email-input');
        const labelSelect = document.getElementById('claim-label-select');
        const sendBtn = document.getElementById('claim-send-code-btn');
        const otpInput = document.getElementById('claim-otp-input');
        const verifyBtn = document.getElementById('claim-verify-btn');
        const backBtn = document.getElementById('claim-back-btn');
        const targetEmailDisplay = document.getElementById('claim-target-email');

        if (!modal || !openBtn) return;

        function resetForm() {
            if (emailInput) emailInput.value = '';
            if (labelSelect) labelSelect.value = 'personal';
            if (otpInput) otpInput.value = '';
            if (step1Error) {
                step1Error.classList.add('hidden');
                step1Error.textContent = '';
            }
            if (step2Error) {
                step2Error.classList.add('hidden');
                step2Error.textContent = '';
            }
            if (step1) step1.classList.remove('hidden');
            if (step2) step2.classList.add('hidden');
            if (sendBtn) {
                sendBtn.disabled = false;
                sendBtn.textContent = 'Send Verification Code';
            }
            if (verifyBtn) {
                verifyBtn.disabled = false;
                verifyBtn.textContent = 'Verify & Lock';
            }
        }

        function openModal() {
            resetForm();
            modal.classList.remove('hidden');
            if (emailInput) emailInput.focus();
        }

        function closeModal() {
            modal.classList.add('hidden');
            resetForm();
        }

        openBtn.addEventListener('click', openModal);
        closeBtns.forEach(btn => btn.addEventListener('click', closeModal));

        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });

        if (backBtn) {
            backBtn.addEventListener('click', () => {
                if (step2) step2.classList.add('hidden');
                if (step1) step1.classList.remove('hidden');
                if (step2Error) step2Error.classList.add('hidden');
            });
        }

        if (sendBtn) {
            sendBtn.addEventListener('click', async (e) => {
                e.preventDefault();
                const email = (emailInput?.value || '').trim().toLowerCase();
                const label = labelSelect?.value || 'personal';

                if (!email || !email.includes('@')) {
                    if (step1Error) {
                        step1Error.textContent = 'Please enter a valid email address.';
                        step1Error.classList.remove('hidden');
                    }
                    return;
                }

                step1Error?.classList.add('hidden');
                sendBtn.disabled = true;
                sendBtn.textContent = 'Sending code...';

                try {
                    const response = await fetch('/auth/email/link/challenge/', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCsrfToken(),
                        },
                        body: JSON.stringify({ email, label }),
                    });

                    const data = await response.json();

                    if (response.status === 409) {
                        if (step1Error) {
                            step1Error.textContent = 'This email is already claimed by an account.';
                            step1Error.classList.remove('hidden');
                        }
                        sendBtn.disabled = false;
                        sendBtn.textContent = 'Send Verification Code';
                        return;
                    }

                    if (!response.ok) {
                        if (step1Error) {
                            step1Error.textContent = data.error_description || data.error || 'Failed to dispatch verification code.';
                            step1Error.classList.remove('hidden');
                        }
                        sendBtn.disabled = false;
                        sendBtn.textContent = 'Send Verification Code';
                        return;
                    }

                    if (targetEmailDisplay) targetEmailDisplay.textContent = email;
                    step1?.classList.add('hidden');
                    step2?.classList.remove('hidden');
                    if (otpInput) {
                        otpInput.value = '';
                        otpInput.focus();
                    }
                } catch (err) {
                    if (step1Error) {
                        step1Error.textContent = 'Network error. Please try again.';
                        step1Error.classList.remove('hidden');
                    }
                } finally {
                    sendBtn.disabled = false;
                    sendBtn.textContent = 'Send Verification Code';
                }
            });
        }

        if (verifyBtn) {
            verifyBtn.addEventListener('click', async (e) => {
                e.preventDefault();
                const email = (emailInput?.value || '').trim().toLowerCase();
                const otp = (otpInput?.value || '').trim();

                if (!otp || otp.length < 6) {
                    if (step2Error) {
                        step2Error.textContent = 'Please enter the 6-digit verification code.';
                        step2Error.classList.remove('hidden');
                    }
                    return;
                }

                step2Error?.classList.add('hidden');
                verifyBtn.disabled = true;
                verifyBtn.textContent = 'Verifying...';

                try {
                    const response = await fetch('/auth/email/link/verify/', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRFToken': getCsrfToken(),
                        },
                        body: JSON.stringify({ email, otp }),
                    });

                    const data = await response.json();

                    if (!response.ok) {
                        if (step2Error) {
                            step2Error.textContent = data.error_description || data.error || 'Invalid or expired verification code.';
                            step2Error.classList.remove('hidden');
                        }
                        verifyBtn.disabled = false;
                        verifyBtn.textContent = 'Verify & Lock';
                        return;
                    }

                    appendLinkedEmailRow({
                        id: data.vc?.credentialSubject?.id ? (data.id || String(Date.now())) : String(Date.now()),
                        email: data.email,
                        label: data.label,
                        verified_at: new Date().toISOString(),
                        is_public: false,
                        vc: data.vc,
                    });

                    const emptyState = document.getElementById('linked-emails-empty');
                    if (emptyState) emptyState.classList.add('hidden');

                    closeModal();
                    showToast(`Email ${data.email} successfully locked and linked!`);
                } catch (err) {
                    if (step2Error) {
                        step2Error.textContent = 'Network error. Please try again.';
                        step2Error.classList.remove('hidden');
                    }
                } finally {
                    verifyBtn.disabled = false;
                    verifyBtn.textContent = 'Verify & Lock';
                }
            });
        }
    }

    function appendLinkedEmailRow(item) {
        const tbody = document.getElementById('linked-emails-tbody');
        if (!tbody) return;

        const row = document.createElement('tr');
        row.id = `linked-email-row-${item.id}`;
        row.className = 'border-b border-gray-100 hover:bg-gray-50/70 transition-colors';

        const labelStyles = {
            work: 'bg-blue-100 text-blue-800 border-blue-200',
            alias: 'bg-purple-100 text-purple-800 border-purple-200',
            personal: 'bg-indigo-100 text-indigo-800 border-indigo-200',
        };
        const badgeClass = labelStyles[item.label] || labelStyles.personal;

        const formattedDate = new Intl.DateTimeFormat('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        }).format(new Date(item.verified_at));

        row.innerHTML = `
            <td class="py-4 px-4 font-medium text-gray-900 flex items-center gap-2">
                <svg class="w-4 h-4 text-gray-400" viewBox="0 0 20 20" fill="currentColor">
                    <path d="M2.003 5.884L10 9.882l7.997-3.998A2 2 0 0016 4H4a2 2 0 00-1.997 1.884z" />
                    <path d="M18 8.118l-8 4-8-4V14a2 2 0 002 2h12a2 2 0 002-2V8.118z" />
                </svg>
                <span>${item.email}</span>
            </td>
            <td class="py-4 px-4">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${badgeClass}">
                    ${item.label}
                </span>
            </td>
            <td class="py-4 px-4 text-xs text-gray-500">
                ${formattedDate}
            </td>
            <td class="py-4 px-4 text-center">
                <label class="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" data-email-id="${item.id}" class="email-public-toggle sr-only peer" ${item.is_public ? 'checked' : ''}>
                    <div class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600"></div>
                </label>
            </td>
            <td class="py-4 px-4 text-right space-x-2">
                <button type="button" data-email-id="${item.id}" data-email="${item.email}" data-label="${item.label}" class="export-vc-btn inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium text-indigo-700 bg-indigo-50 hover:bg-indigo-100 transition-colors">
                    <svg class="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M6 2a2 2 0 00-2 2v12a2 2 0 002 2h8a2 2 0 002-2V7.414A2 2 0 0015.414 6L12 2.586A2 2 0 0010.586 2H6zm5 6a1 1 0 10-2 0v3.586l-1.293-1.293a1 1 0 10-1.414 1.414l3 3a1 1 0 001.414 0l3-3a1 1 0 00-1.414-1.414L11 11.586V8z" clip-rule="evenodd" />
                    </svg>
                    Export VC
                </button>
                <button type="button" data-email-id="${item.id}" data-email="${item.email}" class="remove-email-btn inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium text-red-700 bg-red-50 hover:bg-red-100 transition-colors">
                    <svg class="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clip-rule="evenodd" />
                    </svg>
                    Remove
                </button>
            </td>
        `;
        tbody.appendChild(row);
    }

    function initTableActions() {
        const tableContainer = document.getElementById('linked-emails-container');
        if (!tableContainer) return;

        tableContainer.addEventListener('change', async (e) => {
            const toggle = e.target.closest('.email-public-toggle');
            if (!toggle) return;

            const id = toggle.getAttribute('data-email-id');
            const isPublic = toggle.checked;

            try {
                const response = await fetch(`/auth/email/link/${id}/`, {
                    method: 'PATCH',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken(),
                    },
                    body: JSON.stringify({ is_public: isPublic }),
                });

                if (!response.ok) {
                    toggle.checked = !isPublic;
                    showToast('Failed to update Link Deck status.', 'error');
                    return;
                }

                showToast(isPublic ? 'Email is now public on Link Deck.' : 'Email is now private.');
            } catch (err) {
                toggle.checked = !isPublic;
                showToast('Network error updating Link Deck status.', 'error');
            }
        });

        tableContainer.addEventListener('click', async (e) => {
            const removeBtn = e.target.closest('.remove-email-btn');
            if (removeBtn) {
                const id = removeBtn.getAttribute('data-email-id');
                const email = removeBtn.getAttribute('data-email');

                if (!confirm(`Are you sure you want to remove and unlock ${email}?`)) {
                    return;
                }

                try {
                    const response = await fetch(`/auth/email/link/${id}/`, {
                        method: 'DELETE',
                        headers: {
                            'X-CSRFToken': getCsrfToken(),
                        },
                    });

                    if (!response.ok) {
                        showToast('Failed to remove linked email.', 'error');
                        return;
                    }

                    const row = document.getElementById(`linked-email-row-${id}`);
                    if (row) {
                        row.classList.add('opacity-0', 'transition-opacity');
                        setTimeout(() => {
                            row.remove();
                            const tbody = document.getElementById('linked-emails-tbody');
                            if (tbody && tbody.children.length === 0) {
                                const emptyState = document.getElementById('linked-emails-empty');
                                if (emptyState) emptyState.classList.remove('hidden');
                            }
                        }, 200);
                    }

                    showToast(`Email ${email} removed.`);
                } catch (err) {
                    showToast('Network error removing email.', 'error');
                }
                return;
            }

            const exportBtn = e.target.closest('.export-vc-btn');
            if (exportBtn) {
                const id = exportBtn.getAttribute('data-email-id');
                const email = exportBtn.getAttribute('data-email');
                const isPrimary = exportBtn.getAttribute('data-is-primary') === 'true';

                const url = id
                    ? `/auth/email/link/${id}/vc/`
                    : `/auth/email/link/credential/?email=${encodeURIComponent(email || '')}`;

                try {
                    const response = await fetch(url, {
                        headers: {
                            'X-CSRFToken': getCsrfToken(),
                        },
                    });

                    if (!response.ok) {
                        showToast('Failed to load Verifiable Credential.', 'error');
                        return;
                    }

                    const data = await response.json();
                    openVcModal(email || data.email, data.vc);
                } catch (err) {
                    showToast('Network error loading credential.', 'error');
                }
            }
        });
    }

    function initVcModal() {
        const modal = document.getElementById('vc-export-modal');
        const pre = document.getElementById('vc-json-content');
        const copyBtn = document.getElementById('vc-copy-btn');
        const downloadBtn = document.getElementById('vc-download-btn');
        const closeBtns = document.querySelectorAll('.close-vc-modal-btn');
        const emailLabel = document.getElementById('vc-modal-email');

        if (!modal) return;

        window.openVcModal = function (email, vc) {
            currentExportEmail = email;
            currentExportVc = vc;

            if (emailLabel) emailLabel.textContent = email;
            if (pre) pre.textContent = JSON.stringify(vc, null, 2);

            modal.classList.remove('hidden');
        };

        function closeVcModal() {
            modal.classList.add('hidden');
            if (copyBtn) copyBtn.innerHTML = `
                <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
                    <path d="M8 2a1 1 0 000 2h2a1 1 0 100-2H8z" />
                    <path d="M3 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v6h-2V5H5v14a1 1 0 01-1 1H3a1 1 0 01-1-1V5z" />
                </svg>
                Copy JSON-LD
            `;
        }

        closeBtns.forEach(btn => btn.addEventListener('click', closeVcModal));

        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeVcModal();
        });

        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                if (!currentExportVc) return;
                const jsonText = JSON.stringify(currentExportVc, null, 2);
                navigator.clipboard.writeText(jsonText).then(() => {
                    copyBtn.innerHTML = `
                        <svg class="w-4 h-4 text-emerald-400" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                        </svg>
                        Copied!
                    `;
                    setTimeout(() => {
                        copyBtn.innerHTML = `
                            <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
                                <path d="M8 2a1 1 0 000 2h2a1 1 0 100-2H8z" />
                                <path d="M3 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v6h-2V5H5v14a1 1 0 01-1 1H3a1 1 0 01-1-1V5z" />
                            </svg>
                            Copy JSON-LD
                        `;
                    }, 2000);
                });
            });
        }

        if (downloadBtn) {
            downloadBtn.addEventListener('click', () => {
                if (!currentExportVc) return;
                const jsonText = JSON.stringify(currentExportVc, null, 2);
                const blob = new Blob([jsonText], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `email_ownership_credential_${currentExportEmail || 'identity'}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            });
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        initClaimModal();
        initTableActions();
        initVcModal();
    });
})();
