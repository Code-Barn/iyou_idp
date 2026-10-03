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

    function base64urlToUint8Array(base64url) {
        if (!base64url) return new Uint8Array();
        const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
        const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
    }

    function uint8ArrayToBase64url(arrayBuffer) {
        let binary = '';
        const bytes = new Uint8Array(arrayBuffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function appendPasskeyRow(credentialId, transports) {
        const tbody = document.getElementById('passkeys-tbody');
        if (!tbody) return;

        const row = document.createElement('tr');
        row.className = 'border-b border-gray-100 hover:bg-gray-50/70 transition-colors';

        const formattedDate = new Intl.DateTimeFormat('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        }).format(new Date());

        const previewId = credentialId.length > 20 ? `${credentialId.slice(0, 16)}…` : credentialId;
        const transportLabel = Array.isArray(transports) && transports.length > 0 ? transports.join(', ') : 'internal';

        row.innerHTML = `
            <td class="py-4 px-4 font-medium text-gray-900 flex items-center gap-3">
                <div class="w-8 h-8 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center flex-shrink-0">
                    <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="8" cy="15" r="4"/>
                        <path d="M10.85 12.15L19 4"/>
                        <path d="M18 5l2 2"/>
                        <path d="M15 8l2 2"/>
                    </svg>
                </div>
                <div>
                    <span class="text-sm font-semibold text-gray-800">Passkey Authenticator</span>
                    <p class="text-xs font-mono text-gray-400">${previewId}</p>
                </div>
            </td>
            <td class="py-4 px-4">
                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-700 border border-gray-200">
                    ${transportLabel}
                </span>
            </td>
            <td class="py-4 px-4 text-xs text-gray-500">
                ${formattedDate}
            </td>
            <td class="py-4 px-4 text-xs text-gray-400">
                Never used
            </td>
        `;

        tbody.appendChild(row);
    }

    function initPasskeyEnrollment() {
        const registerBtn = document.getElementById('register-passkey-btn');
        if (!registerBtn) return;

        if (!window.PublicKeyCredential) {
            registerBtn.disabled = true;
            registerBtn.title = 'WebAuthn passkeys are not supported in this browser.';
            return;
        }

        registerBtn.addEventListener('click', async () => {
            const originalText = registerBtn.innerHTML;
            registerBtn.disabled = true;
            registerBtn.innerHTML = `
                <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white inline" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Waiting for device...
            `;

            try {
                const beginResp = await fetch('/auth/passkeys/register/begin/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken(),
                    },
                    body: JSON.stringify({}),
                });

                if (!beginResp.ok) {
                    const errData = await beginResp.json().catch(() => ({}));
                    showToast(errData.error_description || errData.error || 'Failed to begin passkey registration.', 'error');
                    return;
                }

                const beginData = await beginResp.json();
                const publicKeyOptions = beginData.publicKey || beginData.options?.publicKey || beginData.options;

                if (!publicKeyOptions || !publicKeyOptions.challenge) {
                    showToast('Invalid server response for passkey registration.', 'error');
                    return;
                }

                publicKeyOptions.challenge = base64urlToUint8Array(publicKeyOptions.challenge);

                if (publicKeyOptions.user && typeof publicKeyOptions.user.id === 'string') {
                    publicKeyOptions.user.id = base64urlToUint8Array(publicKeyOptions.user.id);
                }

                if (Array.isArray(publicKeyOptions.excludeCredentials)) {
                    publicKeyOptions.excludeCredentials = publicKeyOptions.excludeCredentials.map(cred => ({
                        ...cred,
                        id: base64urlToUint8Array(cred.id),
                    }));
                }

                let credential;
                try {
                    credential = await navigator.credentials.create({ publicKey: publicKeyOptions });
                } catch (credErr) {
                    if (credErr.name === 'NotAllowedError' || credErr.name === 'AbortError') {
                        showToast('Passkey registration was cancelled.', 'error');
                    } else if (credErr.name === 'SecurityError') {
                        showToast('Passkey registration requires HTTPS or localhost.', 'error');
                    } else {
                        showToast(credErr.message || 'Passkey registration failed.', 'error');
                    }
                    return;
                }

                if (!credential) {
                    showToast('No credential returned by authenticator.', 'error');
                    return;
                }

                const credentialData = {
                    ceremony_id: beginData.ceremony_id,
                    id: credential.id,
                    rawId: uint8ArrayToBase64url(credential.rawId),
                    type: credential.type,
                    response: {
                        attestationObject: uint8ArrayToBase64url(credential.response.attestationObject),
                        clientDataJSON: uint8ArrayToBase64url(credential.response.clientDataJSON),
                        transports: credential.response.getTransports ? credential.response.getTransports() : [],
                    },
                };

                const completeResp = await fetch('/auth/passkeys/register/complete/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken(),
                    },
                    body: JSON.stringify(credentialData),
                });

                const completeData = await completeResp.json();

                if (!completeResp.ok) {
                    showToast(completeData.error_description || completeData.error || 'Failed to complete registration.', 'error');
                    return;
                }

                appendPasskeyRow(completeData.credential_id || credential.id, credentialData.response.transports);

                const emptyState = document.getElementById('passkeys-empty');
                if (emptyState) emptyState.classList.add('hidden');

                showToast('Hardware passkey registered successfully!');
            } catch (err) {
                showToast('Unexpected error during passkey registration.', 'error');
            } finally {
                registerBtn.disabled = false;
                registerBtn.innerHTML = originalText;
            }
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        initPasskeyEnrollment();
    });
})();
