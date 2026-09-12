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
  'use strict';

  var modal = document.getElementById('legal-disclaimer-modal');
  var checkbox = document.getElementById('disclaimer-consent-checkbox');
  var ackBtn = document.getElementById('disclaimer-acknowledge-btn');
  var ACK_URL = '/auth/legal-disclaimer/acknowledge/';

  var pendingRedirectUrl = null;

  function getCsrfToken() {
    if (window.csrfToken) return window.csrfToken;
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
      var cookies = document.cookie.split(';');
      for (var i = 0; i < cookies.length; i++) {
        var cookie = cookies[i].trim();
        if (cookie.substring(0, 'idp_csrftoken'.length + 1) === ('idp_csrftoken' + '=')) {
          cookieValue = decodeURIComponent(cookie.substring('idp_csrftoken'.length + 1));
          break;
        }
        if (cookie.substring(0, 'csrftoken'.length + 1) === ('csrftoken' + '=')) {
          cookieValue = decodeURIComponent(cookie.substring('csrftoken'.length + 1));
          break;
        }
      }
    }
    return cookieValue;
  }

  function syncAckButton() {
    if (ackBtn && checkbox) {
      ackBtn.disabled = !checkbox.checked;
    }
  }

  function showModal(redirectUrl) {
    if (!modal) return;
    pendingRedirectUrl = redirectUrl || window.currentNextUrl || window.WUN_URL || '/';
    if (checkbox) checkbox.checked = false;
    syncAckButton();
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }

  function hideModal() {
    if (!modal) return;
    modal.classList.add('hidden');
    document.body.style.overflow = '';
  }

  function handleAcknowledge() {
    // GDPR: affirmative consent is required before the acknowledgement fires.
    if (!checkbox || !checkbox.checked) return;
    if (!ackBtn) return;
    ackBtn.disabled = true;
    var originalText = ackBtn.innerHTML;
    ackBtn.innerHTML = '<span>Proceeding...</span>';

    var destination = pendingRedirectUrl || window.currentNextUrl || window.WUN_URL || '/';

    fetch(ACK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken()
      },
      body: JSON.stringify({ consent_accepted: true, next_url: destination })
    })
    .then(function (res) {
      if (!res.ok) throw new Error('acknowledgment failed');
      return res.json();
    })
    .then(function (data) {
      // Seamless inline redirect in the current window (target defaults to _self).
      window.location.href = data.redirect_url || destination;
    })
    .catch(function (err) {
      console.error('Failed to persist disclaimer acknowledgement:', err);
      ackBtn.disabled = false;
      ackBtn.innerHTML = originalText;
    });
  }

  if (checkbox) {
    checkbox.addEventListener('change', syncAckButton);
  }
  if (ackBtn) {
    ackBtn.addEventListener('click', handleAcknowledge);
  }

  window.triggerLegalDisclaimerGate = function (redirectUrl) {
    showModal(redirectUrl);
  };

  window.closeLegalDisclaimerGate = function () {
    hideModal();
  };
})();
