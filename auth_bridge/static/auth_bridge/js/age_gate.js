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

  var modal = document.getElementById('age-gate-modal');
  var monthSelect = document.getElementById('age-gate-month-select');
  var yearSelect = document.getElementById('age-gate-year-select');
  var continueBtn = document.getElementById('age-gate-continue-btn');
  var errorBanner = document.getElementById('age-gate-error');
  var guardianNotice = document.getElementById('age-gate-guardian-notice');

  var SET_URL = '/auth/age-gate/set/';
  var pendingRedirectUrl = null;
  var pendingShowDisclaimer = false;

  function initYears() {
    if (!yearSelect) return;
    if (yearSelect.options.length > 1) return;
    var currentYear = new Date().getFullYear();
    for (var y = currentYear; y >= currentYear - 100; y--) {
      var opt = document.createElement('option');
      opt.value = String(y);
      opt.textContent = String(y);
      yearSelect.appendChild(opt);
    }
  }

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

  function syncContinueButton() {
    if (!continueBtn || !monthSelect || !yearSelect) return;
    var validMonth = Boolean(monthSelect.value);
    var validYear = Boolean(yearSelect.value);
    continueBtn.disabled = !(validMonth && validYear);
  }

  function showError(msg) {
    if (!errorBanner) return;
    errorBanner.textContent = msg || 'An error occurred. Please try again.';
    errorBanner.classList.remove('hidden');
  }

  function hideError() {
    if (!errorBanner) return;
    errorBanner.textContent = '';
    errorBanner.classList.add('hidden');
  }

  function showModal(redirectUrl, showDisclaimer) {
    if (!modal) return;
    pendingRedirectUrl = redirectUrl || window.currentNextUrl || window.WUN_URL || '/';
    pendingShowDisclaimer = showDisclaimer !== false;
    initYears();
    hideError();
    if (guardianNotice) guardianNotice.classList.add('hidden');
    if (monthSelect) monthSelect.selectedIndex = 0;
    if (yearSelect) yearSelect.selectedIndex = 0;
    syncContinueButton();
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }

  function hideModal() {
    if (!modal) return;
    modal.classList.add('hidden');
    document.body.style.overflow = '';
  }

  function handleContinue() {
    if (!monthSelect || !yearSelect || !continueBtn) return;
    var month = parseInt(monthSelect.value, 10);
    var year = parseInt(yearSelect.value, 10);
    if (!month || !year) return;

    hideError();
    continueBtn.disabled = true;
    var originalText = continueBtn.innerHTML;
    continueBtn.innerHTML = '<span>Processing...</span>';

    var destination = pendingRedirectUrl || window.currentNextUrl || window.WUN_URL || '/';

    fetch(SET_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken()
      },
      body: JSON.stringify({
        month: month,
        year: year,
        next_url: destination
      })
    })
    .then(function (res) {
      return res.json().then(function (data) {
        if (!res.ok || !data.success) {
          throw new Error(data.error_description || data.error || 'Failed to establish age bracket.');
        }
        return data;
      });
    })
    .then(function (data) {
      var nextDest = data.redirect_url || destination;
      var requiresDisclaimer = Boolean(data.show_legal_disclaimer && pendingShowDisclaimer);

      if (data.requires_guardian && guardianNotice) {
        guardianNotice.classList.remove('hidden');
        setTimeout(function () {
          hideModal();
          if (requiresDisclaimer && typeof window.triggerLegalDisclaimerGate === 'function') {
            window.triggerLegalDisclaimerGate(nextDest);
          } else {
            window.location.href = nextDest;
          }
        }, 1200);
      } else {
        hideModal();
        if (requiresDisclaimer && typeof window.triggerLegalDisclaimerGate === 'function') {
          window.triggerLegalDisclaimerGate(nextDest);
        } else {
          window.location.href = nextDest;
        }
      }
    })
    .catch(function (err) {
      showError(err.message || 'Failed to update age bracket.');
      continueBtn.disabled = false;
      continueBtn.innerHTML = originalText;
    });
  }

  if (monthSelect) {
    monthSelect.addEventListener('change', syncContinueButton);
  }
  if (yearSelect) {
    yearSelect.addEventListener('change', syncContinueButton);
  }
  if (continueBtn) {
    continueBtn.addEventListener('click', handleContinue);
  }

  window.triggerAgeGate = function (redirectUrl, showDisclaimer) {
    showModal(redirectUrl, showDisclaimer);
  };

  window.closeAgeGate = function () {
    hideModal();
  };
})();
