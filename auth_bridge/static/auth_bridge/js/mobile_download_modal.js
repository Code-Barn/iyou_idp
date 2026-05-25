(function () {
  'use strict';

  var modal = document.getElementById('mobile-download-modal');
  var backdrop = document.getElementById('mobile-modal-backdrop');
  var closeBtn = document.getElementById('mobile-modal-close-btn');
  var detectionBanner = document.getElementById('mobile-detection-banner');
  var detectedOsEl = document.getElementById('mobile-detected-os');
  var tabBtns = document.querySelectorAll('.mobile-platform-tab');
  var panes = document.querySelectorAll('.mobile-platform-pane');

  if (!modal) return;

  // --- OS Detection ---
  function detectMobileOS() {
    var ua = (navigator.userAgent || navigator.platform || '').toLowerCase();
    if (/iphone|ipad|ipod/.test(ua)) return 'ios';
    if (/android/.test(ua)) return 'android';
    return null;
  }

  var detected = detectMobileOS();

  // --- Open / Close ---
  function openMobileModal() {
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    highlightMobileOS(detected);
    if (detected) {
      switchMobileTab(detected);
    }
  }

  function closeMobileModal() {
    modal.classList.add('hidden');
    document.body.style.overflow = '';
  }

  // Event Delegation — catches clicks from any template
  document.addEventListener('click', function (e) {
    if (e.target.closest('.open-mobile-download-modal') || e.target.closest('#mobile-download-modal-btn')) {
      e.preventDefault();
      openMobileModal();
    }
  });

  if (closeBtn) {
    closeBtn.addEventListener('click', closeMobileModal);
  }

  if (backdrop) {
    backdrop.addEventListener('click', closeMobileModal);
  }

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
      closeMobileModal();
    }
  });

  // --- OS Highlight ---
  function highlightMobileOS(os) {
    if (detectionBanner) detectionBanner.classList.add('hidden');

    tabBtns.forEach(function (btn) {
      btn.classList.remove('ring-2', 'ring-indigo-400', 'bg-white', 'shadow-sm', 'text-indigo-600');
      btn.classList.add('text-gray-500', 'bg-white');
    });

    if (!os) return;

    if (detectionBanner && detectedOsEl) {
      var labels = { ios: 'iOS', android: 'Android' };
      detectedOsEl.textContent = labels[os] || os;
      detectionBanner.classList.remove('hidden');
    }

    var targetTab = document.getElementById('mobile-tab-' + os);
    if (!targetTab) return;

    targetTab.classList.add('ring-2', 'ring-indigo-400');
  }

  // --- Tab Switching ---
  function switchMobileTab(platform) {
    tabBtns.forEach(function (btn) {
      btn.classList.remove('bg-white', 'shadow-sm', 'text-indigo-600');
      btn.classList.add('text-gray-500');
      btn.setAttribute('aria-selected', 'false');
    });

    panes.forEach(function (pane) {
      pane.classList.add('hidden');
    });

    var activeTab = document.getElementById('mobile-tab-' + platform);
    var activePane = document.getElementById('mobile-pane-' + platform);

    if (activeTab) {
      activeTab.classList.add('bg-white', 'shadow-sm', 'text-indigo-600');
      activeTab.classList.remove('text-gray-500');
      activeTab.setAttribute('aria-selected', 'true');
    }
    if (activePane) {
      activePane.classList.remove('hidden');
    }
  }

  // Tab click handlers
  tabBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      var platform = btn.getAttribute('data-mobile-platform');
      if (platform) switchMobileTab(platform);
    });
  });

  // --- Clipboard helper for F-Droid URL ---
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.mobile-dl-copy');
    if (!btn) return;

    var text = btn.getAttribute('data-clip');
    if (!text) return;

    e.preventDefault();
    navigator.clipboard.writeText(text).then(function () {
      var orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(function () { btn.textContent = orig; }, 2000);
    }).catch(function () {
      // Fallback: select and copy
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e) {}
      document.body.removeChild(ta);
      var orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(function () { btn.textContent = orig; }, 2000);
    });
  });

  // Re-highlight on modal re-open
  var observer = new MutationObserver(function () {
    if (!modal.classList.contains('hidden')) {
      highlightMobileOS(detected);
      if (detected) switchMobileTab(detected);
    }
  });
  observer.observe(modal, { attributes: true, attributeFilter: ['class'] });
})();
