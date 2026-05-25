(function () {
  'use strict';

  var modal = document.getElementById('download-modal');
  var backdrop = document.getElementById('modal-backdrop');
  var closeBtn = document.getElementById('modal-close-btn');
  var openBtns = document.querySelectorAll('#download-modal-btn, .open-download-modal');
  var detectionBanner = document.getElementById('detection-banner');
  var detectedOsEl = document.getElementById('detected-os');

  if (!modal) return;

  // --- OS Detection ---
  function detectOS() {
    var ua = navigator.userAgent || navigator.platform || '';
    if (navigator.userAgentData && navigator.userAgentData.platform) {
      ua = navigator.userAgentData.platform;
    }
    ua = ua.toLowerCase();
    if (ua.indexOf('win') !== -1) return 'windows';
    if (ua.indexOf('mac') !== -1) return 'macos';
    if (ua.indexOf('linux') !== -1) return 'linux';
    if (ua.indexOf('x11') !== -1) return 'linux';
    return null;
  }

  var detected = detectOS();

  // --- Open / Close ---
  function openModal() {
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    highlightOS(detected);
  }

  function closeModal() {
    modal.classList.add('hidden');
    document.body.style.overflow = '';
  }

  openBtns.forEach(function (btn) {
    btn.addEventListener('click', openModal);
  });

  if (closeBtn) {
    closeBtn.addEventListener('click', closeModal);
  }

  if (backdrop) {
    backdrop.addEventListener('click', closeModal);
  }

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
      closeModal();
    }
  });

  // --- OS Highlight ---
  function highlightOS(os) {
    // Reset all groups
    var groups = document.querySelectorAll('.os-group');
    groups.forEach(function (g) {
      g.classList.remove('ring-2', 'ring-indigo-400');
      g.style.order = '';
    });

    // Hide detection banner by default
    if (detectionBanner) detectionBanner.classList.add('hidden');

    if (!os) return;

    // Show detection banner
    if (detectionBanner && detectedOsEl) {
      var labels = { windows: 'Windows', macos: 'macOS', linux: 'Linux' };
      detectedOsEl.textContent = labels[os] || os;
      detectionBanner.classList.remove('hidden');
    }

    // Find target group and move it to top
    var target = document.getElementById('os-' + os);
    if (!target) return;

    target.classList.add('ring-2', 'ring-indigo-400');
    target.style.order = '-1';

    // Scroll to the highlighted section
    setTimeout(function () {
      var header = target.querySelector('.bg-gray-50');
      if (header) {
        var top = header.getBoundingClientRect().top + modal.querySelector('.overflow-y-auto').scrollTop - modal.querySelector('.overflow-y-auto').getBoundingClientRect().top - 80;
        modal.querySelector('.overflow-y-auto').scrollTo({ top: top, behavior: 'smooth' });
      }
    }, 150);
  }

  // --- Clipboard helper for magnet/IPFS ---
  document.addEventListener('click', function (e) {
    var link = e.target.closest('.dl-link');
    if (!link || link.hostname !== '') return;

    // For magnet links, optionally copy to clipboard
    if (link.href.indexOf('magnet:') === 0) {
      e.preventDefault();
      navigator.clipboard.writeText(link.href).then(function () {
        var orig = link.textContent;
        link.textContent = 'Copied!';
        setTimeout(function () { link.textContent = orig; }, 2000);
      })["catch"](function () {
        // Fallback — open magnet anyway
        window.location.href = link.href;
      });
    }
  });

  // If modal is already open (e.g. reopened), re-highlight
  var observer = new MutationObserver(function () {
    if (!modal.classList.contains('hidden')) {
      highlightOS(detected);
    }
  });
  observer.observe(modal, { attributes: true, attributeFilter: ['class'] });
})();
