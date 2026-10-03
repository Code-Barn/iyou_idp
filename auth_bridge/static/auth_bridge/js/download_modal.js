(function () {
  'use strict';

  var modal = document.getElementById('download-modal');
  var backdrop = document.getElementById('modal-backdrop');
  var closeBtn = document.getElementById('modal-close-btn');
  var openBtns = document.querySelectorAll('#download-modal-btn, .open-download-modal');
  var detectionBanner = document.getElementById('detection-banner');
  var detectedOsEl = document.getElementById('detected-os');

  if (!modal) return;

  var CACHE_KEY = 'iyou_home_latest_release_v2';
  var GITHUB_API_URL = 'https://api.github.com/repos/Code-Barn/iyou_home/releases/latest';
  var IPFS_FALLBACK_URL = 'https://ipfs.io/ipfs/QmUA8mAoo7fTZbG1hwvChbSVbD3trAhACBHjzYQDAoFDQu/';
  var MAGNET_FALLBACK_URI = 'magnet:?xt=urn:btih:6656bea4131bb570624ab6b39ea67fe2fbbff711&dn=iyou-home_0.2.2&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337%2Fannounce&tr=udp%3A%2F%2Fopen.demonii.com%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.torrent.eu.org%3A451%2Fannounce&ws=https%3A%2F%2Fgithub.com%2FCode-Barn%2Fiyou_home%2Freleases%2Fdownload%2Fv0.2.2%2F';

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

  function openModal() {
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    highlightOS(detected);
    fetchLatestRelease();
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

  function highlightOS(os) {
    var groups = document.querySelectorAll('.os-group');
    groups.forEach(function (g) {
      g.classList.remove('ring-2', 'ring-indigo-400');
      g.style.order = '';
    });

    if (detectionBanner) detectionBanner.classList.add('hidden');

    if (!os) return;

    if (detectionBanner && detectedOsEl) {
      var labels = { windows: 'Windows', macos: 'macOS', linux: 'Linux' };
      detectedOsEl.textContent = labels[os] || os;
      detectionBanner.classList.remove('hidden');
    }

    var target = document.getElementById('os-' + os);
    if (!target) return;

    target.classList.add('ring-2', 'ring-indigo-400');
    target.style.order = '-1';

    setTimeout(function () {
      var header = target.querySelector('.bg-gray-50');
      if (header) {
        var top = header.getBoundingClientRect().top + modal.querySelector('.overflow-y-auto').scrollTop - modal.querySelector('.overflow-y-auto').getBoundingClientRect().top - 80;
        modal.querySelector('.overflow-y-auto').scrollTo({ top: top, behavior: 'smooth' });
      }
    }, 150);
  }

  function copyToClipboard(text, onSuccess, onFallback) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        if (onSuccess) onSuccess();
      })["catch"](function () {
        fallbackCopy(text, onSuccess, onFallback);
      });
    } else {
      fallbackCopy(text, onSuccess, onFallback);
    }
  }

  function fallbackCopy(text, onSuccess, onFallback) {
    var successful = false;
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      ta.style.top = '-9999px';
      ta.setAttribute('readonly', '');
      document.body.appendChild(ta);
      ta.select();
      successful = document.execCommand('copy');
      document.body.removeChild(ta);
    } catch (err) {
      successful = false;
    }
    if (successful) {
      if (onSuccess) onSuccess();
    } else {
      if (onFallback) onFallback();
    }
  }

  function showMagnetCopied(el) {
    if (!el) return;
    if (el.dataset.copying === 'true') return;
    el.dataset.copying = 'true';

    var origHtml = el.innerHTML;
    var origTitle = el.getAttribute('title') || '';
    var origClasses = el.className;

    el.innerHTML = '<span>✓ Copied Magnet Link!</span>';
    el.classList.add('bg-emerald-100', 'text-emerald-800', 'border-emerald-300');
    el.classList.remove('bg-gray-100', 'text-gray-700');
    el.setAttribute('title', 'Copied Magnet Link!');

    setTimeout(function () {
      el.innerHTML = origHtml;
      el.className = origClasses;
      if (origTitle) {
        el.setAttribute('title', origTitle);
      } else {
        el.removeAttribute('title');
      }
      delete el.dataset.copying;
    }, 2000);
  }

  document.addEventListener('click', function (e) {
    var magnetBtn = e.target.closest('#dl-magnet, .dl-btn-magnet, [data-asset="magnet"]');
    if (magnetBtn) {
      e.preventDefault();
      var magnetUri = magnetBtn.getAttribute('href') || magnetBtn.href || MAGNET_FALLBACK_URI;
      copyToClipboard(
        magnetUri,
        function () {
          showMagnetCopied(magnetBtn);
        },
        function () {
          showMagnetCopied(magnetBtn);
        }
      );
      return;
    }

    var link = e.target.closest('.dl-link');
    if (!link) return;

    var magnetUri = (link.href && link.href.indexOf('magnet:') === 0) ? link.href : link.getAttribute('data-magnet');
    if (magnetUri) {
      e.preventDefault();
      copyToClipboard(
        magnetUri,
        function () {
          showMagnetCopied(link);
        },
        function () {
          window.location.href = magnetUri;
        }
      );
    }
  });

  function hydrateReleaseAssets(release) {
    if (!release || !Array.isArray(release.assets)) return;

    var assets = release.assets;

    var macAsset = null;
    var debAsset = null;
    var appImageAsset = null;
    var rpmAsset = null;
    var winAsset = null;
    var torrentAsset = null;

    for (var i = 0; i < assets.length; i++) {
      var a = assets[i];
      if (!a || !a.name) continue;
      if (a.name.endsWith('.dmg')) macAsset = a;
      if (a.name.endsWith('.deb')) debAsset = a;
      if (a.name.endsWith('.AppImage')) appImageAsset = a;
      if (a.name.endsWith('.rpm')) rpmAsset = a;
      if (a.name.endsWith('.exe')) winAsset = a;
      if (a.name.endsWith('.torrent')) torrentAsset = a;
    }

    if (macAsset) {
      var macBtns = modal.querySelectorAll('#dl-macos-dmg, .dl-btn-macos, [data-asset="macos-dmg"]');
      macBtns.forEach(function (el) {
        el.href = macAsset.browser_download_url;
        el.setAttribute('target', '_blank');
        el.setAttribute('rel', 'noopener noreferrer');
      });
    }

    if (debAsset) {
      var debBtns = modal.querySelectorAll('#dl-linux-deb, .dl-btn-linux-deb, [data-asset="linux-deb"]');
      debBtns.forEach(function (el) {
        el.href = debAsset.browser_download_url;
        el.setAttribute('target', '_blank');
        el.setAttribute('rel', 'noopener noreferrer');
      });
    }

    if (appImageAsset) {
      var appImageBtns = modal.querySelectorAll('#dl-linux-appimage, .dl-btn-linux-appimage, [data-asset="linux-appimage"]');
      appImageBtns.forEach(function (el) {
        el.href = appImageAsset.browser_download_url;
        el.setAttribute('target', '_blank');
        el.setAttribute('rel', 'noopener noreferrer');
      });
    }

    if (rpmAsset) {
      var rpmBtns = modal.querySelectorAll('#dl-linux-rpm, .dl-btn-linux-rpm, [data-asset="linux-rpm"]');
      rpmBtns.forEach(function (el) {
        el.href = rpmAsset.browser_download_url;
        el.setAttribute('target', '_blank');
        el.setAttribute('rel', 'noopener noreferrer');
      });
    }

    if (winAsset) {
      var winBtns = modal.querySelectorAll('#dl-windows-exe, .dl-btn-windows, [data-asset="windows-exe"]');
      winBtns.forEach(function (el) {
        el.href = winAsset.browser_download_url;
        el.setAttribute('target', '_blank');
        el.setAttribute('rel', 'noopener noreferrer');
      });
    }

    var torrentBtns = modal.querySelectorAll('#dl-bittorrent, .dl-btn-torrent, [data-asset="torrent"]');
    if (torrentAsset) {
      torrentBtns.forEach(function (el) {
        el.href = torrentAsset.browser_download_url;
        el.setAttribute('download', torrentAsset.name);
        el.setAttribute('target', '_blank');
        el.setAttribute('rel', 'noopener noreferrer');
      });
    }

    const magnetMatch = release.body && release.body.match(/magnet:\?xt=urn:btih:[a-zA-Z0-9]+[^\s"'<>]*/);
    var magnetBtns = modal.querySelectorAll('#dl-magnet, .dl-btn-magnet, [data-asset="magnet"]');

    if (magnetMatch && magnetMatch[0]) {
      var extractedMagnet = magnetMatch[0];
      magnetBtns.forEach(function (el) {
        el.href = extractedMagnet;
        el.classList.remove('hidden');
      });
      torrentBtns.forEach(function (el) {
        el.dataset.magnet = extractedMagnet;
        el.setAttribute('title', 'Direct .torrent file (Magnet available)');
      });
    } else {
      magnetBtns.forEach(function (el) {
        var existingHref = el.getAttribute('href');
        if (!existingHref || existingHref.indexOf('magnet:') !== 0) {
          el.href = MAGNET_FALLBACK_URI;
        }
        el.classList.remove('hidden');
      });
      torrentBtns.forEach(function (el) {
        var currentHref = el.dataset.magnet || MAGNET_FALLBACK_URI;
        el.dataset.magnet = currentHref;
        el.setAttribute('title', 'Direct .torrent file (Magnet available)');
      });
    }

    var ipfsBtns = modal.querySelectorAll('#dl-ipfs, .dl-btn-ipfs, [data-asset="ipfs"]');
    ipfsBtns.forEach(function (el) {
      var existingHref = el.getAttribute('href');
      if (!existingHref) {
        el.href = IPFS_FALLBACK_URL;
      }
      el.setAttribute('target', '_blank');
      el.setAttribute('rel', 'noopener noreferrer');
    });

    if (release.tag_name) {
      var tagBadges = modal.querySelectorAll('#release-version-badge, .release-tag-badge, #release-tag-badge');
      tagBadges.forEach(function (badge) {
        badge.textContent = release.tag_name;
      });
    }
  }

  function fetchLatestRelease() {
    try {
      var cached = sessionStorage.getItem(CACHE_KEY);
      if (cached) {
        var parsed = JSON.parse(cached);
        if (parsed && Array.isArray(parsed.assets)) {
          hydrateReleaseAssets(parsed);
          return;
        }
      }
    } catch (e) {
    }

    fetch(GITHUB_API_URL, {
      headers: { 'Accept': 'application/vnd.github.v3+json' }
    })
      .then(function (res) {
        if (!res.ok) throw new Error('API error');
        return res.json();
      })
      .then(function (data) {
        try {
          sessionStorage.setItem(CACHE_KEY, JSON.stringify(data));
        } catch (e) {
        }
        hydrateReleaseAssets(data);
      })
      .catch(function () {
      });
  }

  fetchLatestRelease();

  var observer = new MutationObserver(function () {
    if (!modal.classList.contains('hidden')) {
      highlightOS(detected);
    }
  });
  observer.observe(modal, { attributes: true, attributeFilter: ['class'] });
})();
