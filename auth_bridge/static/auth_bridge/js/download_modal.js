(function () {
  'use strict';

  var modal = document.getElementById('download-modal');
  var backdrop = document.getElementById('modal-backdrop');
  var closeBtn = document.getElementById('modal-close-btn');
  var openBtns = document.querySelectorAll('#download-modal-btn, .open-download-modal');
  var detectionBanner = document.getElementById('detection-banner');
  var detectedOsEl = document.getElementById('detected-os');

  if (!modal) return;

  var CACHE_KEY = 'iyou_home_latest_release';
  var GITHUB_API_URL = 'https://api.github.com/repos/Code-Barn/iyou_home/releases/latest';
  var IPFS_FALLBACK_URL = 'https://ipfs.io/ipfs/QmfKNn6iVjqo47r5zvwAH9k9mCFeotDLS4mGn1hZ7ETZjH/';
  var MAGNET_FALLBACK_URI = 'magnet:?xt=urn:btih:36aa52f89e030d0a0daf79dffadef7b8ec8277b2&dn=iyou-home_0.2.2&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337%2Fannounce&tr=udp%3A%2F%2Fopen.demonii.com%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.torrent.eu.org%3A451%2Fannounce';

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
    if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
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

  document.addEventListener('click', function (e) {
    var link = e.target.closest('.dl-link');
    if (!link) return;

    var magnetUri = (link.href && link.href.indexOf('magnet:') === 0) ? link.href : link.getAttribute('data-magnet');

    if (magnetUri) {
      e.preventDefault();
      copyToClipboard(
        magnetUri,
        function () {
          var orig = link.textContent;
          link.textContent = 'Copied!';
          setTimeout(function () { link.textContent = orig; }, 2000);
        },
        function () {
          window.location.href = magnetUri;
        }
      );
    }
  });

  function parseMirrorsTxt(text) {
    var result = {};
    if (!text) return result;
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.indexOf('#') === 0) continue;
      var eqIdx = line.indexOf('=');
      if (eqIdx !== -1) {
        var key = line.slice(0, eqIdx).trim();
        var val = line.slice(eqIdx + 1).trim();
        result[key] = val;
      }
    }
    return result;
  }

  function hydrateReleaseAssets(release) {
    if (!release || !Array.isArray(release.assets)) return;

    var assets = release.assets;

    var macAsset = null;
    var debAsset = null;
    var appImageAsset = null;
    var rpmAsset = null;
    var winAsset = null;
    var torrentAsset = null;
    var mirrorsAsset = null;

    for (var i = 0; i < assets.length; i++) {
      var a = assets[i];
      if (!a || !a.name) continue;
      if (a.name.endsWith('.dmg')) macAsset = a;
      if (a.name.endsWith('.deb')) debAsset = a;
      if (a.name.endsWith('.AppImage')) appImageAsset = a;
      if (a.name.endsWith('.rpm')) rpmAsset = a;
      if (a.name.endsWith('.exe')) winAsset = a;
      if (a.name.endsWith('.torrent')) torrentAsset = a;
      if (a.name === 'MIRRORS.txt') mirrorsAsset = a;
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

    if (release.tag_name) {
      var tagBadges = modal.querySelectorAll('#release-version-badge, .release-tag-badge, #release-tag-badge');
      tagBadges.forEach(function (badge) {
        badge.textContent = release.tag_name;
      });
    }

    var ipfsBtns = modal.querySelectorAll('#dl-ipfs, .dl-btn-ipfs, [data-asset="ipfs"]');
    var magnetBtns = modal.querySelectorAll('#dl-magnet, .dl-btn-magnet, [data-asset="magnet"]');

    if (mirrorsAsset && mirrorsAsset.browser_download_url) {
      fetch(mirrorsAsset.browser_download_url)
        .then(function (res) {
          if (!res.ok) throw new Error('Fetch failed');
          return res.text();
        })
        .then(function (txt) {
          var mirrors = parseMirrorsTxt(txt);

          var ipfsUrl = mirrors.IPFS_GATEWAY_URL || IPFS_FALLBACK_URL;
          ipfsBtns.forEach(function (el) {
            el.href = ipfsUrl;
            el.setAttribute('target', '_blank');
            el.setAttribute('rel', 'noopener noreferrer');
          });

          var magnetUrl = mirrors.MAGNET_LINK || MAGNET_FALLBACK_URI;
          magnetBtns.forEach(function (el) {
            el.href = magnetUrl;
            el.classList.remove('hidden');
          });

          torrentBtns.forEach(function (el) {
            el.dataset.magnet = magnetUrl;
            el.setAttribute('title', 'Direct .torrent file (Magnet available)');
          });
        })
        .catch(function () {
          ipfsBtns.forEach(function (el) {
            el.href = IPFS_FALLBACK_URL;
            el.setAttribute('target', '_blank');
            el.setAttribute('rel', 'noopener noreferrer');
          });
          magnetBtns.forEach(function (el) {
            el.href = MAGNET_FALLBACK_URI;
            el.classList.remove('hidden');
          });
        });
    } else {
      ipfsBtns.forEach(function (el) {
        el.href = IPFS_FALLBACK_URL;
        el.setAttribute('target', '_blank');
        el.setAttribute('rel', 'noopener noreferrer');
      });
      magnetBtns.forEach(function (el) {
        el.href = MAGNET_FALLBACK_URI;
        el.classList.remove('hidden');
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
