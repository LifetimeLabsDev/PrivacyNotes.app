// Light/dark toggle for the static pages (/help, /changelog). Pages
// follow the system scheme by default; clicking the toggle stores an
// explicit override under the same localStorage key the app uses
// (src/theme.ts), so the preference is shared with the app.
(function () {
  var KEY = 'privacynotes.theme';
  var root = document.documentElement;

  function stored() {
    try {
      var v = localStorage.getItem(KEY);
      return v === 'light' || v === 'dark' ? v : null;
    } catch (e) {
      return null;
    }
  }

  function effective() {
    var s = stored();
    if (s) return s;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  var s = stored();
  if (s) root.setAttribute('data-theme', s);

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.addEventListener('click', function () {
      var next = effective() === 'dark' ? 'light' : 'dark';
      try {
        localStorage.setItem(KEY, next);
      } catch (e) {
        // Private browsing: still toggle visually for this page view.
      }
      root.setAttribute('data-theme', next);
    });
  });
})();
