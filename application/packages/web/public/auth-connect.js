// This page has no app bundle and no auth client. It hands a one-time PKCE
// code only to its exact same-origin opener, or to an explicit local copy.
// tests/accountConnection.test.ts covers refusal and URL scrubbing.
(function () {
  'use strict';
  function role(name) { return document.querySelector('[data-role="' + name + '"]'); }
  var nojs = role('nojs');
  if (nojs) nojs.hidden = true;
  var url = new URL(window.location.href);
  var code = url.searchParams.get('code');
  var state = url.searchParams.get('pn_connect');
  var error = url.searchParams.get('error');
  var valid = url.pathname === '/auth/connect' && !url.hash
    && url.searchParams.getAll('pn_connect').length === 1 && /^[A-Za-z0-9_-]{43}$/.test(state || '')
    && ((url.searchParams.getAll('code').length === 1 && code && code.length <= 8192 && !/\s/.test(code)) || error);
  var handoff = new URL(url.origin + '/auth/connect');
  if (valid) {
    handoff.searchParams.set('pn_connect', state);
    if (error) handoff.searchParams.set('error', error === 'access_denied' ? 'access_denied' : 'failed');
    else handoff.searchParams.set('code', code);
  }
  // Remove credentials before any subsequent navigation or user copy of the
  // address bar. The explicit copy button holds the bounded return URL.
  try { window.history.replaceState(null, '', url.pathname); } catch (e) { /* no navigation fallback */ }
  if (!valid) {
    var missing = role('missing');
    if (missing) missing.hidden = false;
    return;
  }
  try {
    if (window.opener) window.opener.postMessage({ type: 'pn-account-connect', url: handoff.toString() }, url.origin);
  } catch (e) { /* desktop and isolated popups use the explicit copy */ }
  if (error) {
    var refused = role('missing');
    if (refused) refused.hidden = false;
    return;
  }
  var out = role('code');
  if (out) out.textContent = handoff.toString();
  ['lede', 'codebox', 'steps'].forEach(function (name) { var el = role(name); if (el) el.hidden = false; });
  var btn = role('copy');
  if (btn) btn.addEventListener('click', function () {
    function select() {
      if (!out) return;
      var range = document.createRange(); range.selectNodeContents(out);
      var selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
      btn.textContent = 'Select and copy the link';
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(handoff.toString()).then(function () { btn.textContent = 'Copied'; }, select);
    } else select();
  });
})();
