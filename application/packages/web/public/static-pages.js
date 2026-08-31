// Progressive enhancement for the static pre-rendered pages (/help and
// /changelog). Served same-origin because the deployed CSP allows
// script-src 'self' but no inline scripts (same pattern as
// /theme-toggle.js). Every page renders complete without this file: the
// FAQ search box ships hidden and is revealed here, the changelog filter
// chips are built here from data attributes, and everything else
// (details/summary expand, anchors, theme) is native.
//
// Wired from help-page.ts, changelog-page.ts and brand-page.ts via
// <script src="/static-pages.js" defer>. Which behavior applies is
// selected by <body data-static-page="help|help-leaf|help-guide|changelog|
// brand|landing|cheatsheet">.
(function () {
  'use strict';

  function norm(s) {
    return s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
  }

  function fill(template, vars) {
    return template.replace(/\{\{(\w+)\}\}/g, function (_, k) {
      return String(vars[k] == null ? '' : vars[k]);
    });
  }

  // ---- highlight helpers (shared by the Help hub and the changelog) ----
  // Both pages filter a list in place and both have to show WHERE the query
  // hit, so these live at module scope rather than inside one initialiser.

  function unmark(root) {
    Array.prototype.slice.call(root.querySelectorAll('mark')).forEach(function (m) {
      m.replaceWith(document.createTextNode(m.textContent));
    });
    root.normalize();
  }

  function markIn(root, query) {
    var q = query.toLowerCase();
    if (!q) return;
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    var nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(function (node) {
      if (node.parentElement && node.parentElement.tagName === 'MARK') return;
      var text = node.textContent;
      var idx = text.toLowerCase().indexOf(q);
      if (idx < 0) return;
      var frag = document.createDocumentFragment();
      var rest = text;
      var guard = 0;
      while (idx >= 0 && guard < 20) {
        frag.appendChild(document.createTextNode(rest.slice(0, idx)));
        var mark = document.createElement('mark');
        mark.textContent = rest.slice(idx, idx + q.length);
        frag.appendChild(mark);
        rest = rest.slice(idx + q.length);
        idx = rest.toLowerCase().indexOf(q);
        guard++;
      }
      frag.appendChild(document.createTextNode(rest));
      node.replaceWith(frag);
    });
  }

  // Copy-to-clipboard with a transient confirmation on the button itself.
  // Used by the Help entries' copy-link row and the changelog's per-release
  // permalink; both want "did that work?" answered in place.
  function copyOnClick(btn, url, done, undo) {
    btn.addEventListener('click', function () {
      navigator.clipboard.writeText(url).then(function () {
        done();
        setTimeout(undo, 1600);
      });
    });
  }

  // ---- language plumbing (mirrors languages.tsx / LanguageSuggest.tsx) ----
  var LANG_KEY = 'privacynotes.language';
  var EXPLICIT_KEY = 'privacynotes.langExplicit';
  var DISMISS_KEY = 'privacynotes.langSuggestDismissed';

  function readStore(key) {
    try {
      return localStorage.getItem(key);
    } catch (err) {
      return null;
    }
  }

  function persistLanguage(value) {
    try {
      if (value === 'system') {
        localStorage.removeItem(LANG_KEY);
        localStorage.removeItem(EXPLICIT_KEY);
      } else {
        localStorage.setItem(LANG_KEY, value);
        localStorage.setItem(EXPLICIT_KEY, '1');
      }
    } catch (err) {
      /* storage blocked: the navigation still works */
    }
  }

  // preferredLocale() equivalent: exact match, then 2-letter prefix.
  function preferredLocale(codes) {
    var nav = (navigator.language || 'en').toLowerCase();
    return (
      codes.find(function (c) {
        return c.toLowerCase() === nav;
      }) ||
      codes.find(function (c) {
        return nav.indexOf(c.toLowerCase().slice(0, 2)) === 0;
      }) ||
      null
    );
  }

  // A Help page carries TWO switchers - header rail and footer - the same
  // way the homepage does. Both are wired identically; neither is special.
  // Every menu declares the same data-locales payload, so the first one
  // found answers for the auto-route below.
  var langMenus = [].slice.call(document.querySelectorAll('.langmenu'));
  var langLocales = null;
  if (langMenus.length) {
    for (var i = 0; i < langMenus.length && !langLocales; i++) {
      try {
        langLocales = JSON.parse(langMenus[i].getAttribute('data-locales'));
      } catch (err) {
        langLocales = null;
      }
    }

    // Close on outside click or Escape (native <details> only closes via
    // its own summary).
    document.addEventListener('click', function (e) {
      langMenus.forEach(function (menu) {
        if (menu.open && !menu.contains(e.target)) menu.open = false;
      });
    });
    document.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape') return;
      langMenus.forEach(function (menu) {
        menu.open = false;
      });
    });

    langMenus.forEach(function (menu) {
      // Opening one closes the other, so the page never shows two lists.
      menu.addEventListener('toggle', function () {
        if (!menu.open) return;
        langMenus.forEach(function (other) {
          if (other !== menu) other.open = false;
        });
      });

      // Choosing a language mirrors the homepage switcher: persist under
      // the app's own keys so app, homepage, and static pages follow one
      // choice. The System row clears the override and lands on the
      // x-default hub, where the auto-route below re-detects.
      menu.addEventListener('click', function (e) {
        var link = e.target.closest ? e.target.closest('a[data-lang]') : null;
        if (!link) return;
        persistLanguage(link.getAttribute('data-lang'));
      });
    });

    autoRouteLanguage();
    suggestBanner();
  }

  // First visit to the x-default /help hub: route to the visitor's
  // language. Precedence mirrors the app: explicit choice > browser
  // language > stay on English. Runs ONLY on the apex hub (leaves,
  // guides, and translated pages render exactly what their URL says; a
  // shared link must never bounce its recipient), and only once per
  // session.
  function autoRouteLanguage() {
    if (!langLocales) return;
    if (document.body.getAttribute('data-locale') !== 'en') return;
    if (location.pathname.replace(/\/+$/, '') !== '/help') return;
    var MARKER = 'pn:static-lang-routed';
    try {
      if (sessionStorage.getItem(MARKER)) return;
      sessionStorage.setItem(MARKER, '1');
    } catch (err) {
      return;
    }
    var target = readStore(EXPLICIT_KEY) === '1' ? readStore(LANG_KEY) : null;
    if (!target || langLocales[target] == null) {
      target = preferredLocale(Object.keys(langLocales)) || 'en';
    }
    if (target !== 'en' && langLocales[target] != null) {
      location.replace(langLocales[target] + '/help' + location.hash);
    }
  }

  // Dismissible "View in <language>" pill, the static twin of the
  // homepage's LanguageSuggest banner: same keys, same precedence, same
  // strings (baked from settings.json langSuggest.* into data-suggest),
  // labelled in the suggested language. Navigates to the SAME page in the
  // suggested locale, preserving leaf paths.
  function suggestBanner() {
    var body = document.body;
    var raw = body.getAttribute('data-suggest');
    var pageLocale = body.getAttribute('data-locale');
    if (!raw || !pageLocale || !langLocales) return;
    if (readStore(EXPLICIT_KEY) === '1' || readStore(DISMISS_KEY) === '1') return;
    var strings;
    try {
      strings = JSON.parse(raw);
    } catch (err) {
      return;
    }
    var suggested = preferredLocale(Object.keys(langLocales));
    if (!suggested || suggested === pageLocale || !strings[suggested]) return;

    var currentPrefix = langLocales[pageLocale] || '';
    var rest = location.pathname.slice(currentPrefix.length);
    var targetPath = (langLocales[suggested] || '') + rest + location.hash;

    var banner = document.createElement('div');
    banner.className = 'lang-banner';
    var link = document.createElement('a');
    link.href = targetPath;
    var flagSrc = langMenus[0].querySelector('a[data-lang="' + suggested + '"] svg');
    if (flagSrc) link.appendChild(flagSrc.cloneNode(true));
    link.appendChild(document.createTextNode(strings[suggested].action));
    link.addEventListener('click', function () {
      persistLanguage(suggested);
    });
    var dismiss = document.createElement('button');
    dismiss.type = 'button';
    dismiss.setAttribute('aria-label', strings[suggested].dismiss);
    dismiss.textContent = '×';
    dismiss.addEventListener('click', function () {
      try {
        localStorage.setItem(DISMISS_KEY, '1');
      } catch (err) {
        /* still hide for this view */
      }
      banner.remove();
    });
    banner.appendChild(link);
    banner.appendChild(dismiss);
    var wrap = document.querySelector('.wrap');
    var anchor = document.querySelector('.pcols');
    if (wrap && anchor) wrap.insertBefore(banner, anchor);
  }

  // A leaf answers one question, so there is nothing on the page to filter:
  // its box searches question TITLES across the whole FAQ and jumps you
  // straight to the one you pick. The form still GETs the hub when JS is
  // off, or when the query wants the full-text search over answer bodies.
  function initLeafSearch() {
    var form = document.getElementById('faq-lform');
    var input = document.getElementById('faq-lq');
    var out = document.getElementById('faq-sr');
    if (!form || !input || !out) return;
    var rows;
    try {
      rows = JSON.parse(form.getAttribute('data-index') || '[]');
    } catch (err) {
      return;
    }
    if (!rows.length) return;
    var hay = rows.map(function (r) {
      return norm(r[0]);
    });
    var allTpl = form.getAttribute('data-search-all') || '';
    var hubPath = form.getAttribute('action') || '/help';
    var clear = document.getElementById('faq-lclear');
    var active = -1;

    function render(raw) {
      var typed = raw.trim();
      var q = norm(typed);
      form.classList.toggle('has-q', raw.length > 0);
      out.textContent = '';
      active = -1;
      if (!q) {
        out.hidden = true;
        return;
      }
      var shown = 0;
      for (var i = 0; i < rows.length && shown < 8; i++) {
        if (hay[i].indexOf(q) < 0) continue;
        var hit = document.createElement('a');
        hit.className = 'sr-item';
        hit.href = rows[i][1];
        hit.textContent = rows[i][0];
        out.appendChild(hit);
        shown++;
      }
      // Always last, hit or miss: titles are only half the index, so the
      // way out of a leaf search is never a dead end.
      var all = document.createElement('a');
      all.className = 'sr-item sr-all';
      all.href = hubPath + '?q=' + encodeURIComponent(typed);
      all.textContent = fill(allTpl, { q: typed });
      out.appendChild(all);
      out.hidden = false;
    }

    function move(step) {
      var items = out.querySelectorAll('.sr-item');
      if (!items.length) return;
      active = (active + step + items.length) % items.length;
      for (var i = 0; i < items.length; i++) items[i].classList.toggle('on', i === active);
      items[active].scrollIntoView({ block: 'nearest' });
    }

    input.addEventListener('input', function () {
      render(input.value);
    });
    if (clear)
      clear.addEventListener('click', function () {
        input.value = '';
        render('');
        input.focus();
      });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        move(e.key === 'ArrowDown' ? 1 : -1);
      } else if (e.key === 'Escape') {
        if (input.value) {
          input.value = '';
          render('');
        } else input.blur();
      } else if (e.key === 'Enter') {
        var sel = out.querySelector('.sr-item.on');
        // Nothing picked means "search everything": let the form GET the
        // hub, which also matches the answer bodies.
        if (sel) {
          e.preventDefault();
          location.href = sel.href;
        }
      }
    });
    document.addEventListener('keydown', function (e) {
      var tag = document.activeElement && document.activeElement.tagName;
      if (e.key === '/' && tag !== 'INPUT' && tag !== 'TEXTAREA') {
        e.preventDefault();
        input.focus();
      }
    });
  }

  // The Help link is the one nav destination that exists in every language.
  // Translated pages bake their own locale into the href at build time; the
  // English-only pages (changelog, roadmap, brand) ship /help plus the slug
  // table and get re-pointed here, at the reader's own language. Precedence
  // matches the rest of the site: an explicit choice beats browser detection.
  // Falls back to plain /help whenever nothing matches, so the link is never
  // worse than it was.
  (function localizeHelpLink() {
    var link = document.querySelector('.nav-help[data-help-locales]');
    if (!link) return;
    var map;
    try {
      map = JSON.parse(link.getAttribute('data-help-locales'));
    } catch (err) {
      return;
    }
    var pick = readStore(EXPLICIT_KEY) === '1' ? readStore(LANG_KEY) : null;
    if (!pick || !map[pick]) pick = preferredLocale(Object.keys(map));
    if (pick && map[pick]) link.setAttribute('href', map[pick]);
  })();

  var page = document.body.getAttribute('data-static-page');
  if (page && page.indexOf('help') === 0) { initAsk(); initCopyRows(); }
  if (page === 'help') initFaq();
  if (page === 'help-leaf') initLeafSearch();
  if (page === 'changelog') initChangelog();
  if (page === 'brand') { initBrand(); initBrandRail(); }
  if (page === 'landing') initLanding();
  if (page === 'cheatsheet') initCheatSheet();

  // The printable hotkey cheat sheet (help-page.ts). Two enhancements, and
  // the page renders complete without either: the Print button, and the
  // platform swap - the sheet is pre-rendered with Mac symbols (so no-JS
  // and crawlers get the same sheet the legend describes), and off-Mac each
  // keycap is rewritten to Ctrl/Alt/Shift words, mirroring renderKey() in
  // HotkeysModal.tsx. The legend flips with it: the "⌘ is Ctrl" line hides
  // and the reverse "Ctrl is ⌘" line shows.
  function initCheatSheet() {
    var btn = document.getElementById('cs-print');
    if (btn) btn.addEventListener('click', function () { window.print(); });
    var mac = /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent);
    if (mac) return;
    var map = { '⌘': 'Ctrl', '⌥': 'Alt', '⇧': 'Shift', '⌫': 'Backspace' };
    var caps = document.querySelectorAll('.s-cap');
    for (var i = 0; i < caps.length; i++) {
      var t = caps[i].textContent;
      if (!/[⌘⌥⇧⌫]/.test(t)) continue;
      // Each symbol becomes its word plus a joining "+", then the trailing
      // "+" is trimmed: "⌘" -> "Ctrl". Caps are single symbols since the
      // range split in help-page.ts keyCaps; the "+" join is kept for any
      // future multi-symbol cap.
      t = t.replace(/[⌘⌥⇧⌫]/g, function (m) { return map[m] + '+'; });
      caps[i].textContent = t.replace(/\+$/, '');
    }
    var legendMac = document.getElementById('cs-legend-mac');
    var legendPc = document.getElementById('cs-legend-pc');
    if (legendMac) legendMac.hidden = true;
    if (legendPc) legendPc.hidden = false;
  }

  // SEO landing pages (landing-pages.ts): the sticky bottom CTA and the
  // typing-editor hero. Both are extras on top of a complete page: the
  // sticky bar ships hidden, and the editor ships with its full text
  // rendered, so no-JS readers (and reduced-motion readers) lose nothing.
  function initLanding() {
    var sticky = document.querySelector('.l-sticky');
    var hero = document.querySelector('.l-hero');
    var band = document.querySelector('.l-band');
    if (sticky && hero && band && 'IntersectionObserver' in window) {
      var pastHero = false;
      var atBand = false;
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (e.target === hero) pastHero = !e.isIntersecting;
          if (e.target === band) atBand = e.isIntersecting;
        });
        sticky.hidden = !(pastHero && !atBand);
      });
      io.observe(hero);
      io.observe(band);
    }
    var typer = document.querySelector('[data-landing-typer]');
    if (!typer || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    var lines = [].slice.call(typer.children);
    var full = lines.map(function (el) {
      return el.textContent;
    });
    lines.forEach(function (el) {
      el.textContent = ' ';
    });
    var caret = document.createElement('span');
    caret.className = 'el-caret';
    var li = 0;
    var ci = 0;
    function tick() {
      if (li >= lines.length) {
        caret.remove();
        return;
      }
      var text = full[li];
      ci++;
      if (ci > text.length) {
        li++;
        ci = 0;
        setTimeout(tick, 90);
        return;
      }
      lines[li].textContent = text.slice(0, ci) || ' ';
      lines[li].appendChild(caret);
      setTimeout(tick, 16 + Math.random() * 36);
    }
    setTimeout(tick, 350);
  }

  // The "Ask an AI" box on every Help view (hub, leaf, guide). The button
  // ships hidden and is revealed here, so a reader without JS still gets the
  // prompt from the <details> below it rather than a button that does
  // nothing. The confirmation label rides on data-copied because this page
  // is translated, unlike /brand where 'Copied' can be hardcoded.
  function initAsk() {
    var src = document.getElementById('ask-prompt');
    var buttons = [].slice.call(document.querySelectorAll('.js-ask-copy'));
    if (!src || !buttons.length || !navigator.clipboard) return;
    // textContent, NOT innerText: the prompt lives inside a closed <details>,
    // and innerText returns '' for anything not being rendered - which copies
    // an empty clipboard and looks like it worked. /brand can use innerText
    // because its blocks are always visible.
    var text = src.textContent;
    buttons.forEach(function (btn) {
      btn.hidden = false;
      var lbl = btn.querySelector('.lbl');
      var idle = lbl ? lbl.textContent : '';
      var done = btn.getAttribute('data-copied') || idle;
      // The compact button sits inside the <summary>, so its click would
      // toggle the disclosure as well as copying. Swallow it there.
      btn.addEventListener('click', function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
      });
      copyOnClick(
        btn,
        text,
        function () {
          if (lbl) lbl.textContent = done;
          btn.classList.remove('on');
          // Reflow between removing and re-adding, or a second click inside
          // the confirmation window never restarts the keyframe.
          void btn.offsetWidth;
          btn.classList.add('on');
        },
        function () {
          if (lbl) lbl.textContent = idle;
          btn.classList.remove('on');
        }
      );
    });
  }


  // Copy rows inside a Help answer: a backticked paragraph in the catalog
  // renders as <div class="cbx"><code>value</code><button></div>. The button
  // ships hidden and is revealed here, so a reader without JS still sees the
  // value and can select it by hand. Each button copies the <code> beside it,
  // so a page may carry several without any per-row wiring.
  function initCopyRows() {
    if (!navigator.clipboard) return;
    [].slice.call(document.querySelectorAll('.cbx .js-cbx-copy')).forEach(function (btn) {
      var src = btn.parentNode.querySelector('code');
      if (!src) return;
      btn.hidden = false;
      var lbl = btn.querySelector('.lbl');
      var idle = lbl ? lbl.textContent : '';
      var done = btn.getAttribute('data-copied') || idle;
      copyOnClick(
        btn,
        src.textContent,
        function () {
          if (lbl) lbl.textContent = done;
          btn.classList.remove('on');
          void btn.offsetWidth;
          btn.classList.add('on');
        },
        function () {
          if (lbl) lbl.textContent = idle;
          btn.classList.remove('on');
        }
      );
    });
  }

  // /brand: reveal the copy buttons and wire them to their text blocks.
  // The buttons ship hidden; without JS the text stays selectable as-is.
  function initBrand() {
    if (!navigator.clipboard) return;
    var buttons = [].slice.call(document.querySelectorAll('[data-copy]'));
    buttons.forEach(function (btn) {
      btn.hidden = false;
      btn.addEventListener('click', function () {
        var src = document.getElementById(btn.getAttribute('data-copy'));
        if (!src) return;
        navigator.clipboard.writeText(src.innerText).then(function () {
          var old = btn.textContent;
          btn.textContent = 'Copied';
          btn.classList.add('on');
          setTimeout(function () {
            btn.textContent = old;
            btn.classList.remove('on');
          }, 900);
        });
      });
    });
  }

  function initFaq() {
    var search = document.getElementById('faq-search');
    var input = document.getElementById('faq-q');
    var count = document.getElementById('faq-count');
    var rail = document.getElementById('faq-rail');
    if (!search || !input || !count) return;

    var entries = Array.prototype.slice.call(document.querySelectorAll('details.entry'));
    var groups = Array.prototype.slice.call(document.querySelectorAll('section.fgroup'));
    // Topic rows (.rt) map onto the FAQ groups for filtering and the
    // scroll-spy; guide rows (.rg) carry their own data-s haystack and
    // are matched independently so a guide-only term still lights up.
    var railItems = rail ? Array.prototype.slice.call(rail.querySelectorAll('.ritem.rt')) : [];
    var guideItems = rail ? Array.prototype.slice.call(rail.querySelectorAll('.ritem.rg')) : [];

    // Match each topic row to its section by the #g-<key> fragment it
    // already carries rather than by position, so reordering either list
    // cannot make the filter dim or spotlight the wrong topic.
    var railByGroup = {};
    railItems.forEach(function (r) {
      var hash = (r.getAttribute('href') || '').split('#')[1];
      if (!hash) return;
      railByGroup[hash] = r;
      var ct = r.querySelector('.rct');
      if (ct) ct.setAttribute('data-full', ct.textContent);
    });

    var total = Number(search.getAttribute('data-total')) || entries.length;

    search.hidden = false;

    // --- copy-link button per answer -------------------------------------
    var copyLabel = search.getAttribute('data-copy') || 'Copy link';
    var copiedLabel = search.getAttribute('data-copied') || 'Copied';
    // Same chain link the entry's own permalink anchor draws (LINK_ICON in
    // static-page-chrome.ts), one size down to sit in the copy row.
    var linkIcon =
      '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>';
    if (navigator.clipboard) {
      entries.forEach(function (entry) {
        var body = entry.querySelector('.a');
        if (!body) return;
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'copybtn';
        btn.innerHTML = linkIcon + '<span>' + copyLabel + '</span>';
        // Copy the entry's LEAF page URL (its own indexable landing page),
        // not a #fragment: nicer to share, and every share seeds Google
        // with a signal for that page.
        var leaf = entry.getAttribute('data-leaf');
        var shareUrl = leaf
          ? location.origin + leaf
          : location.origin + location.pathname + '#' + entry.id;
        copyOnClick(
          btn,
          shareUrl,
          function () {
            btn.querySelector('span').textContent = copiedLabel;
          },
          function () {
            btn.querySelector('span').textContent = copyLabel;
          }
        );
        body.appendChild(btn);
      });
    }

    // --- deep links: #<entry-id> auto-opens its answer --------------------
    function openFromHash() {
      var id = location.hash.slice(1);
      if (!id) return;
      var target = document.getElementById(id);
      if (target && target.classList.contains('entry')) {
        target.open = true;
        requestAnimationFrame(function () {
          target.scrollIntoView({ block: 'start', behavior: 'smooth' });
        });
      }
    }
    openFromHash();
    window.addEventListener('hashchange', openFromHash);

    // --- clearing the query ------------------------------------------------
    // One path for every way out of a search: the X in the box, the button
    // in the empty state, Escape, and clicking a topic the query emptied.
    function setQuery(value, keepFocus) {
      input.value = value;
      applyFilter(value);
      if (keepFocus) input.focus();
    }

    var clearBtn = document.getElementById('faq-clear');
    var emptyClear = document.getElementById('faq-empty-clear');
    if (clearBtn)
      clearBtn.addEventListener('click', function () {
        setQuery('', true);
      });
    if (emptyClear)
      emptyClear.addEventListener('click', function () {
        setQuery('', true);
      });

    // --- "/" focuses the search ------------------------------------------
    document.addEventListener('keydown', function (e) {
      var tag = document.activeElement && document.activeElement.tagName;
      if (e.key === '/' && tag !== 'INPUT' && tag !== 'TEXTAREA') {
        e.preventDefault();
        input.focus();
      }
      // Escape clears first and only leaves the box on a second press, so
      // one keystroke never both wipes the query and drops focus.
      if (e.key === 'Escape' && document.activeElement === input) {
        if (input.value) setQuery('', true);
        else input.blur();
      }
    });

    // --- live filter --------------------------------------------------------
    var autoOpened = [];
    var empty = document.getElementById('faq-empty');
    var emptyLead = document.getElementById('faq-empty-lead');

    // The rail is how you get out of a search that went nowhere, so it
    // never disappears with the results: a topic with no hits dims and
    // reports 0 instead of vanishing, which also turns the counts into a
    // map of where the matches actually are. Passing null restores it.
    function setRail(g, matches) {
      var r = railByGroup[g.id];
      if (!r) return;
      r.classList.toggle('dim', matches === 0);
      var ct = r.querySelector('.rct');
      if (ct) ct.textContent = matches == null ? ct.getAttribute('data-full') : String(matches);
    }

    function applyFilter(raw) {
      var q = norm(raw.trim());
      search.classList.toggle('has-q', raw.length > 0);

      autoOpened.forEach(function (entry) {
        entry.open = false;
      });
      autoOpened = [];
      entries.forEach(function (entry) {
        unmark(entry);
        entry.hidden = false;
      });

      if (!q) {
        groups.forEach(function (g) {
          g.hidden = false;
          setRail(g, null);
        });
        guideItems.forEach(function (r) {
          r.classList.remove('dim');
        });
        count.textContent = '';
        if (empty) empty.hidden = true;
        return;
      }

      var shown = 0;
      entries.forEach(function (entry) {
        var hit = (entry.getAttribute('data-s') || '').indexOf(q) >= 0;
        entry.hidden = !hit;
        if (hit) shown++;
      });

      groups.forEach(function (g) {
        var hits = g.querySelectorAll('details.entry:not([hidden])').length;
        g.hidden = hits === 0;
        setRail(g, hits);
      });

      guideItems.forEach(function (r) {
        r.classList.toggle('dim', (r.getAttribute('data-s') || '').indexOf(q) < 0);
      });

      var visible = entries.filter(function (e) {
        return !e.hidden;
      });
      visible.forEach(function (entry) {
        markIn(entry, raw.trim());
        // Auto-expand when the evidence would otherwise be invisible: the
        // match sits in the answer body, not the (always visible) question.
        // With 3 or fewer matches, expand everything.
        var qEl = entry.querySelector('.q');
        var qHit = qEl && norm(qEl.textContent).indexOf(q) >= 0;
        if ((visible.length <= 3 || !qHit) && !entry.open) {
          entry.open = true;
          autoOpened.push(entry);
        }
      });

      // A dead end gets a body of its own rather than a one-line count: the
      // query echoed back, and a way out of it. The feedback block below
      // already carries the "reach out" offer.
      count.textContent = shown
        ? fill(search.getAttribute('data-count-match') || '', { shown: shown, total: total })
        : '';
      if (empty) {
        empty.hidden = shown > 0;
        if (!shown && emptyLead)
          emptyLead.textContent = fill(search.getAttribute('data-no-matches') || '', {
            q: raw.trim(),
          });
      }
    }

    // Clicking a topic the query emptied should take you to that topic, not
    // to a section the filter is hiding: drop the query first, then let the
    // anchor jump run. Rows that still have hits keep the filter on.
    if (rail)
      rail.addEventListener('click', function (e) {
        var row = e.target.closest ? e.target.closest('.ritem') : null;
        if (!row || !input.value) return;
        var home = row.classList.contains('rhome');
        if (!home && !(row.classList.contains('rt') && row.classList.contains('dim'))) return;
        if (home) e.preventDefault();
        setQuery('', false);
      });

    input.addEventListener('input', function () {
      applyFilter(input.value);
    });

    // --- ?q= handoff from the FAQ leaves ----------------------------------
    // Leaf pages carry a plain GET search form pointing at the hub; when it
    // lands here, prefill the live filter with the submitted query.
    var handoff = new URLSearchParams(location.search).get('q');
    if (handoff) {
      input.value = handoff;
      applyFilter(handoff);
    }

    // --- rail scroll-spy ----------------------------------------------------
    if (railItems.length && 'IntersectionObserver' in window) {
      var active = null;
      var io = new IntersectionObserver(
        function (obs) {
          obs.forEach(function (o) {
            if (!o.isIntersecting || o.target.id === active) return;
            active = o.target.id;
            railItems.forEach(function (r) {
              r.classList.toggle('on', r === railByGroup[active]);
            });
          });
        },
        { rootMargin: '-15% 0px -70% 0px' }
      );
      groups.forEach(function (g) {
        io.observe(g);
      });
    }
  }

  // /changelog: one filter over three inputs (a query, a type, a month) plus
  // a reveal cap, all reflected in the URL so a filtered view is shareable.
  //
  // Every release is in the DOM from the start. Nothing here truncates; the
  // cap only HIDES, which is what lets a #v0.180 permalink expand the list
  // until its target is on screen instead of landing in a void.
  function initChangelog() {
    var search = document.getElementById('cl-search');
    var input = document.getElementById('cl-q');
    var count = document.getElementById('cl-count');
    var rail = document.getElementById('cl-rail');
    if (!search || !input || !count) return;

    var releases = Array.prototype.slice.call(document.querySelectorAll('article.release'));
    var items = Array.prototype.slice.call(document.querySelectorAll('li.item[data-t]'));
    var months = Array.prototype.slice.call(document.querySelectorAll('.cl-month'));
    var typeRows = rail ? Array.prototype.slice.call(rail.querySelectorAll('.ritem.ct')) : [];
    var monthRows = rail ? Array.prototype.slice.call(rail.querySelectorAll('.ritem.cm')) : [];
    var types = document.getElementById('cl-types');
    var empty = document.getElementById('cl-empty');
    var emptyLead = document.getElementById('cl-empty-lead');
    var emptyClear = document.getElementById('cl-empty-clear');
    var more = document.getElementById('cl-more');
    var moreBtn = document.getElementById('cl-more-btn');
    var moreLabel = document.getElementById('cl-more-label');
    var rest = document.getElementById('cl-rest');
    var total = Number(search.getAttribute('data-total')) || releases.length;
    var PAGE = Number(search.getAttribute('data-page')) || 25;

    var state = { q: '', t: 'all', m: '' };
    var shown = PAGE;

    search.hidden = false;
    if (types) types.hidden = false;

    // Full counts stashed once so a filtered view can rewrite the badges and
    // still restore the real numbers when the filter clears.
    monthRows.concat(typeRows).forEach(function (r) {
      var ct = r.querySelector('.rct');
      if (ct) ct.setAttribute('data-full', ct.textContent);
    });

    // --- per-release permalink ---------------------------------------------
    if (navigator.clipboard) {
      releases.forEach(function (rel) {
        var btn = rel.querySelector('.perma');
        if (!btn) return;
        btn.hidden = false;
        var url = location.origin + location.pathname + '#' + rel.id;
        copyOnClick(
          btn,
          url,
          function () {
            btn.classList.add('done');
          },
          function () {
            btn.classList.remove('done');
          }
        );
      });
    }

    // --- URL state ----------------------------------------------------------
    // A filtered changelog is worth pasting into an issue reply, so q/t/m all
    // live in the query string. replaceState, not pushState: filtering is not
    // navigation, and burying the back button under keystrokes is hostile.
    function writeUrl() {
      var p = new URLSearchParams();
      if (state.q) p.set('q', state.q);
      if (state.t !== 'all') p.set('t', state.t);
      if (state.m) p.set('m', state.m);
      var qs = p.toString();
      history.replaceState(null, '', location.pathname + (qs ? '?' + qs : '') + location.hash);
    }

    function visible() {
      return releases.filter(function (r) {
        return !r.hidden;
      });
    }

    // --- the one filter -----------------------------------------------------
    function apply(opts) {
      var q = norm(state.q.trim());
      var raw = state.q.trim();

      typeRows.forEach(function (r) {
        r.classList.toggle('on', r.getAttribute('data-t') === state.t);
      });
      monthRows.forEach(function (r) {
        r.classList.toggle('on', r.getAttribute('data-m') === state.m);
      });

      // Item rows come and go with the type filter; the query decides which
      // releases survive at all.
      items.forEach(function (li) {
        li.hidden = state.t !== 'all' && li.getAttribute('data-t') !== state.t;
      });

      releases.forEach(function (rel) {
        unmark(rel);
        var hit = !q || (rel.getAttribute('data-s') || '').indexOf(q) >= 0;
        var inMonth = !state.m || rel.getAttribute('data-m') === state.m;
        var hasItems = rel.querySelector('li.item:not([hidden])') != null;
        rel.hidden = !(hit && inMonth && hasItems);
      });

      var matched = visible();

      // The cap applies to what SURVIVED the filter, so a search never has to
      // be paged through to reach its own results.
      if (opts && opts.resetPage) shown = PAGE;
      matched.forEach(function (rel, i) {
        if (i >= shown) rel.hidden = true;
      });

      var live = visible();
      live.forEach(function (rel) {
        markIn(rel, raw);
      });

      // A month eyebrow belongs to the releases between it and the next one.
      months.forEach(function (m) {
        var node = m.nextElementSibling;
        var any = false;
        while (node && !node.classList.contains('cl-month')) {
          if (node.classList.contains('release') && !node.hidden) {
            any = true;
            break;
          }
          node = node.nextElementSibling;
        }
        m.hidden = !any;
      });

      // The rail is how you get out of a filter that went nowhere, so rows
      // dim and report 0 rather than disappearing - the counts double as a
      // map of where the remaining matches are. Same rule as the Help rail.
      monthRows.forEach(function (r) {
        var key = r.getAttribute('data-m');
        var n = releases.filter(function (rel) {
          if (rel.getAttribute('data-m') !== key) return false;
          if (q && (rel.getAttribute('data-s') || '').indexOf(q) < 0) return false;
          return state.t === 'all' || rel.querySelector('li.item[data-t="' + state.t + '"]') != null;
        }).length;
        r.classList.toggle('dim', n === 0);
        var ct = r.querySelector('.rct');
        if (ct) ct.textContent = q || state.t !== 'all' ? String(n) : ct.getAttribute('data-full');
      });

      var totalMatched = matched.length;
      // Counted over everything that MATCHED, not over the 25 currently
      // revealed - a total that grows every time you press "load more" is
      // not a total.
      var changes = 0;
      matched.forEach(function (rel) {
        changes += rel.querySelectorAll('li.item:not([hidden])').length;
      });

      search.classList.toggle('has-q', state.q.length > 0);

      if (!q && state.t === 'all' && !state.m) {
        count.textContent = total + ' releases';
      } else if (!totalMatched) {
        count.textContent = '';
      } else if (q) {
        // A query matches a RELEASE (its title, its changes, its version or
        // its date), so report releases. Reporting "82 changes" here would
        // be counting every change in the 9 releases that matched, which
        // reads as 82 hits.
        count.textContent =
          totalMatched + (totalMatched === 1 ? ' release matches "' : ' releases match "') + raw + '"';
      } else {
        count.textContent =
          changes + (changes === 1 ? ' change in ' : ' changes in ') +
          totalMatched + (totalMatched === 1 ? ' release' : ' releases');
      }

      if (empty) {
        empty.hidden = totalMatched > 0;
        if (!totalMatched && emptyLead)
          emptyLead.textContent = raw
            ? 'No releases match "' + raw + '".'
            : 'No releases match those filters.';
      }

      if (more) {
        var revealed = Math.min(shown, totalMatched);
        var hiddenCount = totalMatched - revealed;
        more.hidden = hiddenCount <= 0;
        var next = Math.min(PAGE, hiddenCount);
        if (moreLabel)
          moreLabel.textContent =
            'Load ' + next + (next === 1 ? ' more release' : ' more releases');
        if (rest) rest.textContent = 'Showing ' + revealed + ' of ' + totalMatched;
      }

      writeUrl();
    }

    // --- reaching a release the cap is hiding --------------------------------
    // #v0.180 can sit at position 48. Raise the cap until its release is on
    // screen, then let the browser do the jump. Without this every permalink
    // already in the wild would land on a page that does not contain it.
    function revealHash() {
      var id = location.hash.slice(1);
      if (!id) return;
      var target = document.getElementById(id);
      if (!target || !target.classList.contains('release')) return;
      // A filter can exclude the target outright; drop the filters rather
      // than page forever through a list it is not in.
      if (state.q || state.t !== 'all' || state.m) {
        state.q = '';
        state.t = 'all';
        state.m = '';
        input.value = '';
      }
      var guard = 0;
      apply({ resetPage: true });
      while (target.hidden && guard < 200) {
        shown += PAGE;
        apply();
        guard++;
      }
      requestAnimationFrame(function () {
        target.scrollIntoView({ block: 'start', behavior: 'smooth' });
      });
    }

    // --- wiring --------------------------------------------------------------
    input.addEventListener('input', function () {
      state.q = input.value;
      apply({ resetPage: true });
    });

    function clearAll(keepFocus) {
      state.q = '';
      state.t = 'all';
      state.m = '';
      input.value = '';
      apply({ resetPage: true });
      if (keepFocus) input.focus();
    }

    var clearBtn = document.getElementById('cl-clear');
    if (clearBtn)
      clearBtn.addEventListener('click', function () {
        state.q = '';
        input.value = '';
        apply({ resetPage: true });
        input.focus();
      });
    if (emptyClear)
      emptyClear.addEventListener('click', function () {
        clearAll(false);
      });

    if (moreBtn)
      moreBtn.addEventListener('click', function () {
        shown += PAGE;
        apply();
      });

    if (rail)
      rail.addEventListener('click', function (e) {
        var row = e.target.closest ? e.target.closest('.ritem') : null;
        if (!row) return;
        if (row.classList.contains('ct')) {
          e.preventDefault();
          state.t = row.getAttribute('data-t') || 'all';
          apply({ resetPage: true });
          return;
        }
        if (row.classList.contains('cm')) {
          // Toggle: clicking the active month clears it. The anchor still
          // resolves without JS, which is why these rows are real links.
          e.preventDefault();
          var key = row.getAttribute('data-m');
          state.m = state.m === key ? '' : key;
          apply({ resetPage: true });
          var head = document.getElementById('m-' + key);
          if (state.m && head) head.scrollIntoView({ block: 'start', behavior: 'smooth' });
        }
      });

    document.addEventListener('keydown', function (e) {
      var tag = document.activeElement && document.activeElement.tagName;
      if (e.key === '/' && tag !== 'INPUT' && tag !== 'TEXTAREA') {
        e.preventDefault();
        input.focus();
      }
      // Escape clears first and only leaves the box on a second press.
      if (e.key === 'Escape' && document.activeElement === input) {
        if (input.value) {
          state.q = '';
          input.value = '';
          apply({ resetPage: true });
        } else input.blur();
      }
    });

    // --- boot ----------------------------------------------------------------
    var params = new URLSearchParams(location.search);
    var q0 = params.get('q');
    var t0 = params.get('t');
    var m0 = params.get('m');
    if (q0) {
      state.q = q0;
      input.value = q0;
    }
    if (t0 && ['new', 'improved', 'fixed'].indexOf(t0) >= 0) state.t = t0;
    if (m0 && /^\d{4}-\d{2}$/.test(m0)) state.m = m0;
    apply({ resetPage: true });

    revealHash();
    window.addEventListener('hashchange', revealHash);
  }

  // /brand: light the "on this page" row for whichever section is in view.
  function initBrandRail() {
    var rows = Array.prototype.slice.call(document.querySelectorAll('#brand-rail .ritem.bs'));
    if (!rows.length || !('IntersectionObserver' in window)) return;
    var byId = {};
    rows.forEach(function (r) {
      var id = (r.getAttribute('href') || '').slice(1);
      if (id) byId[id] = r;
    });
    var io = new IntersectionObserver(
      function (obs) {
        obs.forEach(function (o) {
          if (!o.isIntersecting) return;
          rows.forEach(function (r) {
            r.classList.toggle('on', r === byId[o.target.id]);
          });
        });
      },
      { rootMargin: '-15% 0px -70% 0px' }
    );
    Object.keys(byId).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) io.observe(el);
    });
  }
})();
