/**
 * The language a code block is highlighted as, and the menu that picks it.
 * The choice is the fence's info string (```html), so it is plain Markdown
 * that every other tool reads the same way. A block with no language stays
 * plain on purpose (`defaultLanguage: 'plaintext'` in Editor.tsx).
 *
 * The menu offers no automatic guess: highlight.js detection read an HTML
 * block with inline styles as CSS and a line of prose as Kotlin, so a
 * "detected" row would mislead on exactly the blocks that need it.
 * Spec: ops/docs/design-decisions.md (code blocks name their language)
 */
import i18n from './i18n';
import { isImeComposing } from './imeComposing';
import { textMatcher } from './textMatch';
import { pushEscapeHandler } from './useEscapeToClose';

/** Every grammar in lowlight's `common` set, as the fence the menu writes
 *  and the name it shows. Order is the menu's order after the popular ones. */
const LANGUAGES: { fence: string; label: string; aliases?: string[] }[] = [
  { fence: 'html', label: 'HTML', aliases: ['htm', 'xhtml'] },
  { fence: 'css', label: 'CSS' },
  { fence: 'javascript', label: 'JavaScript', aliases: ['js', 'jsx', 'mjs', 'cjs'] },
  { fence: 'typescript', label: 'TypeScript', aliases: ['ts', 'tsx', 'mts', 'cts'] },
  { fence: 'python', label: 'Python', aliases: ['py', 'gyp', 'ipython'] },
  { fence: 'json', label: 'JSON', aliases: ['jsonc'] },
  { fence: 'sql', label: 'SQL' },
  { fence: 'bash', label: 'Bash', aliases: ['sh', 'zsh'] },
  { fence: 'arduino', label: 'Arduino', aliases: ['ino'] },
  { fence: 'c', label: 'C', aliases: ['h'] },
  { fence: 'cpp', label: 'C++', aliases: ['c++', 'cc', 'cxx', 'hpp'] },
  { fence: 'csharp', label: 'C#', aliases: ['cs', 'c#'] },
  { fence: 'diff', label: 'Diff', aliases: ['patch'] },
  { fence: 'go', label: 'Go', aliases: ['golang'] },
  { fence: 'graphql', label: 'GraphQL', aliases: ['gql'] },
  { fence: 'ini', label: 'INI / TOML', aliases: ['toml'] },
  { fence: 'java', label: 'Java', aliases: ['jsp'] },
  { fence: 'kotlin', label: 'Kotlin', aliases: ['kt', 'kts'] },
  { fence: 'less', label: 'Less' },
  { fence: 'lua', label: 'Lua' },
  { fence: 'makefile', label: 'Makefile', aliases: ['mk', 'mak', 'make'] },
  { fence: 'markdown', label: 'Markdown', aliases: ['md', 'mkdown', 'mkd'] },
  { fence: 'objectivec', label: 'Objective-C', aliases: ['objc', 'mm', 'obj-c'] },
  { fence: 'perl', label: 'Perl', aliases: ['pl', 'pm'] },
  { fence: 'php', label: 'PHP' },
  { fence: 'php-template', label: 'PHP template' },
  { fence: 'python-repl', label: 'Python REPL', aliases: ['pycon'] },
  { fence: 'r', label: 'R' },
  { fence: 'ruby', label: 'Ruby', aliases: ['rb', 'gemspec', 'podspec', 'thor', 'irb'] },
  { fence: 'rust', label: 'Rust', aliases: ['rs'] },
  { fence: 'scss', label: 'SCSS' },
  { fence: 'shell', label: 'Shell session', aliases: ['console', 'shellsession'] },
  { fence: 'swift', label: 'Swift' },
  { fence: 'vbnet', label: 'Visual Basic .NET', aliases: ['vb'] },
  { fence: 'wasm', label: 'WebAssembly' },
  { fence: 'xml', label: 'XML', aliases: ['rss', 'atom', 'xsl', 'plist', 'svg'] },
  { fence: 'yaml', label: 'YAML', aliases: ['yml'] },
];

/** How many rows of LANGUAGES sit above the divider. */
const POPULAR = 8;

/** The name a block's `language` attribute shows as: null for a plain block,
 *  the attribute itself for a fence the table does not know. */
export function codeLanguageLabel(language: string | null | undefined): string | null {
  if (!language || language === 'plaintext' || language === 'text' || language === 'txt') return null;
  const key = language.toLowerCase();
  return LANGUAGES.find((l) => l.fence === key || l.aliases?.includes(key))?.label ?? language;
}

const MENU =
  'pn-code-lang-menu fixed z-[1000] w-56 rounded-md border border-divider bg-surface-2/95 backdrop-blur ' +
  'shadow-xl text-[13px] [@media(hover:none)]:text-[14px] text-pn select-none flex flex-col overflow-hidden';
const ROW = 'flex w-full items-center gap-2 px-3 py-1.5 [@media(hover:none)]:py-2 text-start transition';

/** Phosphor's X, for the clear button. A node view is plain DOM, so the
 *  icon is markup, not a component. */
const CLEAR_ICON =
  '<svg viewBox="0 0 256 256" width="12" height="12" fill="currentColor" aria-hidden="true">' +
  '<path d="M205.66,194.34a8,8,0,0,1-11.32,11.32L128,139.31,61.66,205.66a8,8,0,0,1-11.32-11.32L116.69,128,50.34,61.66A8,8,0,0,1,61.66,50.34L128,116.69l66.34-66.35a8,8,0,0,1,11.32,11.32L139.31,128Z"/></svg>';

let closeOpen: (() => void) | null = null;

/**
 * Opens the language menu under `anchor`. Plain DOM, because the code block
 * is a node view; it hangs off <body>, because the block's pre clips. A
 * search field on top filters through the shared matcher; arrows and Enter
 * pick from it, and Escape clears the search, then closes the menu.
 * `onPick(null)` means plain text.
 */
export function openCodeLanguageMenu(
  anchor: HTMLElement,
  current: string | null | undefined,
  onPick: (fence: string | null) => void,
): void {
  closeOpen?.();
  const currentLabel = codeLanguageLabel(current);

  const menu = document.createElement('div');
  menu.className = MENU;
  menu.setAttribute('role', 'dialog');
  // The search field as ListSearchInput draws it: a clear button inside the
  // field once there is text, and Escape clears before it closes.
  const field = document.createElement('div');
  field.className = 'relative m-1.5 mb-1';
  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = i18n.t('editor:codeBlock.searchLanguages');
  input.setAttribute('aria-label', input.placeholder);
  const clearBtn = document.createElement('button');
  clearBtn.type = 'button';
  clearBtn.innerHTML = CLEAR_ICON;
  clearBtn.setAttribute('aria-label', i18n.t('common:actions.clearSearch'));
  clearBtn.className =
    'absolute end-1 top-1/2 -translate-y-1/2 inline-flex items-center justify-center w-6 h-6 rounded ' +
    'text-pn-muted hover:text-pn hover:bg-pn/5 transition';
  field.append(input, clearBtn);
  const list = document.createElement('div');
  list.className = 'overflow-y-auto max-h-72 pb-1';
  list.setAttribute('role', 'listbox');
  menu.append(field, list);

  type Row = { fence: string | null; label: string };
  const plain: Row = { fence: null, label: i18n.t('editor:codeBlock.plainText') };
  const all: Row[] = [plain, ...LANGUAGES.map((l) => ({ fence: l.fence, label: l.label }))];
  const isCurrent = (row: Row) => row.label === (currentLabel ?? plain.label);
  // With no query the current language is the row the keys start from, so
  // clearing a search puts the highlight back on it.
  const home = Math.max(0, all.findIndex(isCurrent));
  let rows: Row[] = all;
  let active = home;

  const pick = (row: Row | undefined) => {
    if (!row) return;
    close();
    onPick(row.fence);
  };

  const render = () => {
    const q = input.value.trim();
    input.className =
      `w-full h-8 rounded border border-divider bg-surface-1 ps-2 ${q ? 'pe-8' : 'pe-2'} ` +
      'text-[13px] text-pn outline-none focus:border-accent placeholder:text-pn-muted';
    clearBtn.hidden = !input.value;
    list.replaceChildren();
    if (q) {
      const match = textMatcher(q);
      rows = all
        .map((row) => ({ row, m: match(row.label) ?? match(row.fence ?? '') }))
        .filter((x) => x.m)
        .sort((a, b) => b.m!.rank - a.m!.rank)
        .map((x) => x.row);
    } else {
      rows = all;
    }
    active = Math.min(active, Math.max(0, rows.length - 1));
    if (rows.length === 0) {
      const none = document.createElement('div');
      none.className = 'px-3 py-1.5 text-pn-muted';
      none.textContent = i18n.t('common:state.noResults');
      list.appendChild(none);
    }
    rows.forEach((row, i) => {
      if (!q && i === POPULAR + 1) {
        const hr = document.createElement('div');
        hr.className = 'my-1 border-t border-divider';
        list.appendChild(hr);
      }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.setAttribute('role', 'option');
      const selected = isCurrent(row);
      btn.setAttribute('aria-selected', String(selected));
      btn.className = `${ROW} ${i === active ? 'bg-accent-fill text-white' : 'hover:bg-pn/5'}`;
      const name = document.createElement('span');
      name.className = 'flex-1 truncate';
      name.textContent = row.label;
      btn.appendChild(name);
      if (selected) {
        const tick = document.createElement('span');
        tick.textContent = '\u2713';
        tick.className = i === active ? 'text-white' : 'text-accent';
        btn.appendChild(tick);
      }
      btn.addEventListener('mousedown', (e) => e.preventDefault());
      btn.addEventListener('click', () => pick(row));
      list.appendChild(btn);
    });
    list.querySelectorAll('button')[active]?.scrollIntoView({ block: 'nearest' });
  };

  const clear = () => {
    input.value = '';
    active = home;
    render();
  };

  input.addEventListener('input', () => { active = input.value.trim() ? 0 : home; render(); });
  input.addEventListener('keydown', (e) => {
    if (isImeComposing(e)) return;
    if (e.key === 'ArrowDown') { active = Math.min(active + 1, rows.length - 1); render(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { active = Math.max(active - 1, 0); render(); e.preventDefault(); }
    else if (e.key === 'Enter') { pick(rows[active]); e.preventDefault(); }
  });
  // Keeps the focus in the field, so typing goes on and a phone keeps its
  // keyboard.
  clearBtn.addEventListener('mousedown', (e) => e.preventDefault());
  clearBtn.addEventListener('click', clear);

  // On the shared Escape stack, so the app's own Escape (close the note,
  // leave a search) never sees the key: the first press clears the search,
  // the next closes the menu.
  const popEscape = pushEscapeHandler(() => {
    if (input.value) { clear(); return; }
    close();
    anchor.focus();
  });

  const onOutside = (e: Event) => {
    if (!menu.contains(e.target as Node) && !anchor.contains(e.target as Node)) close();
  };
  const onScroll = (e: Event) => { if (!menu.contains(e.target as Node)) close(); };
  function close() {
    menu.remove();
    popEscape();
    document.removeEventListener('pointerdown', onOutside, true);
    window.removeEventListener('scroll', onScroll, true);
    window.removeEventListener('resize', close);
    if (closeOpen === close) closeOpen = null;
  }
  closeOpen = close;

  render();
  document.body.appendChild(menu);

  // Under the label, flipped above it when the screen ends first, and kept
  // inside the window at both sides.
  const r = anchor.getBoundingClientRect();
  const h = menu.offsetHeight;
  const w = menu.offsetWidth;
  const below = r.bottom + 4 + h <= window.innerHeight;
  menu.style.top = `${below ? r.bottom + 4 : Math.max(8, r.top - 4 - h)}px`;
  menu.style.left = `${Math.min(Math.max(8, r.left), window.innerWidth - w - 8)}px`;

  document.addEventListener('pointerdown', onOutside, true);
  window.addEventListener('scroll', onScroll, true);
  window.addEventListener('resize', close);
  input.focus();
}
