// The homepage's copy of Ninja, the ⌘K box, drawn in the washi palette for
// the Ninja tile (LandingPage.tsx). It plays four typed scenes in a loop: a
// title, a plain-words event, two tasks into a list and a command. The box
// paints the real switcher's shape (the field with the mode sign and its X,
// the group headers, the rows with a toned icon tile and the detail under the
// title, the Enter cap on the selected row, the key hints) with --wl-* so it
// inverts with the page. Every word comes from `ninja.*` in the landing
// catalog, so a reader sees the box in their language. Decorative: the box
// is aria-hidden; the tile text beside it carries the meaning.
// The loop runs only while the tile is on screen and stops under reduced
// motion, where the box rests on the event scene, fully typed.
// Spec: ops/design/patterns/145-150.md section 145
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { ComponentType } from 'react';
import type { IconProps } from '@phosphor-icons/react';
import { ArrowsOutSimple, ArrowElbowDownRight, Book, CalendarDot, CheckSquare, FileText, Folder, Gear, KeyReturn, NotePencil, X } from './icons';
import { KEY_OS } from './shortcutMatch';
import { textMatcher } from './textMatch';
import { SectionEyebrow } from './settingsUI';
import { Kbd } from './ui';

/** The icon tile's tint, as the real rows tone their kind. */
type Tone = 'note' | 'event' | 'task' | 'journal' | 'plain';
type Row = { icon: ComponentType<IconProps>; tone: Tone; title: string; detail?: string; chips?: string[]; keys?: string; mark?: boolean };
type Scene = { sign: '' | '+' | '>'; query: string; groups: { header?: string; rows: Row[] }[] };

const TONE: Record<Tone, string> = {
  note: 'bg-[var(--wl-tint-blue)] text-accent dark:text-blue-300',
  event: 'bg-[var(--wl-tint-teal)] text-[var(--wl-teal)]',
  task: 'bg-[var(--wl-tint-green)] text-[var(--wl-emerald)]',
  journal: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
  plain: 'bg-[var(--wl-tint)] text-[var(--wl-sub)]',
};

/** The empty box before the first scene, and between loops. */
const IDLE_MS = 1400;
const TYPE_MS = 70;
/** The typed scene stays long enough to read three rows. */
const HOLD_MS = 2800;
const STILL_SCENE = 1;

function Marked({ text, q }: { text: string; q: string }) {
  const hit = q ? textMatcher(q)(text) : null;
  if (!hit) return <>{text}</>;
  return (
    <>
      {text.slice(0, hit.start)}
      <mark className="rounded-sm bg-[var(--wl-tint-blue)] px-px text-inherit">{text.slice(hit.start, hit.end)}</mark>
      {text.slice(hit.end)}
    </>
  );
}

function BoxRow({ row, q, on }: { row: Row; q: string; on: boolean }) {
  const Glyph = row.icon;
  const mark = row.mark ? q : '';
  return (
    <div className={`relative mx-1.5 flex items-center gap-3 rounded-md px-2 py-1.5 ${on ? 'bg-[var(--wl-tint-blue)] before:absolute before:inset-y-1.5 before:start-0 before:w-[3px] before:rounded-full before:bg-accent dark:before:bg-blue-300' : ''}`}>
      <span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-md ${TONE[row.tone]}`}>
        <Glyph size={16} weight="bold" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-semibold leading-5 text-[var(--wl-ink)]"><Marked text={row.title} q={mark} /></div>
        {(row.detail || row.chips) && (
          <div className="flex min-w-0 items-center gap-1.5 text-xs leading-4 text-[var(--wl-muted)]">
            {row.detail && <span className="truncate"><Marked text={row.detail} q={mark} /></span>}
            {row.chips?.map((c) => (
              <span key={c} className="shrink-0 rounded bg-[var(--wl-tint-blue)] px-1 text-accent dark:text-blue-300">{c}</span>
            ))}
          </div>
        )}
      </div>
      {row.keys && <Kbd>{row.keys}</Kbd>}
      {on && !row.keys && (
        <span className="inline-flex h-6 w-7 items-center justify-center rounded-md border-[1.5px] border-[var(--wl-line)] bg-[var(--wl-card)] text-[var(--wl-sub)]">
          <KeyReturn size={14} weight="bold" />
        </span>
      )}
    </div>
  );
}

function Header({ children }: { children: string }) {
  return <SectionEyebrow className="px-3.5 pb-1 pt-2.5 dark:text-blue-300">{children}</SectionEyebrow>;
}

/** The real footer's rule (QuickSwitcher.tsx, FooterHint): the keys only,
 *  and the word slides out beside them on hover. */
function Hint({ keys, children }: { keys: string[]; children: string }) {
  return (
    <span className="group inline-flex shrink-0 items-center gap-1">
      {keys.map((k) => <Kbd key={k}>{k}</Kbd>)}
      <span className="max-w-0 overflow-hidden whitespace-nowrap [@media(hover:hover)]:group-hover:max-w-[12rem] transition-[max-width] duration-150 ease-out">
        <span className="ps-0.5">{children}</span>
      </span>
    </span>
  );
}

export function NinjaBox() {
  const { t } = useTranslation('landing');
  const root = useRef<HTMLDivElement>(null);
  // The scene on stage (-1 is the empty box) and how many letters are typed.
  const [at, setAt] = useState(-1);
  const [n, setN] = useState(0);

  const mac = KEY_OS === 'mac';
  const scenes: Scene[] = [
    {
      sign: '',
      query: t('ninja.q1'),
      groups: [
        { rows: [
          { icon: NotePencil, tone: 'note', title: t('ninja.q1Row1'), detail: t('ninja.q1Row1Meta'), mark: true },
          { icon: Folder, tone: 'plain', title: t('ninja.q1Row2'), detail: t('ninja.q1Row2Meta'), mark: true },
        ] },
        { header: t('ninja.inText'), rows: [{ icon: NotePencil, tone: 'note', title: t('ninja.q1Row3'), detail: t('ninja.q1Row3Line'), mark: true }] },
        { header: t('ninja.create'), rows: [{ icon: CalendarDot, tone: 'event', title: t('ninja.q1Row4') }] },
      ],
    },
    {
      sign: '+',
      query: t('ninja.q2'),
      groups: [{ header: t('ninja.create'), rows: [
        { icon: CalendarDot, tone: 'event', title: t('ninja.q2Row1'), detail: t('ninja.q2Detail'), chips: [t('ninja.q2ChipDay'), t('ninja.q2ChipTime'), t('ninja.q2ChipAlert')] },
        { icon: FileText, tone: 'note', title: t('ninja.q2Row2'), detail: t('ninja.q2Detail') },
        { icon: CheckSquare, tone: 'task', title: t('ninja.q2Row3'), detail: t('ninja.q2Detail') },
      ] }],
    },
    {
      sign: '+',
      query: t('ninja.q3'),
      groups: [
        { header: t('ninja.addTo'), rows: [{ icon: ArrowElbowDownRight, tone: 'task', title: t('ninja.q3Row1'), detail: t('ninja.q3Row1Meta') }] },
        { header: t('ninja.create'), rows: [{ icon: CalendarDot, tone: 'event', title: t('ninja.q3Row2') }] },
      ],
    },
    {
      sign: '>',
      query: t('ninja.q4'),
      groups: [{ header: t('ninja.commands'), rows: [
        { icon: ArrowsOutSimple, tone: 'note', title: t('ninja.q4Row1'), keys: mac ? '⇧⌘F' : 'Ctrl+Shift+F' },
        { icon: Gear, tone: 'note', title: t('ninja.q4Row2') },
      ] }],
    },
  ];
  const count = scenes.length;

  useEffect(() => {
    const el = root.current;
    if (!el) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setAt(STILL_SCENE);
      setN(Infinity);
      return;
    }
    let timer = 0;
    let i = -1;
    let k = 0;
    let live = false;
    // The whole loop is one timer at a time, so a pause is one clearTimeout
    // and a resume is one more call: the scene and the letters stay put.
    const tick = () => {
      if (i < 0) {
        i = 0;
        k = 0;
        setAt(0);
        setN(0);
        timer = window.setTimeout(tick, TYPE_MS * 4);
        return;
      }
      const len = (el.dataset.q ?? '').split('\u0000')[i]?.length ?? 0;
      if (k < len) {
        k++;
        setN(k);
        timer = window.setTimeout(tick, TYPE_MS);
        return;
      }
      timer = window.setTimeout(() => {
        k = 0;
        i = i + 1 < count ? i + 1 : -1;
        setAt(i);
        setN(0);
        timer = window.setTimeout(tick, i < 0 ? IDLE_MS : TYPE_MS * 4);
      }, HOLD_MS);
    };
    const io = new IntersectionObserver(([e]) => {
      const on = !!e?.isIntersecting;
      if (on && !live) {
        live = true;
        timer = window.setTimeout(tick, i < 0 ? IDLE_MS : TYPE_MS);
      } else if (!on && live) {
        live = false;
        window.clearTimeout(timer);
      }
    });
    io.observe(el);
    return () => {
      io.disconnect();
      window.clearTimeout(timer);
    };
  }, [count]);

  const scene = at >= 0 ? scenes[at] : undefined;
  const typed = scene ? scene.query.slice(0, n) : '';
  const showRows = !!scene && n >= 1;

  return (
    // The queries ride on the element so the timer reads their lengths
    // without re-running on every language change.
    <div ref={root} data-q={scenes.map((s) => s.query).join('\u0000')} aria-hidden="true" className="pn-fx-ninja-box flex flex-col overflow-hidden rounded-xl border-2 border-[var(--wl-edge)] bg-[var(--wl-card)]">
      <div className="flex h-12 items-center gap-2 border-b border-[var(--wl-line)] px-3.5 text-base font-medium text-[var(--wl-ink)]">
        {scene?.sign && <span className="font-mono text-accent dark:text-blue-300">{scene.sign}</span>}
        <span className="whitespace-pre">{typed}</span>
        <span className="pn-fx-ninja-caret h-[1.15em] w-0.5 shrink-0 bg-accent dark:bg-blue-300" />
        {!scene && <span className="truncate text-sm font-normal text-[var(--wl-muted)]">{t('ninja.placeholder')}</span>}
        <span className="ms-auto inline-flex h-8 w-8 shrink-0 items-center justify-center text-[var(--wl-muted)]"><X size={14} weight="bold" /></span>
      </div>
      {/* The list sits absolutely inside a wrapper that only fills the space the
          box has, so a full scene can never add height and make the tile jump. */}
      <div className="relative h-[13rem] lg:h-auto lg:min-h-[13rem] lg:flex-1">
        <div className="absolute inset-0 overflow-hidden pt-1">
        {!scene && (
          <>
            <Header>{t('ninja.recent')}</Header>
            <BoxRow on q="" row={{ icon: NotePencil, tone: 'note', title: t('ninja.recent1'), detail: t('ninja.recent1Meta') }} />
            <BoxRow on={false} q="" row={{ icon: CheckSquare, tone: 'task', title: t('ninja.recent2'), detail: t('ninja.recent2Meta') }} />
            <BoxRow on={false} q="" row={{ icon: Book, tone: 'journal', title: t('ninja.recent3'), detail: t('ninja.recent3Meta') }} />
          </>
        )}
        {scene && showRows && scene.groups.map((g, gi) => (
          <div key={gi} className={gi ? 'mt-1.5 border-t border-[var(--wl-line)] pt-1' : ''}>
            {g.header && <Header>{g.header}</Header>}
            {g.rows.map((r, ri) => <BoxRow key={r.title} row={r} q={typed} on={gi === 0 && ri === 0} />)}
          </div>
        ))}
              </div>
      </div>
      <div className="flex flex-nowrap gap-x-2.5 border-t border-[var(--wl-line)] px-3.5 py-2 text-xs text-[var(--wl-muted)]">
        <Hint keys={['↑', '↓']}>{t('ninja.hintMove')}</Hint>
        <Hint keys={['↵']}>{t('ninja.hintOpen')}</Hint>
        <Hint keys={['Tab']}>{t('ninja.hintActions')}</Hint>
        <Hint keys={[mac ? '⌥↵' : 'Alt+↵']}>{t('ninja.hintTab')}</Hint>
        <Hint keys={['Esc']}>{t('ninja.hintClose')}</Hint>
      </div>
    </div>
  );
}
