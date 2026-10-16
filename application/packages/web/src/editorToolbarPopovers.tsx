import type { ReactNode, RefObject } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import type { Editor as TipTapEditor } from '@tiptap/react';
import { Trash as TrashIcon, type Icon } from './icons';
import { HoverLabel } from './HoverLabel';
import { ColorSwatch } from './ColorSwatch';
import { TEXT_COLORS, HIGHLIGHT_COLORS, FONT_FAMILIES, FONT_SIZES } from './editorColors';
import { CALLOUT_TYPES } from './calloutTypes';
import { writeColorPref } from './editorPrefs';
import type { ALIGNMENT_VALUES } from './editorExtensions';
import type { PopoverPos } from './usePopoverPosition';
import { TB_BTN_ACTIVE, TB_BTN_BASE, TB_BTN_REST, TB_ICON, normalizeCssColor, runOnCaretWord, smartToggleHeading } from './editorToolbarParts';

// The panels the toolbar's popovers open. Each is portaled to document.body
// so it escapes the toolbar's overflow clipping, and placed by the toolbar's
// useToolbarPopover; the toolbar decides when one is open.

type Alignment = (typeof ALIGNMENT_VALUES)[number];

function ToolbarPanel({ popoverRef, pos, className, children, ...aria }: {
  popoverRef: RefObject<HTMLDivElement | null>;
  pos: PopoverPos | null;
  className: string;
  children: ReactNode;
  role?: string;
  'aria-label'?: string;
}) {
  return createPortal(
    <div
      ref={popoverRef}
      {...aria}
      className={`fixed z-50 ${className}`}
      style={{
        top: pos?.top ?? 0,
        left: pos?.left ?? 0,
        visibility: pos ? 'visible' : 'hidden',
      }}
    >
      {children}
    </div>,
    document.body,
  );
}

export function HeadingPanel({ popoverRef, pos, onClose, editor, activeHeading }: {
  popoverRef: RefObject<HTMLDivElement | null>;
  pos: PopoverPos | null;
  onClose: () => void;
  editor: TipTapEditor;
  activeHeading: number;
}) {
  const { t } = useTranslation('editor');
  return (
    <ToolbarPanel popoverRef={popoverRef} pos={pos} className="bg-surface-1 border border-divider rounded-lg shadow-lg py-1 w-40">
      <button
        type="button"
        onPointerDown={(e) => {
          e.preventDefault();
          editor.chain().focus().setParagraph().run();
          onClose();
        }}
        className={`w-full text-start px-3 py-1.5 text-sm [@media(hover:hover)]:hover:bg-pn/5 active:bg-pn/5 transition ${
          activeHeading === 0 ? 'text-accent' : 'text-pn-soft'
        }`}
      >
        {t('heading.normalText')}
      </button>
      {([1, 2, 3, 4, 5, 6] as const).map((level) => (
        <button
          key={level}
          type="button"
          onPointerDown={(e) => {
            e.preventDefault();
            smartToggleHeading(editor, level);
            onClose();
          }}
          className={`w-full text-start px-3 py-1.5 text-sm [@media(hover:hover)]:hover:bg-pn/5 active:bg-pn/5 transition ${
            activeHeading === level ? 'text-accent' : 'text-pn-soft'
          }`}
        >
          {t('heading.level', { level })}
        </button>
      ))}
    </ToolbarPanel>
  );
}

export function TextColorPanel({ popoverRef, pos, onClose, editor, currentColor, setTextMemory }: {
  popoverRef: RefObject<HTMLDivElement | null>;
  pos: PopoverPos | null;
  onClose: () => void;
  editor: TipTapEditor;
  currentColor: string | undefined;
  setTextMemory: (name: string) => void;
}) {
  const { t } = useTranslation('editor');
  return (
    <ToolbarPanel popoverRef={popoverRef} pos={pos} className="bg-surface-1 border border-divider rounded-lg shadow-lg p-2 w-[168px]">
      <div className="grid grid-cols-5 gap-1.5">
        {TEXT_COLORS.map((c) => (
          <ColorSwatch
            key={c.value}
            label={t(`color.names.${c.name.toLowerCase()}`)}
            background={c.value}
            selected={currentColor?.toLowerCase() === c.value.toLowerCase()}
            onPointerDown={(e) => {
              e.preventDefault();
              runOnCaretWord(editor, (chain) => chain.setColor(c.value));
              // Every pick trains the button. Remove does not: it is
              // not a choice of colour.
              setTextMemory(c.name.toLowerCase());
              writeColorPref('text', c.name.toLowerCase());
              onClose();
            }}
          />
        ))}
        <ColorSwatch
          label={t('color.remove')}
          none
          selected={!currentColor}
          onPointerDown={(e) => {
            e.preventDefault();
            runOnCaretWord(editor, (chain) => chain.unsetColor());
            onClose();
          }}
        />
      </div>
    </ToolbarPanel>
  );
}

export function CalloutPanel({ popoverRef, pos, onClose, editor, isActive }: {
  popoverRef: RefObject<HTMLDivElement | null>;
  pos: PopoverPos | null;
  onClose: () => void;
  editor: TipTapEditor;
  isActive: (name: string) => boolean;
}) {
  const { t } = useTranslation('editor');
  return (
    <ToolbarPanel popoverRef={popoverRef} pos={pos} className="bg-surface-1 border border-divider rounded-lg shadow-lg p-2 w-[240px] max-h-[calc(100dvh-16px)] overflow-y-auto" role="menu" aria-label={t('callout.pickerLabel')}>
      <div className="grid grid-cols-3 gap-1">
        {CALLOUT_TYPES.map((c) => {
          const CalloutIcon = c.icon;
          return (
            <button
              key={c.type}
              type="button"
              onPointerDown={(e) => {
                e.preventDefault();
                onClose();
                if (editor.isActive('callout')) {
                  editor.chain().focus().setCalloutType(c.type).run();
                } else {
                  editor.chain().focus().insertCallout(c.type).run();
                }
              }}
              className="relative flex flex-col items-center gap-1 rounded-md px-1 py-2 text-pn-soft [@media(hover:hover)]:hover:bg-pn/5 transition"
            >
              <CalloutIcon size={18} weight="bold" color={c.color || undefined} />
              <span className="max-w-full text-center text-[11px] leading-tight hyphens-auto break-words">{t(`callout.types.${c.type}`)}</span>
            </button>
          );
        })}
      </div>
      {/* When the cursor is inside a callout, offer an explicit way to remove
          it - the picker is where users look to change or undo a callout, and
          this covers touch platforms with no Backspace-at-start gesture. */}
      {isActive('callout') && (
        <div className="mt-1.5 pt-1.5 border-t border-divider">
          <button
            type="button"
            onPointerDown={(e) => {
              e.preventDefault();
              onClose();
              editor.chain().focus().removeCallout().run();
            }}
            className="flex w-full items-center justify-center gap-2 rounded-md px-2 py-2 text-[13px] text-pn-soft [@media(hover:hover)]:hover:bg-pn/5 transition"
          >
            <TrashIcon size={16} className="text-danger" />
            <span>{t('callout.remove')}</span>
          </button>
        </div>
      )}
    </ToolbarPanel>
  );
}

export function FontPanel({ popoverRef, pos, onClose, editor, currentFontFamily, currentFontSize }: {
  popoverRef: RefObject<HTMLDivElement | null>;
  pos: PopoverPos | null;
  onClose: () => void;
  editor: TipTapEditor;
  currentFontFamily: string | undefined;
  currentFontSize: string | undefined;
}) {
  const { t } = useTranslation('editor');
  return (
    <ToolbarPanel popoverRef={popoverRef} pos={pos} className="bg-surface-1 border border-divider rounded-lg shadow-lg py-1 w-44">
      {FONT_FAMILIES.map((f) => {
        const selected = currentFontFamily === f.value;
        return (
          <button
            key={f.value}
            type="button"
            aria-pressed={selected}
            onPointerDown={(e) => {
              e.preventDefault();
              if (selected) editor.chain().focus().unsetFontFamily().run();
              else editor.chain().focus().setFontFamily(f.value).run();
              onClose();
            }}
            className={`w-full flex items-center justify-between text-start px-3 py-1.5 text-sm [@media(hover:hover)]:hover:bg-pn/5 active:bg-pn/5 transition ${
              selected ? 'text-accent' : 'text-pn-soft'
            }`}
            style={{ fontFamily: f.value }}
          >
            {t(`font.families.${f.name.toLowerCase()}`)}
          </button>
        );
      })}
      <div className="my-1 h-px bg-divider" aria-hidden="true" />
      {FONT_SIZES.map((s) => {
        const selected = currentFontSize === s.value;
        return (
          <button
            key={s.value}
            type="button"
            aria-pressed={selected}
            onPointerDown={(e) => {
              e.preventDefault();
              if (selected) editor.chain().focus().unsetFontSize().run();
              else editor.chain().focus().setFontSize(s.value).run();
              onClose();
            }}
            className={`w-full flex items-center justify-between text-start px-3 py-1.5 [@media(hover:hover)]:hover:bg-pn/5 active:bg-pn/5 transition ${
              selected ? 'text-accent' : 'text-pn-soft'
            }`}
            style={{ fontSize: `calc(0.875rem * ${parseFloat(s.value)})` }}
          >
            {t(`font.sizes.${s.name.toLowerCase()}`)}
          </button>
        );
      })}
      {/* One reset for both axes - the two "unset" paths above only clear
          the entry you re-picked, and a run can carry either or both. */}
      {(currentFontFamily || currentFontSize) && (
        <>
          <div className="my-1 h-px bg-divider" aria-hidden="true" />
          <button
            type="button"
            onPointerDown={(e) => {
              e.preventDefault();
              editor.chain().focus().unsetFontFamily().unsetFontSize().run();
              onClose();
            }}
            className="w-full text-start px-3 py-1.5 text-sm text-pn-soft [@media(hover:hover)]:hover:bg-pn/5 active:bg-pn/5 transition"
          >
            {t('font.reset')}
          </button>
        </>
      )}
    </ToolbarPanel>
  );
}

export function AlignPanel({ popoverRef, pos, onClose, editor, alignments, currentAlign }: {
  popoverRef: RefObject<HTMLDivElement | null>;
  pos: PopoverPos | null;
  onClose: () => void;
  editor: TipTapEditor;
  alignments: { value: Alignment; Icon: Icon }[];
  currentAlign: Alignment | null;
}) {
  const { t } = useTranslation('editor');
  return (
    <ToolbarPanel popoverRef={popoverRef} pos={pos} className="bg-surface-1 border border-divider rounded-lg shadow-lg p-1 flex items-center gap-0.5">
      {alignments.map(({ value, Icon }) => (
        <HoverLabel key={value} label={t(`align.${value}`)} position="above">
          <button
            type="button"
            aria-label={t(`align.${value}`)}
            aria-pressed={currentAlign === value}
            onPointerDown={(e) => {
              e.preventDefault();
              // 'left' unsets rather than sets - it is the unstyled default,
              // and storing it would only add an HTML blob to the markdown
              // source. Re-picking the active alignment also clears it, so
              // the block goes back to inheriting.
              if (value === 'left' || currentAlign === value) {
                editor.chain().focus().unsetTextAlign().run();
              } else {
                editor.chain().focus().setTextAlign(value).run();
              }
              onClose();
            }}
            className={`${TB_BTN_BASE} ${currentAlign === value ? TB_BTN_ACTIVE : TB_BTN_REST}`}
          >
            <Icon size={TB_ICON} />
          </button>
        </HoverLabel>
      ))}
    </ToolbarPanel>
  );
}

export function HighlightPanel({ popoverRef, pos, onClose, editor, highlightOn, currentHighlight, setHighlightMemory }: {
  popoverRef: RefObject<HTMLDivElement | null>;
  pos: PopoverPos | null;
  onClose: () => void;
  editor: TipTapEditor;
  highlightOn: boolean;
  currentHighlight: string | undefined;
  setHighlightMemory: (name: string) => void;
}) {
  const { t } = useTranslation('editor');
  return (
    <ToolbarPanel popoverRef={popoverRef} pos={pos} className="bg-surface-1 border border-divider rounded-lg shadow-lg p-2 w-[168px]">
      <div className="grid grid-cols-5 gap-1.5">
        {HIGHLIGHT_COLORS.map((c) => {
          // A swatch is selected only when the run is actually
          // highlighted: without that check the palette's first entry
          // (color === null) would read as selected on unhighlighted text.
          const selected = highlightOn && normalizeCssColor(currentHighlight) === normalizeCssColor(c.value ?? undefined);
          return (
            <ColorSwatch
              key={c.name}
              label={t(`color.names.${c.name.toLowerCase()}`)}
              // The wash is translucent by design, so the swatch shows
              // it over the popover's own surface - which is the same
              // light-or-dark ground it will sit on in the note. The
              // default entry has no stored color and takes its themed
              // pair from the .pn-hl-default class instead.
              background={c.value ?? undefined}
              className={c.value ? '' : 'pn-hl-default'}
              selected={selected}
              onPointerDown={(e) => {
                e.preventDefault();
                // setHighlight MERGES attributes onto an active mark, so
                // the default entry has to clear the old color rather
                // than omit one: picking Yellow over a green run would
                // otherwise leave it green.
                runOnCaretWord(editor, (chain) => (c.value
                  ? chain.setHighlight({ color: c.value })
                  : chain.unsetHighlight().setHighlight()));
                setHighlightMemory(c.name.toLowerCase());
                writeColorPref('highlight', c.name.toLowerCase());
                onClose();
              }}
            />
          );
        })}
        <ColorSwatch
          label={t('color.removeHighlight')}
          none
          selected={!highlightOn}
          onPointerDown={(e) => {
            e.preventDefault();
            runOnCaretWord(editor, (chain) => chain.unsetHighlight());
            onClose();
          }}
        />
      </div>
    </ToolbarPanel>
  );
}
