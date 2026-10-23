import { useId, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Bandaids, BellSimple, CalendarDots, Circle, Clock, DotsThree, Eyedropper, Flask, Hash, Package, Palette, Pill, Plus, Repeat as RepeatGlyph, Syringe, TextT, Wind, X, type Icon } from '../icons';
import { TEXT_COLORS } from '../editorColors';
import { ColorSwatch } from '../ColorSwatch';
import { MarkTile } from './CustomTrackerGlyph';
import { MonthGrid, firstWeekday } from '../MonthGrid';
import { formatDay, weekdayDate, weekdayLabel } from '../intlFormat';
import { intlLocale } from '../languages';
import { toLocalIso } from '../notesViewUtils';
import { timeLabel } from '../JournalCalendar';
import { weekdayOf, type Repeat } from '../schedule';
import { Switch } from '../Switch';
import { TimeInput } from '../TimeInput';
import { ROW_TITLE, RowTitle, SETTINGS_HELP, SETTINGS_SELECT, SETTINGS_TRACK, settingsChipClass, settingsSegClass } from '../settingsUI';
import { Button, EditRow, IconButton, Popover, TextField } from '../ui';
import { MEDICATION_FORMS, type MedicationDose, type MedicationForm, type MedicationTemplate } from '../trackerTypes';
import { MAX_DOSES, MAIN_DOSE, dosesOf, newDoseId } from '../medicationDoses';
import { MED_DOSAGE_MAX, MED_NAME_MAX, type MedicationPlan } from '../medicationTemplates';
import { askForRemindersOnce } from '../notesView/useReminders';
import { useProGate } from '../ui';
import { ProMark } from '../UpgradeModal';

/**
 * The edit form of one medication in Settings > Trackers > Medication: name
 * and strength, form and color, how it is taken (a schedule or as needed),
 * the repeat, one line per dose with its time and amount, the start and end
 * days, this device's reminder and the supply. Every part is one the app
 * already has. Spec: ops/docs/mood-wellness-tracker.md section 6.7
 */

const NO_DAYS: ReadonlySet<string> = new Set();
/** One glyph per form, as the custom tracker types have. */
const FORM_GLYPHS: Record<MedicationForm, Icon> = {
  tablet: Circle,
  capsule: Pill,
  liquid: Flask,
  injection: Syringe,
  inhaler: Wind,
  patch: Bandaids,
  drops: Eyedropper,
  other: DotsThree,
};
type RepeatKind = 'daily' | 'weekdays' | 'interval';
type DoseDraft = { id: string; time?: string; amount: string };

export type MedicationEdit = {
  name: string;
  dosage: string;
  plan: MedicationPlan;
  refill: number | null;
  remind: boolean;
};

function kindOf(r: Repeat | undefined): RepeatKind {
  if (!r || (r.every === 'day' && r.interval === 1)) return 'daily';
  return r.every === 'week' ? 'weekdays' : 'interval';
}

/** The plural unit of an amount, from the form. */
function unitKey(form: MedicationForm | undefined): string | null {
  return form && form !== 'other' ? `medication.units.${form}` : null;
}

export function MedicationEditor({ initial, remind: initialRemind, supply, runsOut, unlocked, showPro, onUpgrade, onSave, onCancel }: {
  initial: MedicationTemplate;
  /** Whether this medication rings on this device now. */
  remind: boolean;
  /** What is left now, or null without a refill. */
  supply: number | null;
  /** The day the supply runs out, when it can be told. */
  runsOut?: string | null;
  /** Pro or the demo: reminders and the supply are Pro (section 6.7). */
  unlocked: boolean;
  /** The rocket shows for every account without Pro, the demo included. */
  showPro: boolean;
  onUpgrade?: () => void;
  onSave: (edit: MedicationEdit) => void;
  /** Closes an edit. A new medication's form has none: it stays open and
   *  ends on Add, as the custom tracker form ends on Create. */
  onCancel?: () => void;
}) {
  const { t } = useTranslation('trackers');
  // A free account's tap on a Pro control opens the upgrade window; the
  // control stays enabled and carries the rocket.
  const gate = useProGate(unlocked, onUpgrade);
  const [name, setName] = useState(initial.name);
  const [dosage, setDosage] = useState(initial.dosage);
  const [form, setForm] = useState<MedicationForm | ''>(initial.form ?? '');
  const [color, setColor] = useState<string | undefined>(initial.color);
  const [asNeeded, setAsNeeded] = useState(!!initial.asNeeded);
  const [maxPerDay, setMaxPerDay] = useState(initial.maxPerDay ? String(initial.maxPerDay) : '');
  const [kind, setKind] = useState<RepeatKind>(kindOf(initial.repeat));
  const [weekdays, setWeekdays] = useState<number[]>(initial.repeat?.weekdays ?? [weekdayOf(initial.startedAt)]);
  const [interval, setInterval] = useState(String(initial.repeat?.every === 'day' && initial.repeat.interval > 1 ? initial.repeat.interval : 2));
  const [doses, setDoses] = useState<DoseDraft[]>(dosesOf(initial).map((d) => ({ id: d.id, time: d.time, amount: String(d.amount) })));
  const [startedAt, setStartedAt] = useState(initial.startedAt);
  const [endsOn, setEndsOn] = useState<string | undefined>(initial.endsOn);
  const [remind, setRemind] = useState(initialRemind);
  const [refill, setRefill] = useState('');
  const [picking, setPicking] = useState<'start' | 'end' | null>(null);
  const startRef = useRef<HTMLButtonElement>(null);
  const endRef = useRef<HTMLButtonElement>(null);
  const weekStart = firstWeekday(intlLocale());
  const unit = unitKey(form || undefined);
  const timed = doses.some((d) => d.time);
  const remindId = useId();

  const save = () => {
    if (!name.trim()) return;
    const n = Math.max(2, Math.min(99, Number(interval) || 2));
    const repeat: Repeat | undefined = kind === 'daily' ? undefined
      : kind === 'weekdays' ? { every: 'week', interval: 1, weekdays: [...weekdays].sort((a, b) => a - b) }
        : { every: 'day', interval: n };
    const cleanDoses: MedicationDose[] = doses.map((d) => ({
      id: d.id,
      ...(d.time ? { time: d.time } : {}),
      amount: Math.max(0.25, Math.min(99, Number(d.amount.replace(',', '.')) || 1)),
    }));
    const max = Number(maxPerDay);
    const isDefaultDoses = cleanDoses.length === 1 && cleanDoses[0]!.id === MAIN_DOSE && !cleanDoses[0]!.time && cleanDoses[0]!.amount === 1;
    const count = refill.trim() === '' ? null : Number(refill.replace(',', '.'));
    onSave({
      name,
      dosage,
      plan: {
        form: form || undefined,
        color,
        asNeeded: asNeeded || undefined,
        maxPerDay: asNeeded && Number.isInteger(max) && max >= 1 && max <= 24 ? max : undefined,
        repeat: asNeeded ? initial.repeat : repeat,
        doses: asNeeded ? initial.doses : isDefaultDoses ? undefined : cleanDoses,
        startedAt,
        endsOn: endsOn && endsOn >= startedAt ? endsOn : undefined,
      },
      // Free: nothing Pro is saved, whatever the form held.
      refill: unlocked && count !== null && Number.isFinite(count) && count >= 0 ? count : null,
      remind: remind && unlocked,
    });
  };

  const dayButton = (which: 'start' | 'end', day: string | undefined, ref: React.RefObject<HTMLButtonElement | null>) => (
    <>
      <button ref={ref} type="button" onClick={() => setPicking(picking === which ? null : which)} className={`${SETTINGS_SELECT} w-full text-start`}>
        {day ? formatDay(day, 'date') : <span className="text-pn-muted">{t('medication.noEnd')}</span>}
      </button>
      <Popover open={picking === which} anchorRef={ref} onClose={() => setPicking(null)}>
        <MonthGrid
          marked={NO_DAYS}
          selected={day}
          initialMonth={day ?? startedAt}
          onPick={(d) => {
            if (which === 'start') setStartedAt(d);
            else setEndsOn(d < startedAt ? startedAt : d);
            setPicking(null);
          }}
        />
        {which === 'end' && endsOn && (
          <div className="px-3 pb-3">
            <Button icon={<X size={15} aria-hidden="true" />} onClick={() => { setEndsOn(undefined); setPicking(null); }}>{t('medication.noEnd')}</Button>
          </div>
        )}
      </Popover>
    </>
  );

  const addTime = doses.length < MAX_DOSES && (
    <Button icon={<Plus size={15} aria-hidden="true" />} className="whitespace-nowrap" onClick={() => setDoses((cur) => [...cur, { id: newDoseId(), amount: cur[cur.length - 1]?.amount ?? '1' }])}>
      {t('medication.addTime')}
    </Button>
  );
  const doseRows = (
    <div className="flex flex-col gap-1.5">
      {doses.map((d, i) => (
        <div key={d.id} className="flex flex-wrap items-center gap-2">
          <TimeInput
            value={d.time}
            clearable
            label={t('medication.doseTime', { n: i + 1 })}
            onCommit={(time) => setDoses((cur) => cur.map((x) => (x.id === d.id ? { ...x, time: time ?? undefined } : x)))}
            className={`${SETTINGS_SELECT} w-28 text-center tabular-nums`}
          />
          <TextField size="sm" type="number" inputMode="decimal" min={0.25} step={0.25} value={d.amount} onChange={(e) => setDoses((cur) => cur.map((x) => (x.id === d.id ? { ...x, amount: e.target.value } : x)))} className="w-16 text-center" aria-label={t('medication.amount')} />
          <span className="text-xs text-pn-muted truncate">{unit ? t(unit, { count: Number(d.amount) || 1 }) : ''}</span>
          {doses.length > 1 && (
            <IconButton position="start" label={t('medication.removeTime')} onClick={() => setDoses((cur) => cur.filter((x) => x.id !== d.id))}>
              <X size={14} aria-hidden="true" />
            </IconButton>
          )}
          {/* The next time joins the last line rather than taking one of its own. */}
          {i === doses.length - 1 && addTime}
        </div>
      ))}
      <p className={SETTINGS_HELP}>{t('medication.timesHelp')}</p>
    </div>
  );

  // Hairlines part what it is, when it is taken, and the supply, where a
  // boxed schedule used to stand.
  const part = 'flex flex-col gap-3 pt-4 border-t border-divider';

  return (
    // On a wide pane each label sits beside its control, so no row spends a
    // line on its label alone; a phone keeps the label above.
    <div className="@container flex flex-col gap-4">
      <div className="flex flex-col gap-3">
        <FieldPair
          cols="grid-cols-[minmax(0,1fr)_8rem]"
          grow
          first={{
            icon: TextT,
            label: t('config.nameLabel'),
            // The row's own tile, live: the form's glyph in the picked color.
            children: (
              <div className="flex items-center gap-2">
                <MarkTile color={color}>
                  <MedicationGlyph form={form || undefined} size={18} style={color ? { color } : undefined} className={color ? 'shrink-0' : 'shrink-0 text-pn-muted'} />
                </MarkTile>
                <TextField size="sm" aria-label={t('config.nameLabel')} value={name} maxLength={MED_NAME_MAX} onChange={(e) => setName(e.target.value)} placeholder={t('medication.namePlaceholder')} className="w-full" autoFocus />
              </div>
            ),
          }}
          second={{
            icon: Pill,
            label: t('medication.strength'),
            children: <TextField size="sm" aria-label={t('medication.strength')} value={dosage} maxLength={MED_DOSAGE_MAX} onChange={(e) => setDosage(e.target.value)} placeholder={t('medication.strengthPlaceholder')} className="w-full @lg:w-32" />,
          }}
        />
        <Field icon={Package} label={t('medication.form')} top>
          {/* The chips of a custom tracker's type, one per form, each with
              its glyph; a tap on the chosen one clears it. */}
          <div role="group" aria-label={t('medication.form')} className="flex flex-wrap gap-1.5">
            {MEDICATION_FORMS.map((f) => (
              <button key={f} type="button" aria-pressed={form === f} onClick={() => setForm(form === f ? '' : f)} className={`${settingsChipClass(form === f)} gap-1.5 whitespace-nowrap`}>
                <MedicationGlyph form={f} size={12} className="shrink-0" />
                {t(`medication.forms.${f}`)}
              </button>
            ))}
          </div>
        </Field>
        <Field icon={Palette} label={t('config.colorLabel')}>
          {/* The round swatches of the custom tracker form, with a "no
              color" swatch first: a medication needs no color. */}
          <div className="flex flex-wrap items-center gap-1.5 min-h-9">
            <ColorSwatch label={t('shell:noteOptionsMenu.colorNone')} none selected={!color} labelPosition="above-start" onClick={() => setColor(undefined)} />
            {TEXT_COLORS.map(({ name: colorName, value: c }) => (
              <ColorSwatch key={c} label={t(`editor:color.names.${colorName.toLowerCase()}`)} background={c} selected={color === c} onClick={() => setColor(c)} />
            ))}
          </div>
        </Field>
      </div>

      <div className={part}>
        <Field icon={RepeatGlyph} label={t('medication.howTaken')}>
          {/* Beside its label a track hugs its options, as two or three short
              words need no more; stacked, it fills the line in equal parts. */}
          <div role="group" aria-label={t('medication.howTaken')} className={`${SETTINGS_TRACK} ${TRACK_FIT}`}>
            <button type="button" aria-pressed={!asNeeded} onClick={() => setAsNeeded(false)} className={`${settingsSegClass(!asNeeded, true)} ${SEG_FIT}`}>{t('medication.onSchedule')}</button>
            <button type="button" aria-pressed={asNeeded} onClick={() => setAsNeeded(true)} className={`${settingsSegClass(asNeeded, true)} ${SEG_FIT}`}>{t('medication.asNeeded')}</button>
          </div>
        </Field>
        {asNeeded ? (
          <Field icon={Hash} label={t('medication.maxPerDay')} top>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
              <TextField size="sm" type="number" inputMode="numeric" min={1} max={24} aria-label={t('medication.maxPerDay')} value={maxPerDay} onChange={(e) => setMaxPerDay(e.target.value)} className="w-20" />
              <p className={`${SETTINGS_HELP} min-w-0 flex-1 basis-48`}>{t('medication.maxPerDayHelp')}</p>
            </div>
          </Field>
        ) : (
          <>
            <Field icon={CalendarDots} label={t('medication.repeat')} top>
              <div className="flex flex-col gap-2">
                <div role="group" aria-label={t('medication.repeat')} className={`${SETTINGS_TRACK} ${TRACK_FIT}`}>
                  {(['daily', 'weekdays', 'interval'] as const).map((k) => (
                    <button key={k} type="button" aria-pressed={kind === k} onClick={() => setKind(k)} className={`${settingsSegClass(kind === k, true)} ${SEG_FIT}`}>
                      {t(`medication.repeatKinds.${k}`)}
                    </button>
                  ))}
                </div>
                {kind === 'weekdays' && (
                  <div role="group" aria-label={t('medication.repeatKinds.weekdays')} className="flex gap-1">
                    {Array.from({ length: 7 }, (_, i) => (weekStart + i) % 7).map((w) => {
                      const on = weekdays.includes(w);
                      return (
                        <button
                          key={w}
                          type="button"
                          aria-pressed={on}
                          aria-label={weekdayLabel(weekdayDate(w), 'long')}
                          onClick={() => setWeekdays((cur) => (on ? (cur.length > 1 ? cur.filter((x) => x !== w) : cur) : [...cur, w]))}
                          className={`w-8 h-8 rounded-full text-xs font-semibold transition ${on ? 'bg-accent-fill text-white' : 'bg-surface-1 text-pn-muted hover:text-pn'}`}
                        >
                          {weekdayLabel(weekdayDate(w), 'narrow')}
                        </button>
                      );
                    })}
                  </div>
                )}
                {kind === 'interval' && (
                  <label className="flex items-center gap-2 text-[13px] text-pn">
                    {t('medication.every')}
                    <TextField size="sm" type="number" inputMode="numeric" min={2} max={99} value={interval} onChange={(e) => setInterval(e.target.value)} className="w-16 text-center" aria-label={t('medication.every')} />
                    {t('medication.days')}
                  </label>
                )}
              </div>
            </Field>
            <Field icon={Clock} label={t('medication.timesAndAmount')} top>{doseRows}</Field>
          </>
        )}
        <FieldPair
          cols="grid-cols-2"
          first={{ icon: CalendarDots, label: t('medication.started'), children: <div className="w-full @lg:w-40">{dayButton('start', startedAt, startRef)}</div> }}
          second={{ icon: CalendarDots, label: t('medication.ends'), children: <div className="w-full @lg:w-40">{dayButton('end', endsOn, endRef)}</div> }}
        />
        {!asNeeded && (
          <Field icon={BellSimple} label={t('medication.remind')} htmlFor={remindId} pro={showPro}>
            {/* The switch sits in the control column; what it does is its own label. */}
            <Switch
              id={remindId}
              className="w-fit max-w-full"
              labelClassName={SETTINGS_HELP}
              label={timed ? t('medication.remindHelp') : t('medication.remindNeedsTime')}
              checked={remind && unlocked}
              onChange={gate((on: boolean) => { setRemind(on); if (on) askForRemindersOnce(); })}
            />
          </Field>
        )}
      </div>

      {/* Wide, the actions end the supply's line. Narrow, they would float
          under its help as if they belonged to it, so they take a footer line. */}
      <div className="flex flex-col gap-3 pt-4 border-t border-divider @lg:flex-row @lg:items-center @lg:gap-4">
        <div className="min-w-0 flex-1">
          <Field icon={Package} label={t('medication.supply')} top pro={showPro}>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
              {unlocked ? (
                <TextField size="sm" type="number" inputMode="decimal" min={0} value={refill} onChange={(e) => setRefill(e.target.value)} placeholder={t('medication.refillPlaceholder')} aria-label={t('medication.refill')} className="w-36" />
              ) : (
                // Free: the Pro door in place of the count, as every Pro control.
                <Button icon={<Package size={15} aria-hidden="true" />} pro onClick={onUpgrade}>{t('medication.trackSupply')}</Button>
              )}
              <p className={`${SETTINGS_HELP} min-w-0 flex-1 basis-40`}>
                {supply === null || !unlocked
                  ? t('medication.supplyHelp')
                  : runsOut
                    ? t('medication.supplyRunsOut', { count: supply, date: formatDay(runsOut, 'date') })
                    : t('medication.supplyLeft', { count: supply })}
              </p>
            </div>
          </Field>
        </div>
        {/* Narrow, the footer's buttons share its full width. */}
        <div className="flex pt-3 border-t border-divider @lg:shrink-0 @lg:pt-0 @lg:border-0">
          {onCancel ? (
            <EditRow onSave={save} onCancel={onCancel} canSave={!!name.trim()} className="w-full [&>*]:flex-1 @lg:w-auto @lg:[&>*]:flex-none" />
          ) : (
            <Button action="add" onClick={save} disabled={!name.trim()} className="w-full @lg:w-auto" />
          )}
        </div>
      </div>
    </div>
  );
}

const TRACK_FIT = 'w-full @lg:w-fit';
const SEG_FIT = 'leading-tight @lg:flex-none @lg:whitespace-nowrap';

const LABEL_COL = '@lg:w-40 @lg:shrink-0';

/** One labeled row: the label above its control on a narrow pane, beside it
 *  on a wide one. `top` holds the label to the first line of a tall control. */
function Field({ icon: Glyph, label, top = false, htmlFor, pro = false, children }: { icon: Icon; label: string; top?: boolean; htmlFor?: string; pro?: boolean; children: ReactNode }) {
  return (
    <div className={`flex flex-col gap-1.5 @lg:flex-row @lg:gap-4 ${top ? '@lg:items-start' : '@lg:items-center'}`}>
      <div className={`${LABEL_COL} ${top ? '@lg:min-h-9 @lg:flex @lg:items-center' : ''}`}>
        {/* A Pro field carries the mark after its label, as a Pro heading does. */}
        <span className="inline-flex flex-wrap items-center gap-x-1.5">
          {htmlFor ? (
            <label htmlFor={htmlFor} className={ROW_TITLE}>
              <Glyph size={14} className="text-accent shrink-0" aria-hidden="true" />
              {label}
            </label>
          ) : (
            <RowTitle icon={Glyph}>{label}</RowTitle>
          )}
          {pro && <ProMark />}
        </span>
      </div>
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}

type PairSide = { icon: Icon; label: string; children: ReactNode };

/** Two fields on one row. Wide: the first label in the label column, the
 *  second label inline after the first control. Narrow: side by side in
 *  `cols`, each label above its control. `grow` lets the first control take
 *  the room the second leaves. */
function FieldPair({ cols, grow = false, first, second }: { cols: string; grow?: boolean; first: PairSide; second: PairSide }) {
  return (
    <div className={`grid ${cols} gap-2 @lg:flex @lg:items-center @lg:gap-4`}>
      {/* Wide, this wrapper dissolves, so its label and control join the row. */}
      <div className="flex flex-col gap-1.5 min-w-0 @lg:contents">
        <div className={LABEL_COL}><RowTitle icon={first.icon}>{first.label}</RowTitle></div>
        <div className={`min-w-0 ${grow ? '@lg:flex-1' : ''}`}>{first.children}</div>
      </div>
      <div className="flex flex-col gap-1.5 min-w-0 @lg:flex-row @lg:items-center @lg:gap-3 @lg:shrink-0">
        <RowTitle icon={second.icon}>{second.label}</RowTitle>
        {second.children}
      </div>
    </div>
  );
}

/** A medication's glyph: the one of its form, or a pill without one. */
export function MedicationGlyph({ form, size = 12, className, style }: { form?: MedicationForm; size?: number; className?: string; style?: React.CSSProperties }) {
  const Glyph = form ? FORM_GLYPHS[form] : Pill;
  return <Glyph size={size} className={className} style={style} aria-hidden="true" />;
}

/** One line for a medication's row: the amount and how it is taken
 *  ("1 tablet, every day at 08:00", "As needed, at most 3 a day"). */
export function describeMedication(med: MedicationTemplate, t: (key: string, o?: Record<string, unknown>) => string): string {
  if (med.asNeeded) {
    return [t('medication.asNeeded'), med.maxPerDay ? t('medication.summary.atMost', { count: med.maxPerDay }) : ''].filter(Boolean).join(', ');
  }
  const doses = dosesOf(med);
  const unit = unitKey(med.form);
  const amount = doses[0]!.amount;
  const same = doses.every((d) => d.amount === amount);
  const r = med.repeat;
  const when = !r || (r.every === 'day' && r.interval === 1) ? t('medication.summary.everyDay')
    : r.every === 'week' ? t('medication.summary.onDays', { days: (r.weekdays ?? [weekdayOf(med.startedAt)]).map((w) => weekdayLabel(weekdayDate(w), 'short')).join(', ') })
      : t('medication.summary.everyN', { count: r.interval });
  // The times in the clock the person set (8 AM or 08:00).
  const today = toLocalIso(new Date());
  const times = doses.filter((d) => d.time).map((d) => d.time!).sort().map((time) => timeLabel(today, time));
  const amountText = same && unit ? `${amount} ${t(unit, { count: amount })}` : '';
  const parts = [
    // A strength already written as the amount ("1 tablet") is not repeated.
    amountText && amountText.toLowerCase() !== med.dosage.trim().toLowerCase() ? amountText : !same || !unit ? (doses.length > 1 ? t('medication.summary.doses', { count: doses.length }) : '') : '',
    times.length ? `${when} ${t('medication.summary.at', { times: times.join(', ') })}` : when,
  ].filter(Boolean);
  return parts.join(', ');
}
