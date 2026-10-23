import { useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from '../db';
import { BellSimple, Check } from '../icons';
import { UpdateToast } from '../UpdateToast';
import { formatInstant, toLocalIso } from '../intlFormat';
import { contactBirthday, parseContactBody } from '../contactBody';
import { entryDayOf } from '../notesViewUtils';
import { scheduleOf, type Schedule } from '../schedule';
import { isDemoMode } from '../demo';
import { CHECK_IN_REMINDER_ID, checkInReminderItem } from '../checkIn';
import { MEDICATION_REMINDER_PREFIX } from '../medicationReminders';
import { mayWriteUnstamped } from '../liveSignIn';
import {
  markUnseen,
  planAlerts,
  plannedThrough,
  readSnoozes,
  reminderText,
  snooze,
  type PlannedAlert,
  type ReminderItem,
} from '../reminders';

/**
 * The reminders of this device, driven from the shell: the items with alerts
 * (and every birthday, at the Settings default), the plan, the OS schedule on
 * a phone, the timer in an open app, the in-app toast with Open and Snooze,
 * and the bell on the Calendar row. The plan re-runs on every change to the
 * items, on foreground and on launch; Pro locked (a refund) plans nothing,
 * which cancels everything this device scheduled. The daily check-in
 * reminder is one more item of the same plan, free, with no private text.
 * Spec: ops/docs/archive/calendar-pillar-spec.md (step 7, section 8);
 * ops/issues/0439.md (Reminder plan)
 */

const NATIVE_MOBILE = __PN_BUILD_PLATFORM__ === 'ios' || __PN_BUILD_PLATFORM__ === 'android';
const NATIVE = __PN_BUILD_PLATFORM__ !== '';
const SCHEDULED_KEY = 'privacynotes.reminderScheduled';
const firedKey = () => (isDemoMode() ? 'privacynotes.demo.reminderFired' : 'privacynotes.reminderFired');
/** A timer longer than this overflows; the next check runs before it anyway. */
const MAX_TIMER_MS = 6 * 60 * 60_000;
/** How often an open app looks for a time zone change. */
const ZONE_CHECK_MS = 60_000;

/** The zone a plan's instants are counted in: its name, and its offset now. */
function zoneNow(): string {
  return `${Intl.DateTimeFormat().resolvedOptions().timeZone}|${new Date().getTimezoneOffset()}`;
}

type Platform = 'mobile' | 'desktop' | 'browser';
export const REMINDER_PLATFORM: Platform = NATIVE_MOBILE ? 'mobile' : NATIVE ? 'desktop' : 'browser';

// ── "Scheduled through", for Settings › Calendar ──────────────────────

const statusListeners = new Set<() => void>();
let throughDay: string | null = null;
function setThrough(day: string | null) {
  if (day === throughDay) return;
  throughDay = day;
  statusListeners.forEach((l) => l());
}
/** The day the plan reaches when it is full, or null when every alert fits. */
export function useRemindersThrough(): string | null {
  return useSyncExternalStore((l) => { statusListeners.add(l); return () => { statusListeners.delete(l); }; }, () => throughDay);
}

// ── Fired keys, so a reload inside the grace minute does not ring twice ─

/** When each key last fired. A key fired before its planned instant (a
 *  snooze moved it later) fires again. */
function firedAt(): Record<string, number> {
  try {
    const v = JSON.parse(localStorage.getItem(firedKey()) ?? '{}') as Record<string, number>;
    const cut = Date.now() - 2 * 86_400_000;
    return Object.fromEntries(Object.entries(v).filter(([, t]) => t > cut));
  } catch {
    return {};
  }
}
function markFired(key: string) {
  try {
    const v = JSON.parse(localStorage.getItem(firedKey()) ?? '{}') as Record<string, number>;
    const cut = Date.now() - 2 * 86_400_000;
    const kept = Object.fromEntries(Object.entries(v).filter(([, t]) => t > cut));
    localStorage.setItem(firedKey(), JSON.stringify({ ...kept, [key]: Date.now() }));
  } catch {
    // Storage refused: this page remembers it below.
  }
}

// ── The OS side ───────────────────────────────────────────────────────

type Plugin = typeof import('@tauri-apps/plugin-notification');
let pluginLoad: Promise<Plugin> | null = null;
function plugin(): Promise<Plugin> {
  pluginLoad ??= import('@tauri-apps/plugin-notification');
  return pluginLoad;
}

// ── The permission ────────────────────────────────────────────────────
// A launch, a sync and a re-plan only read it. The OS asks only from a tap:
// the first alert set on this device, or a Turn on or Allow button. iOS shows
// its dialog once and Android twice, so an ask with no context wastes it.

export type ReminderPermission = 'granted' | 'prompt' | 'denied' | 'unsupported';
const ASKED_KEY = 'privacynotes.reminderAsked';
const permissionListeners = new Set<() => void>();
let permissionNow: ReminderPermission = NATIVE ? 'prompt' : browserState();
function browserState(): ReminderPermission {
  if (typeof Notification === 'undefined') return 'unsupported';
  return Notification.permission === 'default' ? 'prompt' : Notification.permission;
}
/** False until the first read, so the agenda hint never flashes at launch. */
let permissionKnown = !NATIVE;
function setPermission(p: ReminderPermission) {
  const first = !permissionKnown;
  permissionKnown = true;
  if (p === permissionNow && !first) return;
  permissionNow = p;
  permissionListeners.forEach((l) => l());
}

/** Read the permission without a dialog. The plugin's own command answers
 *  null while the OS would still ask. */
async function readPermission(): Promise<ReminderPermission> {
  if (!NATIVE) {
    setPermission(browserState());
    return permissionNow;
  }
  const { invoke } = await import('@tauri-apps/api/core');
  const v = await invoke<boolean | null>('plugin:notification|is_permission_granted');
  setPermission(v === true ? 'granted' : v === false ? 'denied' : 'prompt');
  return permissionNow;
}

/** This device's permission, for the agenda hint and Settings › Calendar. */
export function useReminderPermission(): ReminderPermission {
  useEffect(() => { void readPermission().catch(() => {}); }, []);
  return useSyncExternalStore((l) => { permissionListeners.add(l); return () => { permissionListeners.delete(l); }; }, () => permissionNow);
}

/** Ask the OS, from a tap. */
export async function askReminderPermission(): Promise<ReminderPermission> {
  try {
    localStorage.setItem(ASKED_KEY, '1');
  } catch {
    // Storage refused: the next alert may ask once more.
  }
  if (!NATIVE) {
    if (typeof Notification !== 'undefined') await Notification.requestPermission();
    return readPermission();
  }
  await (await plugin()).requestPermission();
  return readPermission();
}

/** A phone asks by itself once, when the person sets an alert: the moment the
 *  reason is plain. After that only a button asks. */
export function askForRemindersOnce(): void {
  if (!NATIVE_MOBILE) return;
  try {
    if (localStorage.getItem(ASKED_KEY)) return;
  } catch {
    return;
  }
  void readPermission()
    .then((p) => (p === 'prompt' ? askReminderPermission() : p))
    .catch(() => {});
}

/** The OS page for this app's notifications, where a denial is undone. */
export async function openReminderSettings(): Promise<void> {
  const { invoke } = await import('@tauri-apps/api/core');
  await invoke('plugin:notification|open_settings');
}

/** True while an alert waits on this phone and the OS may not show it. */
const waitingListeners = new Set<() => void>();
let alertsWaiting = false;
function setAlertsWaiting(v: boolean) {
  if (v === alertsWaiting) return;
  alertsWaiting = v;
  waitingListeners.forEach((l) => l());
}
function useAlertsWaiting(): boolean {
  return useSyncExternalStore((l) => { waitingListeners.add(l); return () => { waitingListeners.delete(l); }; }, () => alertsWaiting);
}

/** The agenda's row on a phone: an alert waits and the OS may not show it. */
export function ReminderPermissionHint() {
  const { t } = useTranslation('shell');
  const permission = useReminderPermission();
  const waiting = useAlertsWaiting();
  if (!NATIVE_MOBILE || !waiting || !permissionKnown || permission === 'granted' || permission === 'unsupported') return null;
  const denied = permission === 'denied';
  return (
    <div className="shrink-0 mx-3 mt-2 flex items-center gap-2.5 rounded-lg border border-accent/30 bg-accent/10 px-3 py-2">
      <BellSimple className="w-4 h-4 shrink-0 text-accent" aria-hidden="true" />
      <p className="flex-1 min-w-0 text-[12.5px] text-pn">{t('alerts.offOnPhone')}</p>
      <button
        type="button"
        onClick={() => void (denied ? openReminderSettings() : askReminderPermission()).catch(() => {})}
        className="shrink-0 rounded-md bg-accent-fill text-white px-2.5 py-1 text-[12.5px] font-medium hover:bg-accent-fill-hover transition"
      >
        {t(denied ? 'alerts.openSettings' : 'alerts.turnOn')}
      </button>
    </div>
  );
}

/** What this device handed the OS, by notification id. Android returns
 *  only the action id with a tap or an action (no id, no extra), so the
 *  snooze action carries the id in its own id and this map turns it back
 *  into the alert. `plain` says the text sent carried no title. Ids, times
 *  and that one flag: never a title. */
type Scheduled = { nid: number; key: string; itemId: string; occurrence: string; at: number; plain?: boolean };
function readScheduled(): Scheduled[] {
  try {
    const v = JSON.parse(localStorage.getItem(SCHEDULED_KEY) ?? '[]') as unknown;
    return Array.isArray(v) ? v.filter((s): s is Scheduled => typeof s === 'object' && s !== null && typeof (s as Scheduled).nid === 'number') : [];
  } catch {
    return [];
  }
}
const SNOOZE_ACTION = 'snooze-';
/** How long a rung alert stays in the map, for a tap on Android. */
const RANG_KEPT_MS = 6 * 60 * 60_000;

/** Every id this device handed the OS, with its instant, until it is
 *  cancelled. The map lets an alert go six hours after its minute, and
 *  Android may still hold it then; the teardown cancels from this list too,
 *  because Android's cancel-all reaches only its own store, which these
 *  never enter. Ids and times only. */
const HANDED_KEY = 'privacynotes.reminderHanded';
/** No OS still holds an alarm this long past its minute. */
const HANDED_KEPT_MS = 7 * 86_400_000;
function readHanded(): Record<string, number> {
  try {
    const v = JSON.parse(localStorage.getItem(HANDED_KEY) ?? '{}') as Record<string, unknown>;
    return Object.fromEntries(Object.entries(v).filter((e): e is [string, number] => typeof e[1] === 'number'));
  } catch {
    return {};
  }
}
function writeHanded(v: Record<string, number>) {
  try {
    localStorage.setItem(HANDED_KEY, JSON.stringify(v));
  } catch {
    // Storage refused: the map still names the alerts of the last six hours.
  }
}
function noteHanded(alerts: readonly { nid: number; at: number }[]) {
  const cut = Date.now() - HANDED_KEPT_MS;
  const v = Object.fromEntries(Object.entries(readHanded()).filter(([, t]) => t > cut));
  for (const a of alerts) v[a.nid] = a.at;
  writeHanded(v);
}
function forgetHanded(nids: readonly number[]) {
  const v = readHanded();
  if (!nids.some((nid) => nid in v)) return;
  for (const nid of nids) delete v[nid];
  writeHanded(v);
}

/** The ids a teardown is cancelling and has not seen cancelled yet. A wipe
 *  keeps this one key, and a reload can come before the OS answered a send
 *  that was on its way, so the next start cancels these
 *  (cancelLeftoverReminders), and a plan does before it sends anything. Ids
 *  only, never a title or a time, and gone as soon as the teardown's last
 *  cancel went out. */
export const REMINDER_TO_CANCEL_KEY = 'privacynotes.reminderToCancel';
function readToCancel(): number[] {
  try {
    const v = JSON.parse(localStorage.getItem(REMINDER_TO_CANCEL_KEY) ?? '[]') as unknown;
    return Array.isArray(v) ? v.filter((n): n is number => typeof n === 'number') : [];
  } catch {
    return [];
  }
}
function writeToCancel(nids: readonly number[]) {
  try {
    if (nids.length) localStorage.setItem(REMINDER_TO_CANCEL_KEY, JSON.stringify([...new Set(nids)]));
    else localStorage.removeItem(REMINDER_TO_CANCEL_KEY);
  } catch {
    // Storage refused: the teardown's own cancels still run in this page.
  }
}
/** Takes off the list only the ids the caller just cancelled: a teardown can
 *  add its own while another step's cancel is out. */
function forgetToCancel(nids: readonly number[]) {
  const done = new Set(nids);
  writeToCancel(readToCancel().filter((nid) => !done.has(nid)));
}

/** Cancels what a teardown of an earlier page left unconfirmed, in the queue
 *  of runs, so it never lands between a plan's cancel and its send. The start
 *  of a phone build runs it whatever the screen (main.tsx), because after a
 *  Delete account or a sign-out cut short the next page is the sign-in screen
 *  and makes no plan. Never rejects; ids whose cancel the OS refused are
 *  dropped as well, so one refusal cannot stop every later run. */
export function cancelLeftoverReminders(): Promise<void> {
  if (!NATIVE_MOBILE) return Promise.resolve();
  deviceRun = deviceRun.catch(() => {}).then(async () => {
    const leftover = readToCancel();
    if (!leftover.length) return;
    const p = await plugin();
    await p.cancel(leftover).catch(() => {});
    leftover.forEach((nid) => sentHere.delete(nid));
    forgetToCancel(leftover);
  });
  return deviceRun.catch(() => {});
}

/** What this page sent, by id, so a re-plan sends only what changed. Kept in
 *  memory: a launch sends the whole plan once, which replaces by id. */
const sentHere = new Map<number, string>();
let typesHere = '';

/** Hand the plan to the OS on a phone. Cancel the future alerts that left
 *  the plan and send the ones that are new or changed. An alert whose minute
 *  passed is left alone while its item still wants it: the OS may still be
 *  inside its delivery window, and the plugin's cancel also takes a delivered
 *  notification off the screen. One whose item no longer wants it (deleted,
 *  trashed, its alert changed) is cancelled unless the OS shows it, or
 *  Android's late delivery rings it with the old title. When the OS cannot
 *  say what it shows, nothing is cancelled: a missed cancel costs one late
 *  notification, a wrong one a reminder that never rings.
 *  While `redact` is on (the app lock), an alert the OS still lists as
 *  pending past its minute, with a title or with text this device never
 *  recorded, is cancelled and rings again ten minutes later as a snooze, with
 *  the plan's text. Only the OS's own pending list names one: a notification
 *  delivered and dismissed is in neither that list nor the shown one, and
 *  must not ring again. Android lists no alarm of this app there, so on
 *  Android nothing is relabelled.
 *  The runs go one after the other, and a run that a newer plan replaced
 *  stops at its next step, so an older plan that waited on the permission
 *  never schedules after a newer, empty one (a Pro lock). A run also stops
 *  once a sign-out has begun: the view stays mounted for the sign-out's
 *  flush, and nothing may reach the OS or the map after the teardown below
 *  read it (liveSignIn.ts). Each send waits for the plugin's answer, which
 *  Android gives once the alarm is set and iOS before the system has added
 *  the request; the teardown cancels once more after the last answer.
 *  `plain` in the map is the text the OS was last handed: it changes only
 *  when a send was answered. Before anything else a run cancels the ids a
 *  teardown left unconfirmed (REMINDER_TO_CANCEL_KEY), so an alarm that
 *  landed after an earlier page reloaded goes before this page sends.
 *  Answers true when it snoozed alerts, which the plan must then hold. */
let deviceRun: Promise<void> = Promise.resolve();
let deviceGeneration = 0;
function scheduleOnDevice(
  plan: readonly (PlannedAlert & { title: string; body: string; plain: boolean })[],
  snoozeLabel: string,
  stillDue: (s: Scheduled) => boolean,
  redact: boolean,
): Promise<boolean> {
  const gen = ++deviceGeneration;
  const stale = () => gen !== deviceGeneration || !mayWriteUnstamped();
  let snoozed = false;
  deviceRun = deviceRun.catch(() => {}).then(async () => {
    if (stale()) return;
    const p = await plugin();
    if (stale()) return;
    const leftover = readToCancel();
    if (leftover.length) {
      // A refusal must not stop this run, or every later one.
      await p.cancel(leftover).catch(() => {});
      leftover.forEach((nid) => sentHere.delete(nid));
      forgetToCancel(leftover);
      if (stale()) return;
    }
    const now = Date.now();
    const future = plan.filter((a) => a.at > now);
    const wanted = new Set(future.map((a) => a.nid));
    const previous = readScheduled();
    // A map written before the handed list existed names alarms it does not.
    const handed = readHanded();
    const unlisted = previous.filter((s) => !(s.nid in handed));
    if (unlisted.length) noteHanded(unlisted);
    const gone = previous.filter((s) => s.at > now && !wanted.has(s.nid)).map((s) => s.nid);
    const overdue = previous.filter((s) => s.at <= now && s.at > now - RANG_KEPT_MS && !wanted.has(s.nid));
    const orphans = overdue.filter((s) => !stillDue(s));
    const titled = redact ? overdue.filter((s) => s.plain !== true && !orphans.includes(s)) : [];
    let undelivered: number[] = [];
    let relabel: Scheduled[] = [];
    if (orphans.length) {
      const shown = await p.active().then((list) => new Set(list.map((n) => n.id)), () => null);
      if (stale()) return;
      if (shown) undelivered = orphans.filter((s) => !shown.has(s.nid)).map((s) => s.nid);
    }
    if (titled.length) {
      const waiting = await p.pending().then((list) => new Set(list.map((n) => n.id)), () => null);
      if (stale()) return;
      if (waiting) relabel = titled.filter((s) => waiting.has(s.nid));
    }
    const cancel = [...gone, ...undelivered, ...relabel.map((s) => s.nid)];
    if (cancel.length) {
      await p.cancel(cancel);
      cancel.forEach((nid) => sentHere.delete(nid));
      forgetHanded(cancel);
    }
    if (stale()) return;
    for (const s of relabel) snooze(s.key, now);
    snoozed = relabel.length > 0;
    const dropped = new Set(cancel);
    const rang = overdue.filter((s) => !dropped.has(s.nid));
    const signature = (a: { at: number; title: string; body: string }) => `${a.at}|${a.title}|${a.body}`;
    const changed = future.filter((a) => sentHere.get(a.nid) !== signature(a));
    const toSend = new Set(changed.map((a) => a.nid));
    const heldPlain = new Map(previous.map((s) => [s.nid, s.plain]));
    const entry = (a: (typeof future)[number], plain: boolean | undefined): Scheduled =>
      ({ nid: a.nid, key: a.key, itemId: a.itemId, occurrence: a.occurrence, at: a.at, plain });
    // Until the OS answers, a send's text is unknown, which counts as titled:
    // only a generic text replacing a generic one is known to be plain.
    let stored: Scheduled[] = [...rang, ...future.map((a) => entry(a, toSend.has(a.nid) ? (heldPlain.get(a.nid) === true && a.plain) || undefined : a.plain))];
    localStorage.setItem(SCHEDULED_KEY, JSON.stringify(stored));
    if (changed.length === 0 || stale()) return;
    if ((await readPermission()) !== 'granted' || stale()) return;
    // iOS keeps one set of categories, so the set always names every stored alert.
    const types = stored.map((s) => s.nid).join();
    if (types !== typesHere) {
      await p.registerActionTypes(stored.map((s) => ({ id: `reminder-${s.nid}`, actions: [{ id: `${SNOOZE_ACTION}${s.nid}`, title: snoozeLabel }] })));
      typesHere = types;
    }
    // The plugin's own send does not wait for an answer; its command does.
    const { invoke } = await import('@tauri-apps/api/core');
    const answered = new Map<number, boolean>();
    for (const a of changed) {
      if (stale()) return;
      // Named before it goes, so a teardown that starts while the OS takes
      // it still cancels it.
      noteHanded([a]);
      // What the OS holds is unknown until it answers, so a run that goes
      // stale meanwhile leaves this alert to be sent again.
      sentHere.delete(a.nid);
      const options = {
        id: a.nid,
        title: a.title,
        body: a.body,
        schedule: p.Schedule.at(new Date(a.at), false, true),
        actionTypeId: `reminder-${a.nid}`,
        autoCancel: true,
      };
      const ok = await invoke('plugin:notification|notify', { options }).then(() => true, () => false);
      // One the OS refuses is sent again by the next plan, and so is one a
      // teardown cancelled while it went out.
      if (!ok || stale()) continue;
      sentHere.set(a.nid, signature(a));
      answered.set(a.nid, a.plain);
    }
    if (answered.size === 0 || stale()) return;
    stored = stored.map((s) => (answered.has(s.nid) ? { ...s, plain: answered.get(s.nid) } : s));
    localStorage.setItem(SCHEDULED_KEY, JSON.stringify(stored));
  });
  return deviceRun.then(() => snoozed);
}

/** How long a teardown waits for the plugin's answers before the wipe goes on. */
const TEARDOWN_WAIT_MS = 2_000;

/**
 * Take this phone's reminders off the OS: every alert the map or the handed
 * list names, any other pending one this app scheduled, and what already
 * rang. Every path that ends the account on this device (sign-out, a forced
 * one, the account switch, the Danger zone wipe) runs it before those lists
 * go, because the OS rings what it holds with the titles of an account that
 * is gone, and once the lists are gone nothing can name those ids again.
 *
 * The ids it can name are cancelled at once, ahead of any run still waiting
 * in the queue (on the permission, say), and again once the queue drains,
 * after the answer to any send that was on its way. It resolves only after
 * the first cancel went out, and waits for the rest at most
 * TEARDOWN_WAIT_MS, so the wipe that follows may run before the second
 * cancel; a page that reloads right after must first wait for it
 * (remindersTeardownSettled). Until that cancel went out the ids also sit in
 * REMINDER_TO_CANCEL_KEY, which a wipe keeps, so when a reload comes first
 * the next start cancels them. A run already queued stops at its next step,
 * and the next plan starts from nothing and sends every alert again. During
 * a sign-out the plans the mounted view still makes stop on their own
 * (scheduleOnDevice); during an account switch no view of the leaving
 * account is mounted.
 */
export function cancelDeviceReminders(): Promise<void> {
  if (!NATIVE_MOBILE) return Promise.resolve();
  deviceGeneration++;
  sentHere.clear();
  typesHere = '';
  // An earlier page's leftovers too: no run may have come since to cancel them.
  const named = () => [...new Set([...readScheduled().map((s) => s.nid), ...Object.keys(readHanded()).map(Number), ...readToCancel()])];
  const listed = named();
  writeToCancel(listed);
  const loading = plugin();
  // Each step on its own, so one the OS refuses leaves the others to run.
  const first = loading.then((p) => (listed.length ? p.cancel(listed).catch(() => {}) : undefined), () => {});
  deviceRun = deviceRun.catch(() => {}).then(async () => {
    const p = await loading;
    await first;
    const ids = [...new Set([...listed, ...named()])];
    if (ids.length) await p.cancel(ids).catch(() => {});
    // iOS removes every pending request, ids neither list held included;
    // Android cancels only what its own store lists, which holds none of these.
    await p.cancelAll().catch(() => {});
    await p.removeAllActive().catch(() => {});
    forgetToCancel(ids);
  });
  const drained = deviceRun.catch(() => {});
  // Registered after `first`, so the first cancel has gone out when this runs.
  return loading.then(
    () => Promise.race([Promise.all([first, drained]).then(() => {}), new Promise<void>((resolve) => { setTimeout(resolve, TEARDOWN_WAIT_MS); })]),
    () => {},
  );
}

/** Settles once every queued run, the teardown's second cancel among them,
 *  has finished, or after `ms`: what a page waits for before it reloads,
 *  since a reload drops whatever the old page still had to send the OS. */
export function remindersTeardownSettled(ms: number): Promise<void> {
  return Promise.race([deviceRun.catch(() => {}), new Promise<void>((resolve) => { setTimeout(resolve, ms); })]);
}

/** The alert a phone's tap or action names. iOS sends the notification id;
 *  Android sends only the action id, so a tap there opens the one alert that
 *  rang in the last hours, and nothing when that is not one alert. */
function alertOfAction(actionId: string, nid: number | undefined): Scheduled | undefined {
  const all = readScheduled();
  if (actionId.startsWith(SNOOZE_ACTION)) nid = Number(actionId.slice(SNOOZE_ACTION.length));
  if (nid !== undefined && Number.isFinite(nid)) return all.find((s) => s.nid === nid);
  const now = Date.now();
  const rang = all.filter((s) => s.at <= now && s.at > now - RANG_KEPT_MS);
  return rang.length === 1 ? rang[0] : undefined;
}

/** The permission of this device, for a settings row: Allow while the OS
 *  would still ask, Allowed, and after a denial the reason and, on a phone,
 *  the way to the OS page. */
export function ReminderPermissionControl() {
  const { t } = useTranslation('settings');
  const permission = useReminderPermission();
  if (permission === 'prompt') {
    return (
      <button
        type="button"
        onClick={() => void askReminderPermission().catch(() => {})}
        className="shrink-0 rounded-md bg-accent-fill text-white px-3 py-1.5 text-sm font-medium hover:bg-accent-fill-hover transition"
      >
        {t('calendar.permissionAsk')}
      </button>
    );
  }
  if (permission === 'granted') {
    return (
      <span role="status" className="shrink-0 inline-flex items-center gap-1.5 rounded-md bg-track px-3 py-1.5 text-sm text-pn-muted">
        <Check size={14} aria-hidden="true" />
        {t('calendar.permissionGranted')}
      </span>
    );
  }
  if (permission === 'denied' && REMINDER_PLATFORM === 'mobile') {
    return (
      <button
        type="button"
        onClick={() => void openReminderSettings().catch(() => {})}
        className="shrink-0 rounded-md border border-divider px-3 py-1.5 text-sm font-medium text-pn hover:bg-track transition"
      >
        {t('calendar.permissionOpenSettings')}
      </button>
    );
  }
  return null;
}

/** Show one alert now: the plugin on a desktop, the Notification API in a browser. */
async function showNow(title: string, body: string, onClick: () => void) {
  if (NATIVE) {
    const p = await plugin();
    if (await p.isPermissionGranted()) p.sendNotification({ title, body });
    return;
  }
  if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
  const n = new Notification(title, { body, tag: `${title}|${body}` });
  n.onclick = () => {
    window.focus();
    onClick();
    n.close();
  };
}

// ── The hook ──────────────────────────────────────────────────────────

const NO_ITEMS: readonly ReminderItem[] = [];

export function useReminders({
  notes, loaded, titleOf, folderName, alertsUnlocked, titles, appLock, birthday, checkIn, medications = NO_ITEMS, onOpen,
}: {
  notes: readonly LocalNote[];
  /** The first read of this device's items has landed. Before it the list is
   *  empty, and a plan made from it would cancel every alert on the phone,
   *  the ones Android still holds past their minute among them, which then
   *  never ring. */
  loaded: boolean;
  titleOf: (n: LocalNote) => string;
  folderName: (folderId: string | null | undefined) => string | undefined;
  /** Pro, or the demo. False plans nothing and cancels what was scheduled. */
  alertsUnlocked: boolean;
  /** Settings › Calendar: show titles in reminders. */
  titles: boolean;
  /** The app lock is on. A reminder then shows only the word and the time,
   *  as a PIN-protected item's does: what the OS holds and shows sits outside
   *  the lock, on its lock screen and in its own store. */
  appLock: boolean;
  /** Settings › Calendar: the birthday alert, or null for none. */
  birthday: { days: number; at: string } | null;
  /** The daily check-in reminder of this device: its time, and whether
   *  today's check-in is done. Null while it is off. Free: it rings with
   *  alerts locked. Opened under CHECK_IN_REMINDER_ID. */
  checkIn: { time: string; done: boolean } | null;
  /** The medication reminders of this device (medicationReminderItems).
   *  Pro, like the calendar alerts: with alerts locked they ring never. They
   *  never name the medication. */
  medications?: readonly ReminderItem[];
  onOpen: (id: string, occurrence: string) => void;
}): { toast: ReactNode } {
  const { t } = useTranslation('shell');
  const [tick, setTick] = useState(0);
  const [shown, setShown] = useState<(PlannedAlert & { title: string; body: string }) | null>(null);
  const firedHere = useRef(new Map<string, number>());
  const onOpenRef = useRef(onOpen);
  onOpenRef.current = onOpen;
  const permission = useReminderPermission();
  useEffect(() => { if (permission === 'granted') setTick((n) => n + 1); }, [permission]);

  // The items that can ring, with what each may show.
  const items = useMemo<ReminderItem[]>(() => {
    const out: ReminderItem[] = [];
    if (checkIn) out.push(checkInReminderItem(checkIn.time, toLocalIso(new Date()), checkIn.done));
    if (!alertsUnlocked) return out;
    out.push(...medications);
    for (const n of notes) {
      if (n.deleted !== 0 || n.trashed !== 0 || n.archived === 1) continue;
      let s: Schedule | null = null;
      let born: { month: number; day: number } | undefined;
      if (n.type === 'contact') {
        if (!birthday || n.pinProtected === 1) continue;
        const b = contactBirthday(parseContactBody(n.body));
        if (!b) continue;
        // The days come from the birthday rule (planAlerts), so 29 February
        // rings on the day the calendar draws it in every year.
        born = b;
        s = { day: toLocalIso(new Date()), alerts: [birthday] };
      } else {
        s = scheduleOf(n.trackers as Record<string, unknown> | undefined, n.type, n.type === 'journal' ? entryDayOf(n) : undefined);
      }
      if (!s?.alerts?.length) continue;
      // A PIN-protected item shows "Reminder" and the time, locked or not:
      // a plan made while the gate is open outlives the gate on the OS.
      const gated = n.pinProtected === 1;
      out.push({ id: n.id, schedule: s, title: gated ? '' : titleOf(n), folder: gated ? undefined : folderName(n.folderId), gated, birthday: born });
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [notes, alertsUnlocked, birthday?.days, birthday?.at, checkIn?.time, checkIn?.done, medications, tick]);

  const plan = useMemo(() => {
    const raw = planAlerts(items, Date.now(), readSnoozes());
    const byId = new Map(items.map((i) => [i.id, i]));
    return raw.map((a) => {
      const item = byId.get(a.itemId)!;
      // The check-in reminder carries the question and nothing else: no
      // title, no value, so the lock and the titles switch change nothing.
      if (a.itemId === CHECK_IN_REMINDER_ID) return { ...a, plain: true, title: t('checkIn.prompt'), body: '' };
      // A medication reminder says what it is and when, never which one:
      // a lock screen is read over a shoulder.
      if (a.itemId.startsWith(MEDICATION_REMINDER_PREFIX)) {
        return { ...a, plain: true, title: t('alerts.medication'), body: formatInstant(new Date(a.startsAt), 'time') };
      }
      const start = new Date(a.startsAt);
      const today = toLocalIso(start) === toLocalIso(new Date());
      const when = item.schedule.time ? formatInstant(start, today ? 'time' : 'row') : formatInstant(start, today ? 'weekday' : 'date');
      const plain = !titles || appLock || item.gated;
      return { ...a, plain, ...reminderText(item, when, { titles: !plain, reminder: t('alerts.reminder'), untitled: t('common:state.untitled') }) };
    });
  }, [items, titles, appLock, t, tick]);

  // The OS schedule on a phone, and the status line, from the items read.
  useEffect(() => {
    if (!loaded) return;
    setThrough(plannedThrough(plan));
    if (!NATIVE_MOBILE) return;
    const now = Date.now();
    setAlertsWaiting(plan.some((a) => a.at > now));
    // Whether an alert whose minute passed is one its item still wants, at
    // that instant: the plan from that moment holds it.
    const byId = new Map(items.map((i) => [i.id, i]));
    const stillDue = (s: Scheduled) => {
      const item = byId.get(s.itemId);
      return item !== undefined && planAlerts([item], s.at, readSnoozes()).some((a) => a.key === s.key && a.at === s.at);
    };
    void scheduleOnDevice(plan, t('alerts.snooze'), stillDue, appLock)
      .then((snoozed) => { if (snoozed) setTick((n) => n + 1); })
      .catch((err: unknown) => console.warn('[reminders] schedule failed', err));
  }, [plan, items, loaded, appLock, t]);

  // A local time names an instant only in a zone. When the zone changes while
  // the app runs (a flight, the clock settings), the plan is made again, so an
  // alert at 09:00 moves to 09:00 where the device is now: a phone's OS gets
  // the new instants, and the timer below waits for the new one. Coming back
  // to the app re-plans as well (below); a phone that stays closed keeps the
  // old instants until it runs once in the new zone.
  // The zone the plan was counted in: read again each time the plan is made.
  const planZone = useMemo(() => zoneNow(), [plan]);
  useEffect(() => {
    const id = window.setInterval(() => {
      if (zoneNow() !== planZone) setTick((n) => n + 1);
    }, ZONE_CHECK_MS);
    return () => window.clearInterval(id);
  }, [planZone]);

  // Back to the app (also from the OS settings): re-plan, so a day that
  // passed, a snooze, a permission granted there or a new time zone is counted.
  useEffect(() => {
    const again = () => {
      if (document.visibilityState !== 'visible') return;
      void readPermission().catch(() => {});
      setTick((n) => n + 1);
    };
    document.addEventListener('visibilitychange', again);
    return () => document.removeEventListener('visibilitychange', again);
  }, []);

  // A phone's notification: a tap opens the item, Snooze puts it ten minutes out.
  useEffect(() => {
    if (!NATIVE_MOBILE) return;
    let off: { unregister: () => void } | null = null;
    let gone = false;
    void (async () => {
      const p = await plugin();
      const listener = await p.onAction((payload) => {
        const raw = payload as unknown as { actionId?: string; notification?: { id?: number } | null };
        const actionId = raw.actionId ?? '';
        if (actionId === 'dismiss') return;
        const alert = alertOfAction(actionId, raw.notification?.id);
        if (!alert) return;
        if (actionId.startsWith(SNOOZE_ACTION)) {
          snooze(alert.key);
          setTick((n) => n + 1);
          return;
        }
        onOpenRef.current(alert.itemId, alert.occurrence);
      });
      if (gone) listener.unregister();
      else off = listener;
    })();
    return () => { gone = true; off?.unregister(); };
  }, []);

  // The timer of an open app: the next alert fires the toast, the bell, and
  // on a desktop or in a browser the system notification.
  useEffect(() => {
    const fired = firedAt();
    const done = (a: PlannedAlert) => {
      const t = fired[a.key] ?? firedHere.current.get(a.key);
      return t !== undefined && t >= a.at - 60_000;
    };
    const next = plan.find((a) => !done(a));
    if (!next) return;
    const wait = Math.max(0, next.at - Date.now());
    const id = window.setTimeout(() => {
      // Waited past its cap, or the zone changed since the plan was made.
      if (wait > MAX_TIMER_MS || zoneNow() !== planZone) { setTick((n) => n + 1); return; }
      firedHere.current.set(next.key, Date.now());
      markFired(next.key);
      // The bell is the Calendar row's; the check-in has no item there.
      if (next.itemId !== CHECK_IN_REMINDER_ID && !next.itemId.startsWith(MEDICATION_REMINDER_PREFIX)) markUnseen(next.itemId);
      setShown(next);
      if (!NATIVE_MOBILE) void showNow(next.title, next.body, () => onOpenRef.current(next.itemId, next.occurrence));
      setTick((n) => n + 1);
    }, Math.min(wait, MAX_TIMER_MS));
    return () => window.clearTimeout(id);
  }, [plan, planZone]);

  const toast = shown ? (
    <UpdateToast
      title={shown.title}
      meta={shown.body}
      icon={<BellSimple className="w-4 h-4 text-accent" aria-hidden="true" />}
      actionLabel={t('alerts.open')}
      onAction={() => { const s = shown; setShown(null); onOpenRef.current(s.itemId, s.occurrence); }}
      secondary={{ label: t('alerts.snooze'), onAction: () => { snooze(shown.key); setShown(null); setTick((n) => n + 1); } }}
      onDismiss={() => setShown(null)}
    />
  ) : null;

  return { toast };
}
