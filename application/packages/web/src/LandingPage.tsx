import { useEffect, useRef, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import type { CSSProperties, ReactNode } from 'react';
import { AndroidLogo, AppleLogo, Archive, ArrowLeft, ArrowUpRight, Book, Bookmarks, CaretDown, ChartBar, Check, CheckCircle, CheckFat, CheckSquare, Copy, Cube, FileText, Folder, GithubLogo, GooglePlayLogo, Key, List, Lock, LockSimple, Moon, Package, Pill, SealCheck, Shield, Smiley, Square, Sun, TerminalWindow, WindowsLogo, X } from './icons';
import { LogoIcon } from './LogoIcon';
import { Brand } from './Brand';
import { openExternal } from './openExternal';
import { LanguageMenu } from './LanguageMenu';
import { LanguageSuggest } from './LanguageSuggest';
import { AnnouncementBanner } from './AnnouncementBanner';
import { siteDismissedIds, dismissOnSite } from './announcements';
import { SiteFooter } from './SiteFooter';
import { helpPath } from './localeRoutes';
import { HelpChip } from './HelpChip';
import { activeLocale } from './languages';
import { applyStoredTheme, previewColorTheme, getStoredColorTheme, useTheme } from './theme';
import { isBetaPricing } from './paddle';
import { PRO_PRICE, EARLY_PRICE, STORAGE_ADDON_PRICE } from './pricing';
import { detectPlatform } from './devices';
import { useAuth } from './auth';
import { isDemoMode } from './demo';
import { APP_ORIGIN, isAppHost, isApexHost } from './hosts';
import { captureSource, withSource } from './campaignSource';
import { marketingHomeHref } from './siteLinks';
import { GUIDE_META, GUIDE_ORDER } from './guides';

/** Native (Tauri) apps skip the marketing homepage and open on the auth card. */
const IS_DESKTOP = detectPlatform() !== 'web';

/**
 * Stable "latest macOS build" link. The release runbook overwrites this single
 * object on every release, so the homepage never needs touching and the link
 * never goes stale. Universal .dmg (Intel + Apple Silicon).
 * // Spec: ops/docs/macos-ios-setup.md (publish to R2 - stable latest/ alias)
 */
const MAC_DMG_URL = 'https://releases.privacynotes.app/latest/PrivacyNotes_universal.dmg';

/**
 * App Store listing for the iPhone and iPad app. Country-less form: Apple
 * redirects it to the reader's own storefront. StoreUpdateToast.tsx carries
 * the same URL for the in-app floor toast, because that file ships inside the
 * native binaries and must not import marketing code.
 * // Spec: ops/docs/mobile-release-status.md (app records - Apple ID 6785958812)
 */
const APP_STORE_URL = 'https://apps.apple.com/app/id6785958812';

/** All-platform release archive on the public GitHub repo, one page per version, signed builds. */
const GITHUB_RELEASES_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/releases';

/**
 * The public repository, and the documents that answer "prove it".
 *
 * Every URL below is written out in full rather than built from the repo
 * root, because `pnpm check:docs` finds these links by scanning for the
 * literal `/blob/main/` prefix. It then reads the private source of each
 * document and fails when a heading we link no longer exists. A composed
 * URL would be invisible to it, and a renamed heading is invisible to
 * everyone else: GitHub serves a stale anchor as the top of the page.
 */
const GITHUB_REPO_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app';
const VERIFY_DOC_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md';
const THREAT_MODEL_DOC_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/THREAT_MODEL.md';
const SECURITY_DOC_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md';
const CRYPTO_SRC_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/crypto/crypto.ts';

/**
 * The Zapstore listing, and the store itself for a reader who has never heard of it.
 *
 * Zapstore carries the same direct APK the row below links, taken from the GitHub release,
 * so there is no separate build and no second signing key. What it adds over a raw download
 * is verification a person cannot do by hand on a phone: it checks the file hash and the
 * signing certificate against the ones recorded when we published, and refuses the install
 * on a mismatch. The listing id is the Android package id.
 * Spec: ops/docs/android-setup.md (Zapstore listing)
 */
const ZAPSTORE_LISTING_URL = 'https://zapstore.dev/apps/app.privacynotes';
const ZAPSTORE_SITE_URL = 'https://zapstore.dev';

/**
 * Repo root, which is what Obtainium's GitHub source wants pasted in - NOT the /releases
 * page and NOT a direct asset link. Obtainium then reads the release feed itself, picks the
 * one .apk asset per tag, and installs each new version. That is the whole integration: no
 * manifest to publish, no account, no review queue, and nothing for us to keep in sync,
 * because it reads the same releases the workflows already push.
 */
const OBTAINIUM_SOURCE_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app';

/** Obtainium's own homepage, linked from the row so people who have never heard of it can find out what it is. */
const OBTAINIUM_SITE_URL = 'https://obtainium.imranr.dev/';

/**
 * The one-tap route: Obtainium registers the `obtainium://` scheme, so this hands the phone a
 * ready-made app entry instead of a URL to paste. The payload is built here rather than pasted
 * as one long encoded string, so the repo URL stays single-sourced and the shape stays readable;
 * it is the same four fields as our merged listing in ops/packaging/obtainium/app.privacynotes.json,
 * and Obtainium fills every other field with its GitHub-source defaults on import.
 * The redirect page in the middle is Obtainium's own and is what makes the link degrade instead
 * of dead-ending: it validates the payload, then falls back to "get Obtainium" when no handler
 * answers, which is every desktop visitor and everyone who does not have it yet.
 * // Spec: ops/packaging/obtainium/README.md (the one-tap add link)
 */
const OBTAINIUM_ADD_URL = `https://apps.obtainium.imranr.dev/redirect?r=obtainium://app/${encodeURIComponent(
  JSON.stringify({ id: 'app.privacynotes', url: OBTAINIUM_SOURCE_URL, author: 'LifetimeLabsDev', name: 'PrivacyNotes' }),
)}`;

/**
 * Stable "latest Linux build" link (AppImage, x86_64). Same pattern as MAC_DMG_URL: the
 * release workflow overwrites this object every release, so the link never goes stale.
 * // Spec: ops/docs/linux-release.md (publish to R2 - stable latest/ alias)
 */
const LINUX_APPIMAGE_URL = 'https://releases.privacynotes.app/latest/PrivacyNotes_x86_64.AppImage';

/**
 * Stable "latest Linux .deb" link (amd64), the native Debian/Ubuntu install: no chmod, a
 * desktop entry, an app-menu icon. Same overwrite-every-release pattern as the AppImage, but
 * unlike the AppImage it cannot self-update (a deb lives in root-owned /usr), so it is offered
 * alongside the AppImage, not instead of it.
 * // Spec: ops/docs/linux-release.md (publish to R2 - stable latest/ alias)
 */
const LINUX_DEB_URL = 'https://releases.privacynotes.app/latest/PrivacyNotes_amd64.deb';

/** ARM64 (aarch64) Linux builds: Raspberry Pi, Ampere/Graviton, ARM laptops, ARM Linux VMs. */
const LINUX_APPIMAGE_ARM64_URL = 'https://releases.privacynotes.app/latest/PrivacyNotes_aarch64.AppImage';
const LINUX_DEB_ARM64_URL = 'https://releases.privacynotes.app/latest/PrivacyNotes_arm64.deb';

/** The two CPU families the Linux release matrix publishes for. */
type LinuxArch = 'x86_64' | 'aarch64';

/**
 * Everything the Linux disclosure needs per architecture, in one table: the two
 * download links, the `.deb` filename its apt footnote quotes, and the two copy keys
 * for the group heading. Single-sourcing the heading here is what keeps the footnote
 * from drifting from the rows above it - they used to carry the same two literals
 * twice, and only one of the pair would have been updated.
 */
const LINUX_BUILDS: Record<LinuxArch, { appimage: string; deb: string; debFile: string; label: string; desc: string }> = {
  x86_64: {
    appimage: LINUX_APPIMAGE_URL,
    deb: LINUX_DEB_URL,
    debFile: 'PrivacyNotes_amd64.deb',
    label: 'downloads.linuxArchX86',
    desc: 'downloads.linuxArchX86Desc',
  },
  aarch64: {
    appimage: LINUX_APPIMAGE_ARM64_URL,
    deb: LINUX_DEB_ARM64_URL,
    debFile: 'PrivacyNotes_arm64.deb',
    label: 'downloads.linuxArchArm',
    desc: 'downloads.linuxArchArmDesc',
  },
};

/**
 * Which Linux build this machine needs, or null when the browser will not say.
 *
 * Null is not a failure. It renders BOTH groups, which is the disclosure exactly as it
 * shipped before detection existed, so everything here is a shortcut layered on a panel
 * that is already complete without it. Nothing renders differently on first paint or
 * with JS off, because the effect only ever narrows what is shown.
 *
 * Two engines, two sources, and the order matters. Chrome froze its Linux user agent at
 * `X11; Linux x86_64` during UA reduction, so reading the string there would confidently
 * hand an ARM machine the wrong file; on Chromium the only honest answer is the async
 * UA-CH `architecture` hint. Firefox never froze it and reports `aarch64` in the string,
 * which is why the string branch runs ONLY when `navigator.userAgentData` is absent.
 *
 * A visitor who is not on Linux always gets null. Someone who opens this panel on a Mac
 * is downloading for a different machine, and their own CPU says nothing about it.
 */
function useLinuxArch(): LinuxArch | null {
  const [arch, setArch] = useState<LinuxArch | null>(null);
  useEffect(() => {
    // Cast through unknown rather than intersecting Navigator: where the DOM lib
    // already declares userAgentData, an intersection merges with its narrower hint
    // type and `bitness` disappears.
    const uaData = (navigator as unknown as {
      userAgentData?: {
        platform?: string;
        getHighEntropyValues?: (hints: string[]) => Promise<{ architecture?: string; bitness?: string }>;
      };
    }).userAgentData;
    if (uaData) {
      if (uaData.platform !== 'Linux' || !uaData.getHighEntropyValues) return;
      uaData.getHighEntropyValues(['architecture', 'bitness']).then(
        (hints) => {
          if (hints.bitness !== '64') return;
          if (hints.architecture === 'arm') setArch('aarch64');
          else if (hints.architecture === 'x86') setArch('x86_64');
        },
        () => {},
      );
      return;
    }
    const ua = navigator.userAgent;
    if (!/Linux|X11/.test(ua) || /Android/.test(ua)) return;
    if (/aarch64|arm64/.test(ua)) setArch('aarch64');
    else if (/x86_64|amd64/.test(ua)) setArch('x86_64');
  }, []);
  return arch;
}

/**
 * The digest link at the end of a download row: a padlock, the word, and a new tab. Every
 * release pipeline publishes a `.sha256` beside every artifact it serves, on every
 * platform, so the URL is always the download URL plus a suffix.
 * // Spec: ops/docs/linux-release.md (every artifact ships a .sha256 sibling)
 *
 * A new tab, because the digest is a plain-text file the browser renders in place:
 * same-tab would replace the download page with a bare line of hex and leave the reader to
 * find their way back to the build they came for.
 *
 * `relative` is load-bearing. Both callers stretch their own download link across the
 * whole row with an `::after`, so without a stacking context of its own this link would
 * sit underneath it and never take the click.
 */
function ChecksumLink({ href, label, className }: { href: string; label: string; className?: string }) {
  const { t } = useTranslation('landing');
  return (
    <a
      href={`${href}.sha256`}
      target="_blank"
      rel="noopener"
      aria-label={t('downloads.checksumAria', { label })}
      className={`relative flex shrink-0 items-center gap-1 font-mono text-[11px] text-accent transition hover:opacity-80${className ? ` ${className}` : ''}`}
    >
      <LockSimple size={13} weight="fill" aria-hidden="true" />
      sha256
    </a>
  );
}

/**
 * One row in the Linux download disclosure: the format link, its one-line description,
 * and the digest CI publishes beside every artifact, so a download from this page can be
 * checked without trusting this page. The `.sha256` sibling names the R2 object rather
 * than the local build file, so `sha256sum -c` works on the file as it was downloaded.
 * // Spec: ops/docs/linux-release.md (every artifact ships a .sha256 sibling)
 *
 * The row is a div rather than an anchor because it now holds two links, and an anchor
 * may not nest one. The format link stretches back over the whole row, so the click
 * target is exactly what it was, and the digest link sits above it on its own layer.
 */
function LinuxDl({ href, label, desc, icon, recommended, divider }: {
  href: string; label: string; desc: string; icon: ReactNode; recommended?: boolean; divider?: boolean;
}) {
  const { t } = useTranslation('landing');
  return (
    <div
      className={`relative flex flex-wrap items-center justify-between gap-x-3 gap-y-1 px-4 py-3 hover:bg-[var(--wl-ink)]/5${divider ? ' border-t border-[var(--wl-ink)]/10' : ''}`}
    >
      <a href={href} className="flex items-center gap-2 font-semibold text-[var(--wl-ink)] after:absolute after:inset-0">
        <span aria-hidden="true" className="shrink-0 text-accent">{icon}</span>
        {label}
      </a>
      {recommended && (
        <span className="shrink-0 rounded-full border border-[var(--wl-emerald)]/30 bg-[var(--wl-tint-green)] px-2.5 py-1 text-xs font-semibold text-[var(--wl-emerald)]">
          {t('downloads.recommended')}
        </span>
      )}
      <span className="flex items-center gap-3 sm:ms-auto">
        <span className="text-sm text-[var(--wl-sub)]">{desc}</span>
        <ChecksumLink href={href} label={label} />
      </span>
    </div>
  );
}

/**
 * Rounded mono command block with a copy button glued to its right edge. The single way
 * /download presents a shell command: DebCmd and PkgCmd both render through it, so a
 * styling or behaviour change lands on every command at once. The button copies the
 * unwrapped one-line command, and flips to a check for a moment as feedback.
 */
function CmdBlock({ cmd, className }: { cmd: string; className?: string }) {
  const { t } = useTranslation('landing');
  const [copied, setCopied] = useState(false);
  return (
    <div className={`flex items-center justify-between gap-2 rounded-lg bg-[var(--wl-ink)]/8 py-1 ps-2.5 pe-1 ${className ?? ''}`}>
      <code className="min-w-0 whitespace-pre-wrap break-words py-0.5 font-mono text-xs text-[var(--wl-ink)]">{cmd}</code>
      <button
        type="button"
        aria-label={t('common:actions.copy')}
        onClick={() => {
          navigator.clipboard.writeText(cmd).then(
            () => {
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1500);
            },
            () => {},
          );
        }}
        className="shrink-0 cursor-pointer rounded-md p-1.5 text-[var(--wl-sub)] transition hover:bg-[var(--wl-ink)]/8 hover:text-[var(--wl-ink)]"
      >
        {copied ? <Check size={15} weight="bold" /> : <Copy size={15} weight="bold" />}
      </button>
    </div>
  );
}

/**
 * One `sudo apt install` line in the Linux disclosure's update footnote, labelled with the
 * architecture it belongs to. The label carries the same weight, size and accent colour as
 * the architecture heading in the artifact list above, because it names the same thing and a
 * reader scans down for the one that matches. It is labelled rather than bare, and follows the same
 * `linuxArchShown` set as the download rows above, because the filenames differ by one token
 * and the failure mode for picking wrong is unreadable: installing the arm64 `.deb` on an x86
 * machine dies deep in apt's dependency solver (foreign-arch deps are "not installable", plus
 * a conflict against the installed native package), which reads as a broken package rather
 * than as the wrong download.
 *
 * Soft-wrap rather than scroll: at this card width the command is ~40px too long, and a
 * horizontal scroller hides the tail of the filename, which is the part that has to be right.
 * The wrap falls at the space before the path and never enters the DOM, so a copy still
 * yields one line.
 */
function DebCmd({ arch, file }: { arch: string; file: string }) {
  return (
    <>
      <div className="mt-2.5 font-semibold text-accent">{arch}</div>
      <CmdBlock className="mt-1" cmd={`sudo apt install ~/Downloads/${file}`} />
    </>
  );
}

/**
 * One package-manager row inside the downloads disclosure: platform icon, the OS name
 * with the tool in brackets, a one-line note, then the command.
 *
 * The command block is CmdBlock, shared with DebCmd, so /download keeps a single way
 * of presenting a shell command: one rounded mono block, one copy button.
 */
function PkgCmd({ icon, name, tool, desc, cmd, divider }: {
  icon: ReactNode; name: string; tool: string; desc: string; cmd: string; divider?: boolean;
}) {
  return (
    <div className={`px-4 py-3${divider ? ' border-t border-[var(--wl-ink)]/10' : ''}`}>
      <span className="mb-1.5 flex items-center gap-2 font-semibold text-[var(--wl-ink)]">
        <span aria-hidden="true" className="shrink-0 text-accent">{icon}</span>
        {name} <span className="font-normal text-[var(--wl-sub)]">({tool})</span>
      </span>
      <span className="mt-0.5 block text-sm text-[var(--wl-sub)]">{desc}</span>
      <CmdBlock className="mt-2" cmd={cmd} />
    </div>
  );
}

/**
 * Stable "latest Windows build" link (NSIS -setup.exe, x86_64). Same overwrite-on-release
 * pattern as MAC_DMG_URL and LINUX_APPIMAGE_URL: the release workflow rewrites this alias every
 * release, so the link never goes stale.
 * // Spec: ops/docs/windows-release.md (publish to R2 - stable latest/ alias)
 */
const WINDOWS_SETUP_URL = 'https://releases.privacynotes.app/latest/PrivacyNotes_x64-setup.exe';

/**
 * Stable "latest Android direct APK" link (the sideload channel; Google Play comes
 * later). Same pattern as MAC_DMG_URL: publishing a release overwrites this object
 * every release, so the link never goes stale. Installed APKs nudge themselves onto
 * newer versions via AndroidUpdateToast.tsx.
 *
 * The URL is versionless but the DOWNLOAD is not: publishing sets Content-Disposition
 * on this object to the release filename, so it saves as PrivacyNotes-<ver>.apk. That
 * matters more on Android than anywhere else, because a sideloaded APK updates by
 * manual re-download and the copies otherwise pile up as PrivacyNotes-1.apk, -2.apk
 * with no way to tell them apart. Do NOT "fix" this by pointing the href at the
 * versioned key: that needs the manifest fetch below to have resolved, so it would
 * break the tile with JS off, on a failed fetch, and on first paint.
 * // Spec: ops/docs/android-setup.md (publish to R2 - stable latest/ alias)
 */
const ANDROID_APK_URL = 'https://releases.privacynotes.app/latest/PrivacyNotes.apk';

/**
 * Per-platform "latest release" manifests, rendered as small version tags on
 * the download tiles. Desktop entries are the Tauri per-target updater
 * manifests each release pipeline keeps fresh; Android is the direct-APK
 * manifest AndroidUpdateToast polls. Platform versions drift on purpose (a
 * macOS-only fix bumps only darwin), so every tile fetches its own manifest.
 * A failed fetch just renders no tag.
 * // Spec: ops/docs/macos-ios-setup.md, ops/docs/linux-release.md, ops/docs/windows-release.md (per-target updater manifests)
 */
const VERSION_MANIFEST_URLS = {
  macOS: 'https://releases.privacynotes.app/u/darwin-aarch64/latest.json',
  Windows: 'https://releases.privacynotes.app/u/windows-x86_64/latest.json',
  Linux: 'https://releases.privacynotes.app/u/linux-x86_64/latest.json',
  Android: 'https://releases.privacynotes.app/android/latest.json',
} as const;

type VersionPlatform = keyof typeof VERSION_MANIFEST_URLS;

/**
 * Latest released version per platform, filled in as each manifest loads.
 *
 * `enabled` is false wherever the download tiles are unreachable, which is the
 * native app and the dedicated app host: both open straight to the auth card
 * and return before the marketing body renders, so fetching four release
 * manifests there is four requests for markup nobody will see - and this
 * component remounts on sign-out, so an ungated fetch would re-run then too.
 */
function usePlatformVersions(enabled: boolean) {
  const [versions, setVersions] = useState<Partial<Record<VersionPlatform, string>>>({});
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    for (const [platform, url] of Object.entries(VERSION_MANIFEST_URLS) as [VersionPlatform, string][]) {
      fetch(url)
        .then((res) => (res.ok ? res.json() : null))
        .then((manifest: unknown) => {
          const version = (manifest as { version?: unknown } | null)?.version;
          if (cancelled || typeof version !== 'string') return;
          setVersions((prev) => ({ ...prev, [platform]: version.replace(/^v/, '') }));
        })
        .catch(() => {});
    }
    return () => {
      cancelled = true;
    };
  }, [enabled]);
  return versions;
}

function FeaturePill({ children }: { children: ReactNode }) {
  return (
    <span className="rounded-full border-[1.5px] border-[var(--wl-chip-border)] bg-[var(--wl-card)] text-[var(--wl-chip-text)] px-3.5 py-1.5 text-xs font-semibold">
      {children}
    </span>
  );
}

/** Tux, drawn multi-path so the feet and beak can carry the brand amber.
 *  Landing-only. The colors are canonical and fixed: the platform tiles
 *  keep their light tints in BOTH modes (see DownloadTile's tileBg doc),
 *  so the black body always sits on the light tan - an inverted cream
 *  penguin was tried on 2026-08-25 and rejected the same hour. */
function TuxMark({ size = 46 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <ellipse cx="8.6" cy="21" rx="2.5" ry="1.4" fill="#E08A0B" />
      <ellipse cx="15.4" cy="21" rx="2.5" ry="1.4" fill="#E08A0B" />
      <path d="M12 2.2c-3.1 0-5 2.6-5 6 0 2-.9 3.2-.9 5.6 0 3.4 2.6 6.4 5.9 6.4s5.9-3 5.9-6.4c0-2.4-.9-3.6-.9-5.6 0-3.4-1.9-6-5-6z" fill="#171717" />
      <ellipse cx="12" cy="14.4" rx="3.1" ry="4.4" fill="#ffffff" />
      <ellipse cx="9.9" cy="7.8" rx="1.3" ry="1.8" fill="#ffffff" />
      <ellipse cx="14.1" cy="7.8" rx="1.3" ry="1.8" fill="#ffffff" />
      <circle cx="10.2" cy="8.3" r="0.7" fill="#171717" />
      <circle cx="13.8" cy="8.3" r="0.7" fill="#171717" />
      <path d="M10.5 9.8h3l-1.5 1.8z" fill="#E08A0B" />
    </svg>
  );
}

function DownloadTile({
  href,
  icon,
  name,
  tileBg,
  iconColor,
  onClick,
  expanded,
  version,
  note,
}: {
  href?: string;
  icon: ReactNode;
  name: string;
  /** Tile fill for BOTH modes: the platform tiles keep their light tints
   *  in dark (decided 2026-08-25) so the brand icons - Tux's canonical
   *  black body above all - never sit on a near-black card. Icon colors
   *  must therefore work on a light ground in both modes. A tile with no
   *  destination is the exception and renders dim and dashed below. */
  tileBg?: string;
  iconColor?: string;
  onClick?: () => void;
  expanded?: boolean;
  version?: string;
  /** Fills the version slot on a tile that has no version manifest to read.
   *  The App Store owns the iOS version and publishes no manifest we could
   *  poll, so that tile names the store instead of leaving the line blank. */
  note?: string;
}) {
  const { t } = useTranslation('landing');
  if (!href && !onClick) {
    return (
      <div className="flex w-20 flex-col items-center gap-2.5">
        <span
          aria-hidden="true"
          className="inline-flex h-[72px] w-[72px] items-center justify-center rounded-2xl border-2 border-dashed border-[var(--wl-ink)]/15 bg-[var(--wl-tint)] text-[var(--wl-muted)]"
        >
          {icon}
        </span>
        <span className="text-sm font-semibold text-[var(--wl-muted)]">{name}</span>
      </div>
    );
  }
  // No parentheses around the version: the accessible name must CONTAIN the
  // visible text ("macOS v0.448.0"), and "(v0.448.0)" breaks the substring.
  // Same rule for a note, which sits in the same slot and is equally visible.
  const suffix = version ? ` v${version}` : note ? ` ${note}` : '';
  const ariaLabel = `${t('downloads.tileAria', { name })}${suffix}`;
  const tile = (
    <>
      <span
        aria-hidden="true"
        className="pn-fx-conic-tile inline-flex h-[72px] w-[72px] items-center justify-center rounded-2xl"
        style={{ '--tile-bg-l': tileBg, color: iconColor } as CSSProperties}
      >
        {icon}
      </span>
      <span className="text-sm font-semibold text-[var(--wl-ink)]">{name}</span>
      <span className="h-3.5 font-mono text-[10px] text-[var(--wl-muted)]">{version ? `v${version}` : note}</span>
    </>
  );
  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        aria-expanded={expanded}
        aria-label={ariaLabel}
        className="group flex w-20 cursor-pointer flex-col items-center gap-2.5"
      >
        {tile}
      </button>
    );
  }
  return (
    <a href={href} aria-label={ariaLabel} className="group flex w-20 flex-col items-center gap-2.5">
      {tile}
    </a>
  );
}

function Marquee({ items, separator, className }: { items: string[]; separator: string; className: string }) {
  const content = items.map((item) => `${item}  ${separator}  `).join('');
  return (
    <div className={`overflow-hidden whitespace-nowrap py-2.5 ${className}`}>
      <div className="inline-flex w-max pn-marquee">
        <span>{content}</span>
        <span aria-hidden="true">{content}</span>
      </div>
    </div>
  );
}

/**
 * Two-state theme switch for the marketing chrome: it flips to the opposite
 * of what is on screen and pins that choice (theme.ts toggle semantics -
 * the same stored mode the app's Appearance pane and the static pages'
 * toggle use). The system preference applies on its own until the first
 * click; there is deliberately no third "system" position here - Auto
 * stays one click away in the app's Appearance pane. The icon shows the
 * mode a click switches TO. Rendered in both swap-over headers (rule: the
 * two headers carry the same controls), in the mobile nav overlay, and on
 * the auth view's header row.
 */
function ThemeToggle({ compact }: { compact?: boolean }) {
  const { t } = useTranslation('landing');
  const { theme, toggle } = useTheme();
  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={t('header.themeToggle')}
      className={`cursor-pointer inline-flex ${compact ? 'h-9 w-9' : 'h-10 w-10'} items-center justify-center rounded-full border-[1.5px] border-[var(--wl-ink)] text-[var(--wl-ink)] hover:bg-[var(--wl-ink)]/10 transition`}
    >
      {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
    </button>
  );
}

function Kicker({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={`font-mono text-[11px] font-semibold uppercase tracking-[0.2em] mb-5 ${className ?? 'text-accent'}`}>
      {'// '}{children}
    </div>
  );
}

const RIBBON_ITEM_KEYS = ['ribbon.freeForever', 'ribbon.zeroKnowledge', 'ribbon.swissServers', 'ribbon.noSubscription', 'ribbon.openSource'];
const WONT_FIND_KEYS = [
  'wontFind.noTracking',
  'wontFind.noAds',
  'wontFind.noHarvesting',
  'wontFind.noAiTraining',
  'wontFind.noLockIn',
  'wontFind.noEmail',
  'wontFind.noTelemetry',
  'wontFind.noCookieBanner',
  'wontFind.noPasswords',
  'wontFind.noDarkPatterns',
  'wontFind.noVc',
  'wontFind.noBlockchain',
  'wontFind.noBackdoor',
];
const CRYPTO_ITEM_KEYS = ['crypto.xchacha', 'crypto.bip39', 'crypto.ed25519', 'crypto.swissServers', 'crypto.noTracking', 'crypto.rls'];

/**
 * The "read it yourself" rows. Order is the reader's route, not the
 * repository's: the walkthrough that needs no tools, then the attacker's
 * view, then the server's, and the cipher last for whoever wants it.
 *
 * The file name renders under every label because it is the honest part -
 * these are English documents on GitHub, and a row that hid that behind a
 * translated label would promise a page in the reader's language.
 */
const READ_IT_DOCS = [
  { file: 'VERIFY.md', href: VERIFY_DOC_URL, labelKey: 'readIt.verify', icon: SealCheck },
  { file: 'THREAT_MODEL.md', href: THREAT_MODEL_DOC_URL, labelKey: 'readIt.threatModel', icon: Shield },
  { file: 'SECURITY.md', href: SECURITY_DOC_URL, labelKey: 'readIt.security', icon: Lock },
  { file: 'crypto/crypto.ts', href: CRYPTO_SRC_URL, labelKey: 'readIt.crypto', icon: Key },
] as const;

/* Landing-only hover effects (scoped pn-fx- classes) plus the washi palette
   variables (--wl-*) the marketing page is tinted with, both rendered in a
   <style> tag next to the marquee keyframes. The palette is scoped to the
   .pn-washi wrapper so the app theme tokens stay untouched; the .dark block
   flips it to the sumi ink set. Every value passes WCAG AA against the
   grounds it is used on - re-check contrast if any value changes.
   // Spec: ops/docs/design-decisions.md (washi landing palette) */
export const FX_CSS = `
.pn-washi{
--wl-bg:#F7F1E1;--wl-card:#FCF8EC;--wl-tint:#ECE3C9;
--wl-ink:#1C1917;--wl-sub:#6A6152;--wl-muted:#6F654C;--wl-line:#E0D7BD;
--brand-ink:var(--wl-ink);
--wl-slab-sub:#A9A195;
--wl-ink-card:#201B15;--wl-ink-line:#37301F;--wl-ink-text:#D8D2C3;--wl-ink-sub:#A69E8F;
--wl-pro:#1E40AF;
--wl-tint-blue:#E8EAF2;--wl-tint-green:#E4EBD5;--wl-tint-amber:#F7EAB8;
--wl-amber-text:#92400E;--wl-amber-border:#B45309;
--wl-emerald:#065F46;
--wl-chip-border:#1C1917;--wl-chip-text:#1C1917;
--wl-footer:#161210;
--wl-tile-files:#ECE3C9;--wl-tile-marks:#FCF8EC;
--wl-grid-line:rgba(30,64,175,.12);
}
.dark .pn-washi{
--wl-bg:#171310;--wl-card:#201B15;--wl-tint:#241E15;
--wl-ink:#EDE7DB;--wl-sub:#A69E8F;--wl-muted:#8F8776;--wl-line:#352D20;
--wl-slab-sub:#6A6152;
--wl-ink-card:#251F17;--wl-ink-line:#3A3226;--wl-ink-text:#D8D2C3;--wl-ink-sub:#A69E8F;
--wl-pro:#24439E;
--wl-tint-blue:#212940;--wl-tint-green:#1E2A1F;--wl-tint-amber:#2C230F;
--wl-amber-text:#FBBF24;--wl-amber-border:rgba(251,191,36,.55);
--wl-emerald:#34D399;
--wl-chip-border:#3A3226;--wl-chip-text:#CFC8B8;
--wl-footer:#1F1A14;
--wl-tile-files:#322818;--wl-tile-marks:#272119;
--wl-grid-line:rgba(122,155,232,.16);
}
@property --pn-spin{syntax:"<angle>";initial-value:0deg;inherits:false}
.pn-fx-conic-btn{border:2px solid transparent;background:linear-gradient(var(--wl-ink),var(--wl-ink)) padding-box,linear-gradient(var(--wl-ink),var(--wl-ink)) border-box}
.pn-fx-conic-btn:hover,.group:hover .pn-fx-conic-btn{background:linear-gradient(var(--wl-ink),var(--wl-ink)) padding-box,conic-gradient(from var(--pn-spin,0deg),var(--wl-ink) 0 70%,rgb(var(--pn-accent)) 80%,#f59e0b 90%,var(--wl-ink) 100%) border-box;animation:pn-spin 1.2s linear infinite}
@keyframes pn-spin{to{--pn-spin:360deg}}
.pn-fx-conic-tile{border:2px solid transparent;background:linear-gradient(var(--tile-bg),var(--tile-bg)) padding-box,linear-gradient(var(--wl-line),var(--wl-line)) border-box}
.pn-fx-conic-tile:hover{background:linear-gradient(var(--tile-bg),var(--tile-bg)) padding-box,conic-gradient(from var(--pn-spin,0deg),var(--wl-line) 0 68%,rgb(var(--pn-accent)) 80%,#f59e0b 90%,var(--wl-line) 100%) border-box;animation:pn-spin 1.2s linear infinite}
.pn-fx-conic-tile{--tile-bg:var(--tile-bg-l,var(--wl-card))}
.pn-fx-popmix>span{transform:translate(-2px,-2px);box-shadow:3px 3px 0 var(--wl-chip-border);transition:transform .12s ease,box-shadow .12s ease}
.pn-fx-popmix>span:hover{transform:translate(0,0);box-shadow:none}
.pn-fx-amber{background:#f59e0b;border-color:#f59e0b;color:#1c1917;transition:background-color .15s ease,color .15s ease}
.pn-fx-amber:hover{background:transparent;color:var(--wl-amber-text)}
.pn-fx-straighten{transition:transform .25s cubic-bezier(.34,1.56,.64,1),box-shadow .25s ease}
.pn-fx-straighten:hover{transform:rotate(0deg) scale(1.04);z-index:10;box-shadow:0 16px 32px rgba(0,0,0,.14)}
.pn-fx-lift{transition:transform .2s ease,box-shadow .2s ease}
.pn-fx-lift:hover{transform:translateY(-6px);box-shadow:0 14px 28px rgba(0,0,0,.12)}
.pn-fx-track{transition:letter-spacing .2s ease,padding .2s ease}
.pn-fx-track:hover{letter-spacing:.14em;padding-left:1.1rem;padding-right:1.1rem}
.pn-fx-navlink{position:relative}
.pn-fx-navlink::after{content:"";position:absolute;left:0;bottom:-2px;height:2px;width:0;background:var(--pn-fx-underline,rgb(var(--pn-accent)));transition:width .2s ease}
.pn-fx-navlink:hover::after{width:100%}
.pn-fx-shake:hover{animation:pn-headshake .4s ease;background:#fef2f2;border-color:#dc2626;color:#dc2626}
@keyframes pn-headshake{0%,100%{transform:translateX(0)}25%{transform:translateX(-5px)}50%{transform:translateX(5px)}75%{transform:translateX(-3px)}}
.pn-fx-slab{transition:transform .15s ease,box-shadow .15s ease}
.pn-fx-slab:hover{transform:translate(-4px,-4px);box-shadow:6px 6px 0 var(--wl-ink)}
.pn-fx-scan{position:relative;overflow:hidden;transition:border-color .2s}
.pn-fx-scan::before{content:"";position:absolute;inset:0;opacity:0;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(10,10,10,.05) 0 2px,transparent 2px 4px);transition:opacity .2s}
.pn-fx-scan::after{content:"";position:absolute;left:0;right:0;height:30px;top:-30px;opacity:0;background:linear-gradient(to bottom,transparent,rgba(16,185,129,.18),transparent);pointer-events:none}
.pn-fx-scan:hover{border-color:var(--wl-emerald)}
.pn-fx-scan:hover::before{opacity:1}
.pn-fx-scan:hover::after{opacity:1;animation:pn-scanline 1.4s linear infinite}
@keyframes pn-scanline{to{top:100%}}
.pn-fx-stamp{position:relative}
.pn-fx-stamp::after{content:attr(data-stamp);position:absolute;top:14px;right:14px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;font-weight:800;letter-spacing:.1em;white-space:nowrap;color:#dc2626;border:2px solid currentColor;padding:2px 8px;border-radius:4px;transform:rotate(8deg) scale(3);opacity:0;pointer-events:none;transition:transform .18s cubic-bezier(.34,1.56,.64,1),opacity .12s}
.pn-fx-stamp:hover::after{transform:rotate(-6deg) scale(1);opacity:1}
.pn-fx-stamp-bright::after{color:#ef4444}
.pn-fx-invert{transition:background-color .2s ease,box-shadow .2s ease}
.pn-fx-invert>div,.pn-fx-invert>p,.pn-fx-invert>svg{transition:color .2s ease}
.pn-fx-invert:hover{background:var(--wl-card);box-shadow:inset 0 0 0 2px var(--wl-ink)}
.pn-fx-invert:hover>div{color:var(--wl-ink)}
.pn-fx-invert:hover>p{color:var(--wl-sub)}
.pn-fx-invert:hover>svg{color:rgb(var(--pn-accent))}
.pn-fx-grid{position:relative;transition:background-color .25s ease}
.pn-fx-grid>*{position:relative}
.pn-fx-grid::before{content:"";position:absolute;inset:0;border-radius:14px;pointer-events:none;background-image:linear-gradient(var(--wl-grid-line) 1px,transparent 1px),linear-gradient(90deg,var(--wl-grid-line) 1px,transparent 1px);background-size:20px 20px;transition:opacity .25s ease}
.pn-fx-grid:hover{background-color:var(--wl-card)}
.pn-fx-grid:hover::before{opacity:0}
.pn-fx-meter-fill{width:32%}
.pn-fx-meter-readout::before{content:"160"}
@media (hover:hover) and (pointer:fine){
.pn-fx-meter-fill{transition:width .45s cubic-bezier(.22,1,.36,1)}
.pn-fx-meter:hover .pn-fx-meter-fill{width:82.4%}
.pn-fx-meter:hover .pn-fx-meter-readout::before{content:"412"}
}
.pn-fx-draw{position:relative}
.pn-fx-draw-rect{position:absolute;inset:-2px;width:calc(100% + 4px);height:calc(100% + 4px);pointer-events:none}
.pn-fx-draw-rect rect{x:1.5px;y:1.5px;width:calc(100% - 3px);height:calc(100% - 3px);rx:16px;fill:none;stroke:rgb(var(--pn-accent));stroke-width:3;stroke-dasharray:1200;stroke-dashoffset:1200;transition:stroke-dashoffset .6s ease}
.pn-fx-draw:hover .pn-fx-draw-rect rect{stroke-dashoffset:0}
.pn-fx-ants{border:2px solid transparent;background:linear-gradient(var(--tile-bg,var(--wl-tint-amber)),var(--tile-bg,var(--wl-tint-amber))) padding-box,repeating-linear-gradient(45deg,#f59e0b 0 8px,transparent 8px 16px) border-box}
.pn-fx-ants:hover{animation:pn-ants .5s linear infinite}
.pn-fx-ribbon{position:relative;overflow:hidden}
.pn-fx-ribbon::before{content:"";position:absolute;top:-2px;inset-inline-end:26px;width:22px;height:40px;background:rgb(var(--pn-accent));clip-path:polygon(0 0,100% 0,100% 100%,50% 74%,0 100%);transition:top .3s cubic-bezier(.34,1.56,.64,1)}
.pn-fx-ribbon:hover::before{top:-44px}
@keyframes pn-ants{to{background-position:0 0,22.6px 0}}
.pn-fx-type:hover .pn-fx-icons svg{animation:pn-icon-type .12s ease both}
.pn-fx-type:hover .pn-fx-icons svg:nth-child(1){animation-delay:.08s}
.pn-fx-type:hover .pn-fx-icons svg:nth-child(2){animation-delay:.32s}
.pn-fx-type:hover .pn-fx-icons svg:nth-child(3){animation-delay:.56s}
.pn-fx-type:hover .pn-fx-icons svg:nth-child(4){animation-delay:.8s}
@keyframes pn-icon-type{from{opacity:0}to{opacity:1}}
.pn-fx-arrow::after{content:"\\2192";width:0;overflow:hidden;display:inline-block;transition:width .2s ease}
.pn-fx-arrow:hover::after{width:1.1em}
.pn-sticky{animation:pn-sticky-in .22s ease}
@keyframes pn-sticky-in{from{transform:translateY(-100%)}to{transform:translateY(0)}}
/* Touch devices: iOS synthesizes :hover on tap and then HOLDS it until you
   tap elsewhere, so every infinite hover animation here keeps running after a
   tap - the conic border spins forever behind the App button people actually
   press. Park the looping ones where there is no real pointer. The static
   halves of those rules (the gradient, the scanlines) stay; they cost one
   paint, not a frame budget. */
@media (hover:none){.pn-fx-conic-btn:hover,.group:hover .pn-fx-conic-btn,.pn-fx-conic-tile:hover,.pn-fx-scan:hover::after,.pn-fx-ants:hover{animation:none!important}}
@media (prefers-reduced-motion:reduce){.pn-sticky,.pn-fx-conic-btn,.pn-fx-conic-tile,.pn-fx-popmix>span,.pn-fx-shake:hover,.pn-fx-slab,.pn-fx-scan:hover::after,.pn-fx-stamp::after,.pn-fx-type:hover .pn-fx-icons svg,.pn-fx-ants:hover,.pn-fx-meter-fill{animation:none!important;transition:none!important}}
`;

export function LandingPage({
  children,
  onAuthedEnterApp,
}: {
  children: ReactNode;
  onAuthedEnterApp?: () => void;
}) {
  const { t } = useTranslation('landing');
  const { auth } = useAuth();
  // Drives the live-demo shot below, which ships as a light and a dark
  // capture. Read here rather than through a CSS class pair so only the
  // one in view downloads; initTheme() paints before React mounts, so the
  // first render already picks the right file and there is no swap.
  const { theme } = useTheme();
  // Native apps open straight on the auth card (no marketing page), and so
  // does the dedicated app host: marketing lives on the apex, so a signed-out
  // visitor who reached use.privacynotes.app came for the app, not for the
  // pitch. That is also what makes an apex CTA land without a marketing
  // flash - the card is the first paint, no fragment needed. Web on the apex
  // still starts on the marketing homepage until the visitor picks an intent.
  // Spec: ops/docs/domain-split.md (apex is marketing-only, a signed-in visitor there sees MoveScreen)
  const [authIntent, setAuthIntent] = useState<'create' | 'login' | null>(
    IS_DESKTOP || isAppHost() ? 'login' : null,
  );

  // Announcement ribbon dismissal (backlog #175): per browser, because the
  // apex visitor has no account. Read synchronously in the initializer so
  // the bar is part of the first paint and never appears after it.
  const [dismissedAnnouncements, setDismissedAnnouncements] =
    useState<string[]>(siteDismissedIds);

  // The Linux download tile is a click-to-reveal disclosure (two Linux formats)
  // rather than a single direct download. Collapsed by default.
  const [linuxOpen, setLinuxOpen] = useState(false);
  const [androidOpen, setAndroidOpen] = useState(false);
  const [pkgOpen, setPkgOpen] = useState(false);

  // Detected architecture first, and the other one behind a toggle. When detection
  // returns null both groups render and the toggle never appears, which is the panel
  // as it was before. `linuxArchShown` drives the artifact rows AND the apt footnote
  // together, so opening the toggle can never leave the two halves disagreeing.
  const linuxArch = useLinuxArch();
  const [linuxOtherArch, setLinuxOtherArch] = useState(false);
  const linuxPrimaryArch: LinuxArch = linuxArch === 'aarch64' ? 'aarch64' : 'x86_64';
  const linuxSecondArch: LinuxArch = linuxArch === 'aarch64' ? 'x86_64' : 'aarch64';
  const linuxArchShown: LinuxArch[] = linuxArch === null || linuxOtherArch
    ? [linuxPrimaryArch, linuxSecondArch]
    : [linuxPrimaryArch];

  // Mobile nav overlay (below lg, where the inline nav links are hidden) and
  // the compact sticky header that appears once the top header scrolls away.
  const [navOpen, setNavOpen] = useState(false);
  const [pastHero, setPastHero] = useState(false);
  const headerRef = useRef<HTMLElement>(null);

  // The marketing homepage AND the auth card are both brand surfaces
  // designed for the default (white) palette. A visitor may have a tinted
  // color theme (Cream, Slate) saved from the app - or picked while
  // trying the demo - so force the default for as long as this component
  // owns the screen, and restore their choice when the app takes over on
  // unmount. previewColorTheme applies the class without persisting, so
  // the stored preference survives untouched.
  //
  // Scope is the whole component, not just the homepage: this renders the
  // auth card too (as the shell around the onboarding steps), and the card
  // is the one screen a returning user sees before the app, so a Cream
  // wash there reads as the app leaking onto the sign-in page. Every
  // platform, including native and the app host, where this component
  // opens straight on the card and there is no homepage at all.
  // Light/dark is deliberately NOT forced here - the card adapts to the
  // stored mode (see openAuth and Onboarding) so it feels familiar.
  useEffect(() => {
    previewColorTheme('default');
    return () => previewColorTheme(getStoredColorTheme());
  }, []);

  // Capture ?ref= (or an allowlisted referring site) into sessionStorage
  // and strip it from the address bar. Runs on the apex, where the
  // arrival happens, and on the app host, where the handoff lands it.
  // First touch wins, so a re-mount cannot overwrite the arrival.
  // Spec: ops/docs/plans/partner-attribution.md (referrer resolved server-side in the Worker, never sent raw from the browser)
  useEffect(() => {
    captureSource();
  }, []);

  // The public marketing + auth pages carry no dense editor inputs, so allow
  // pinch-zoom for accessibility. A locked viewport (user-scalable=no) is a
  // Lighthouse a11y failure. The gated app keeps the restrictive viewport from
  // index.html that blocks iOS auto-zoom on the editor; we restore it on
  // unmount, when the authenticated app takes over.
  useEffect(() => {
    const vp = document.querySelector('meta[name="viewport"]');
    if (!vp) return;
    const restrictive = vp.getAttribute('content');
    vp.setAttribute('content', 'width=device-width, initial-scale=1, viewport-fit=cover');
    return () => {
      if (restrictive) vp.setAttribute('content', restrictive);
    };
  }, []);

  // Mobile nav overlay: lock page scroll while open, close on Escape.
  useEffect(() => {
    if (!navOpen) return;
    const prevOverflow = document.documentElement.style.overflow;
    document.documentElement.style.overflow = 'hidden';
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setNavOpen(false);
    };
    window.addEventListener('keydown', onKey);
    return () => {
      document.documentElement.style.overflow = prevOverflow;
      window.removeEventListener('keydown', onKey);
    };
  }, [navOpen]);

  // Show the sticky bar only after the real header has scrolled off the
  // top, so the two are never on screen together.
  useEffect(() => {
    if (authIntent !== null) return;
    const el = headerRef.current;
    if (!el || typeof IntersectionObserver === 'undefined') return;
    const io = new IntersectionObserver(([entry]) => {
      setPastHero(!entry!.isIntersecting && entry!.boundingClientRect.top < 0);
    });
    io.observe(el);
    return () => io.disconnect();
  }, [authIntent]);

  const platformVersions = usePlatformVersions(!IS_DESKTOP && !isAppHost());

  // Deep links to a section (e.g. /en#downloads from the in-app Downloads
  // button) land at the top on a fresh load: the target is client-rendered,
  // so the browser's initial hash scroll finds nothing. Re-run it once the
  // marketing content is on screen.
  useEffect(() => {
    if (authIntent !== null) return;
    const id = window.location.hash.slice(1);
    if (!id) return;
    const raf = requestAnimationFrame(() => {
      document.getElementById(id)?.scrollIntoView();
    });
    return () => cancelAnimationFrame(raf);
  }, [authIntent]);

  function openAuth(intent: 'create' | 'login') {
    // Already signed in (a returning visitor browsing this marketing page on a
    // locale-slug URL): go straight to the app instead of a redundant sign-in
    // form. Only wired on slug URLs, where App passes the handler; a fresh
    // visitor here isn't authenticated, so a real sign-in is never blocked.
    if (
      onAuthedEnterApp &&
      (auth.status === 'authenticated' || auth.status === 'device_limit_reached')
    ) {
      onAuthedEnterApp();
      return;
    }
    // Cutover (permanent since the 2026-08-25 apex retirement): new
    // sessions belong to the app host. On the apex marketing page, hand
    // the visitor to use.privacynotes.app instead of opening the auth
    // card here. No intent travels with them: onboarding is one unified
    // flow, so the app host's own auth card serves create and sign-in
    // alike. Signed-in visitors keep the in-place paths (the MoveScreen
    // owns their migration, with its sync gate); demo, native,
    // localhost, and the app host itself are untouched.
    // Spec: ops/docs/domain-split.md (no feature flag: rollback means reverting the retirement commit)
    if (
      isApexHost() &&
      !isDemoMode() &&
      detectPlatform() === 'web' &&
      auth.status !== 'authenticated' &&
      auth.status !== 'device_limit_reached'
    ) {
      window.location.href = withSource(APP_ORIGIN);
      return;
    }
    setAuthIntent(intent);
    // Adapt to the user's system (or stored) light/dark preference the
    // moment they commit to signing up, so the app feels familiar right
    // away. The landing page itself stays forced-light (see Onboarding).
    applyStoredTheme();
    window.scrollTo(0, 0);
  }

  function closeAuth() {
    // Native builds never render the marketing page: app builds strip its
    // assets (pn-strip-marketing-assets in vite.config.ts), so the homepage
    // would render with a 404'd screenshot, download tiles for the app you
    // are already running, and locale-slug navigation the bundle cannot
    // serve. Hand the visitor to the website in the system browser instead.
    // The header below never calls closeAuth on native, so this branch is
    // defense in depth for any future caller.
    if (IS_DESKTOP) {
      // openExternal keeps the iOS in-app browser sheet behaviour in one
      // place (App.tsx interceptor + openExternal.ts, guideline 4).
      openExternal(marketingHomeHref());
      return;
    }
    // On the app host there is nothing to go back TO: the marketing page
    // lives on the apex, and worker.ts 301s every other marketing path off
    // this origin already. Leave for it in the visitor's language rather
    // than revealing a second copy of the homepage on the wrong domain.
    if (isAppHost()) {
      window.location.href = marketingHomeHref();
      return;
    }
    setAuthIntent(null);
    // Back to the marketing page. It follows the stored/system mode like
    // the rest of the app; the header ThemeToggle pins an explicit choice.
    applyStoredTheme();
    window.scrollTo(0, 0);
  }

  // Overlay links scroll after the overlay unmounts and its scroll lock
  // lifts; a plain href="#..." would try to jump while the page can't move.
  function goToSection(id: string) {
    setNavOpen(false);
    requestAnimationFrame(() => {
      document.getElementById(id)?.scrollIntoView();
    });
  }

  if (authIntent) {
    // Web only: the header Back (and the logo) exit the auth card to the
    // marketing page, and closeAuth handles the app-host redirect. Native
    // never renders the marketing page in-app, so there is nothing to exit
    // to; every onboarding step past the first carries its own back
    // control inside the card, which is the one a thumb reaches anyway.
    const headerBack = IS_DESKTOP ? undefined : closeAuth;
    const logoInner = (
      <>
        <LogoIcon size={44} className="shrink-0 text-accent" />
        <span className="truncate text-2xl tracking-tight"><Brand /></span>
      </>
    );
    return (
      <div className="pn-washi min-h-screen bg-[var(--wl-bg)] text-[var(--wl-ink)]">
        {/* The auth view wears the same washi shell as the marketing page
            (this style tag carries the --wl-* variables), so the handoff
            between the two is seamless in both modes. The onboarding steps
            inside the card keep the app's own surfaces. */}
        <style>{FX_CSS}</style>
        <div className="mx-auto max-w-3xl px-5 sm:px-8 pt-[calc(env(safe-area-inset-top)+1rem)] sm:pt-14 pb-16">
          {/* Brand on the left, exactly one control on the right: the Back
              exit on the web, the language icon on native. The website link,
              the language selector and the theme toggle all rode this row
              until those four controls at 375px pushed the wordmark
              underneath them. min-w-0 + truncate + shrink-0 are the backstop
              for the narrowest phones, same as the landing header. */}
          <div className="flex items-center justify-between gap-3 mb-8">
            {headerBack ? (
              <button type="button" onClick={headerBack} className="flex min-w-0 cursor-pointer items-center gap-3">
                {logoInner}
              </button>
            ) : (
              <div className="flex min-w-0 items-center gap-3">{logoInner}</div>
            )}
            {headerBack ? (
              <button
                type="button"
                onClick={headerBack}
                className="inline-flex shrink-0 cursor-pointer items-center gap-1.5 text-sm text-[var(--wl-sub)] hover:text-[var(--wl-ink)] transition"
              >
                {/* The icon, not a bare &larr;: it is the one arrow in this
                    file that has to mirror for Arabic, and icons.tsx does
                    that for every ArrowLeft call site. */}
                <ArrowLeft size={14} aria-hidden="true" /> {t('common:actions.back')}
              </button>
            ) : (
              /* Native opens straight on this card, so it is the only
                 screen before sign-in and the only place to correct a
                 wrong language guess. In-place switch, no `navigate`: a
                 slug navigation would drop the visitor out of the auth
                 flow. Detection already picked the browser language; this
                 is the override. */
              <span className="shrink-0">
                <LanguageMenu iconOnly compact />
              </span>
            )}
          </div>
          <div className="rounded-2xl border border-[var(--wl-line)] bg-[var(--wl-card)] shadow-sm p-5 sm:p-6">
            {children}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="pn-washi min-h-screen bg-[var(--wl-bg)] text-[var(--wl-ink)] overflow-x-clip">
      <style>{'@keyframes pn-marquee{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}.pn-marquee{animation:pn-marquee 40s linear infinite}@media (prefers-reduced-motion:reduce){.pn-marquee{animation:none}}'}</style>
      <style>{FX_CSS}</style>

      <AnnouncementBanner
        surface="site"
        dismissedIds={dismissedAnnouncements}
        onDismiss={(id) => {
          dismissOnSite(id);
          setDismissedAnnouncements((prev) => [...prev, id]);
        }}
      />

      {/* Top padding grows only at lg, where the language utility row
          needs the room; below lg the selector is a header-row icon and
          the old sm:pt-14 was dead space above the brand. */}
      <div className="relative mx-auto max-w-5xl px-5 sm:px-8 pt-[calc(env(safe-area-inset-top)+0.75rem)] sm:pt-6 lg:pt-14">
        {/* Language utility row, top-right of the page. The row carries no
            margin of its own: below lg the selector lives in the header row
            instead, and a row-level margin would reserve a blank strip
            where nothing renders. Each child brings its own margin. */}
        <div className="flex items-center justify-end gap-2">
          <LanguageSuggest className="mb-3 sm:mb-4" />
          <span className="mb-3 hidden sm:mb-4 lg:block">
            <LanguageMenu navigate />
          </span>
        </div>
        {/* Top brand row. Mirrored in plain HTML+CSS by landingHeader() in
            ../landing-pages.ts for the static SEO landing pages (same deal as
            SiteFooter.tsx / static-page-chrome.ts): presentation cannot be
            shared because the static pages ship no React/Tailwind and the two
            auth buttons here are JS - change the structure, links or CTAs
            here and update the twin in the same commit. */}
        <header ref={headerRef} className="flex items-center justify-between gap-x-3 sm:gap-x-6 mb-10 sm:mb-16">
          {/* Below sm the brand steps down a size: this row now carries the App
              pill at every width, and the poster-sized wordmark plus four
              controls do not fit a 375px line. min-w-0 + truncate + shrink-0
              are the backstop for the narrowest phones, same as the sticky
              bar. */}
          <div className="flex min-w-0 items-center gap-2 sm:gap-3">
            <LogoIcon size={64} className="shrink-0 text-accent w-8 h-8 sm:w-16 sm:h-16" />
            <h1 className="truncate text-lg sm:text-4xl tracking-tight">
              <Brand />
            </h1>
          </div>
          <nav className="flex shrink-0 items-center gap-2 sm:gap-3 lg:gap-4 text-sm text-[var(--wl-sub)]">
            {/* Priority ladder (most important first): App and language
                always, toggle from sm, demo from md, Downloads and Help
                from 896px, Changelog at lg - where the hamburger that
                also carries them disappears, so nothing gates past lg.
                The 896px step is deliberate: at plain md the long locales
                (fr measures ~900px of content at 768) overflow, while
                waiting for lg wastes a third of the row. There is no Log
                in button: the App pill opens the same auth card, and the
                hero microcopy keeps an explicit log-in link. Width
                budget: ui-patterns.md section 49. */}
            <a href="https://try.privacynotes.app/" className="pn-fx-navlink hidden md:inline hover:text-accent transition">{t('hero.tryDemo')}</a>
            <a href="#downloads" className="pn-fx-navlink hidden min-[896px]:inline hover:text-accent transition">{t('header.downloads')}</a>
            <a href={helpPath(activeLocale())} className="pn-fx-navlink hidden min-[896px]:inline hover:text-accent transition">{t('header.help')}</a>
            <a href="/changelog" className="pn-fx-navlink hidden lg:inline hover:text-accent transition">{t('header.changelog')}</a>
              <a href="/roadmap" className="pn-fx-navlink hidden lg:inline hover:text-accent transition">{t('header.roadmap')}</a>
            <span className="hidden sm:block">
              <ThemeToggle compact />
            </span>
            {/* Same label and the same always-on rule as the sticky bar's
                CTA below: the two headers swap over on scroll, so a button
                that only one of them carries reads as the page losing it.
                "App" is a deliberate literal, not a locale key - see the
                sticky bar for why. */}
            <button
              type="button"
              onClick={() => openAuth('create')}
              className="pn-fx-conic-btn cursor-pointer whitespace-nowrap inline-flex items-center justify-center rounded-full bg-[var(--wl-ink)] text-[var(--wl-bg)] px-4 py-1.5 text-sm font-semibold"
            >
              App
            </button>
            {/* Below lg the language selector rides the header row as an
                icon; the lg+ utility row above is hidden at these widths. */}
            <span className="lg:hidden">
              <LanguageMenu navigate iconOnly />
            </span>
            <button
              type="button"
              onClick={() => setNavOpen(true)}
              aria-label={t('header.menuLabel')}
              aria-expanded={navOpen}
              className="lg:hidden cursor-pointer inline-flex h-10 w-10 items-center justify-center rounded-full border-[1.5px] border-[var(--wl-ink)] text-[var(--wl-ink)]"
            >
              <List size={20} />
            </button>
          </nav>
        </header>

        {/* Mobile nav overlay: the only path to Roadmap, Help and Changelog
            below lg, where the inline header links are hidden. */}
        {navOpen && (
          <div
            role="dialog"
            aria-modal="true"
            aria-label={t('header.menuLabel')}
            className="fixed inset-0 z-[70] overflow-y-auto bg-[var(--wl-bg)] lg:hidden"
          >
            <div className="mx-auto flex min-h-full max-w-5xl flex-col px-5 sm:px-8 pt-[calc(env(safe-area-inset-top)+0.75rem)] pb-10">
              <div className="mb-10 flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <LogoIcon size={40} className="text-accent" />
                  <span className="text-xl tracking-tight text-[var(--wl-ink)]">
                    <Brand />
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setNavOpen(false)}
                  aria-label={t('header.closeMenu')}
                  className="inline-flex h-10 w-10 cursor-pointer items-center justify-center rounded-full border-[1.5px] border-[var(--wl-ink)] text-[var(--wl-ink)]"
                >
                  <X size={20} />
                </button>
              </div>
              <nav className="flex flex-col text-3xl font-black tracking-tight text-[var(--wl-ink)]">
                <button type="button" onClick={() => goToSection('downloads')} className="cursor-pointer border-b border-[var(--wl-line)] py-4 text-start">
                  {t('header.downloads')}
                </button>
                <a href={helpPath(activeLocale())} className="border-b border-[var(--wl-line)] py-4">
                  {t('header.help')}
                </a>
                {/* Help, Changelog, Roadmap run in the order the inline
                    header puts them in, so the two navs read as one menu at
                    the width where they swap over. Pricing has no inline
                    counterpart and keeps its place. The last row carries no
                    rule, so the divider moves with the order. */}
                <a href="/changelog" className="border-b border-[var(--wl-line)] py-4">
                  {t('header.changelog')}
                </a>
                <a href="/roadmap" className="py-4">
                  {t('header.roadmap')}
                </a>
              </nav>
              <div className="mt-auto space-y-3 pt-10">
                {/* One auth button, not a create/log-in pair: the auth card
                    behind it is one unified flow, so a second button was a
                    choice with no consequence. Same story as the header's
                    App pill. */}
                <button
                  type="button"
                  onClick={() => { setNavOpen(false); openAuth('create'); }}
                  className="pn-fx-conic-btn cursor-pointer w-full rounded-full bg-[var(--wl-ink)] py-3.5 text-base font-bold text-[var(--wl-bg)]"
                >
                  {t('header.openApp')}
                </button>
                <a
                  href="https://try.privacynotes.app/"
                  className="pn-fx-amber flex w-full cursor-pointer items-center justify-center gap-2 rounded-full border-2 border-[var(--wl-amber-border)] py-3 text-base font-bold text-[var(--wl-amber-text)] transition"
                >
                  {t('hero.tryDemo')}
                  <ArrowUpRight size={16} className="shrink-0" aria-hidden="true" />
                </a>
                <div className="flex items-center justify-center gap-3 pt-3">
                  <ThemeToggle />
                  <LanguageMenu dropUp navigate />
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Compact sticky header: keeps nav + the primary CTA reachable on a
          page this tall. Rendered only after the top header scrolls out. */}
      {pastHero && (
        <div className="pn-sticky fixed inset-x-0 top-0 z-50 border-b border-[var(--wl-line)] bg-[var(--wl-bg)]/90 backdrop-blur">
          <div className="mx-auto flex h-14 max-w-5xl items-center justify-between gap-3 px-5 sm:px-8">
            {/* min-w-0 + truncate on the wordmark, shrink-0 on the actions: this
                row has no room to spare below lg, so the logo gives way first
                instead of the two sides overlapping. */}
            <button type="button" onClick={() => window.scrollTo({ top: 0 })} className="flex min-w-0 cursor-pointer items-center gap-2">
              <LogoIcon size={28} className="shrink-0 text-accent" />
              <span className="truncate text-base tracking-tight text-[var(--wl-ink)]">
                <Brand />
              </span>
            </button>
            <div className="flex shrink-0 items-center gap-3 lg:gap-4 text-sm text-[var(--wl-sub)]">
              <a href="https://try.privacynotes.app/" className="pn-fx-navlink hidden md:inline hover:text-accent transition">{t('hero.tryDemo')}</a>
              <a href="#downloads" className="pn-fx-navlink hidden min-[896px]:inline hover:text-accent transition">{t('header.downloads')}</a>
              <a href={helpPath(activeLocale())} className="pn-fx-navlink hidden min-[896px]:inline hover:text-accent transition">{t('header.help')}</a>
              <a href="/changelog" className="pn-fx-navlink hidden lg:inline hover:text-accent transition">{t('header.changelog')}</a>
              <a href="/roadmap" className="pn-fx-navlink hidden lg:inline hover:text-accent transition">{t('header.roadmap')}</a>
              <span className="hidden sm:block">
                <ThemeToggle compact />
              </span>
              {/* "App", not the full "Create your vault" the page's other CTAs
                  carry, and deliberately NOT a locale key: this bar keeps the
                  logo, a language button and the menu on one 375px row, and a
                  translated label there is what pushed this CTA over the
                  wordmark. The word is a short loan word in every catalog we
                  ship, so one literal serves all of them. The top brand row
                  carries the twin of this button. */}
              <button
                type="button"
                onClick={() => openAuth('create')}
                className="pn-fx-conic-btn cursor-pointer whitespace-nowrap rounded-full bg-[var(--wl-ink)] text-[var(--wl-bg)] px-4 py-1.5 text-sm font-semibold"
              >
                App
              </button>
              {/* The sticky bar carries the language icon at every width:
                  below lg it mirrors the top header's icon, and at lg+ it
                  stands in for the utility-row selector that scrolled away. */}
              <span>
                <LanguageMenu navigate iconOnly compact />
              </span>
              <button
                type="button"
                onClick={() => setNavOpen(true)}
                aria-label={t('header.menuLabel')}
                aria-expanded={navOpen}
                className="lg:hidden cursor-pointer inline-flex h-9 w-9 items-center justify-center rounded-full border-[1.5px] border-[var(--wl-ink)] text-[var(--wl-ink)]"
              >
                <List size={18} />
              </button>
            </div>
          </div>
        </div>
      )}

      <main>
        <div className="relative mx-auto max-w-5xl px-5 sm:px-8 pb-10 sm:pb-14">
        {/* ── Hero (poster, two-column) ───────────────────────── */}
        <div className="relative grid lg:grid-cols-[minmax(0,1fr)_360px] gap-12 items-center mb-12 sm:mb-16">
        {/* Below lg the card column (and its asanoha patch) is hidden, so
            this twin keeps the motif on phones and tablets: same pattern,
            bleeding off the top end corner behind the hero text. Own ids
            (-sm): the lg instance sits in a display:none subtree at these
            widths, and pattern/mask refs into hidden defs are unreliable. */}
        <svg
          viewBox="0 0 240 240"
          className="pointer-events-none absolute -top-16 -end-24 h-[380px] w-[380px] text-accent opacity-[0.11] dark:opacity-[0.15] lg:hidden"
          fill="none"
          aria-hidden="true"
        >
          <defs>
            <pattern id="pn-asanoha-sm" width="40" height="46" patternUnits="userSpaceOnUse">
              <g stroke="currentColor" strokeWidth="1.4">
                <path d="M20 0 L20 23 M20 23 L0 11.5 M20 23 L40 11.5 M20 23 L0 34.5 M20 23 L40 34.5 M20 23 L20 46" />
                <path d="M0 11.5 L20 0 L40 11.5 M0 34.5 L20 46 L40 34.5 M0 11.5 L0 34.5 M40 11.5 L40 34.5" />
              </g>
            </pattern>
            <radialGradient id="pn-asanoha-sm-fade">
              <stop offset="45%" stopColor="#fff" />
              <stop offset="100%" stopColor="#fff" stopOpacity="0" />
            </radialGradient>
            <mask id="pn-asanoha-sm-mask">
              <circle cx="120" cy="120" r="120" fill="url(#pn-asanoha-sm-fade)" />
            </mask>
          </defs>
          <rect width="240" height="240" fill="url(#pn-asanoha-sm)" mask="url(#pn-asanoha-sm-mask)" />
        </svg>
        <div className="max-w-3xl">
          <a
            href="https://github.com/LifetimeLabsDev/PrivacyNotes.app"
            target="_blank"
            rel="noopener noreferrer"
            className="pn-fx-track inline-flex items-center gap-2 rounded-full border border-[var(--wl-emerald)]/40 bg-[var(--wl-tint-green)] px-3 py-1 text-[11px] font-bold text-[var(--wl-emerald)] uppercase tracking-[0.08em] hover:bg-[var(--wl-emerald)]/15 transition mb-6"
          >
            <Lock size={12} className="shrink-0" />
            {t('hero.badge')}
          </a>
          <h2 className="text-5xl sm:text-7xl lg:text-6xl font-black tracking-tight leading-[0.95] text-[var(--wl-ink)]">
            <Trans
              i18nKey="landing:hero.headline"
              components={{
                br: <br />,
                stroke: (
                  <span
                    className="block mt-1.5 leading-[1.05]"
                    style={{
                      WebkitTextStroke: '2.5px rgb(var(--pn-accent))',
                      color: 'var(--wl-bg)',
                      paintOrder: 'stroke',
                    }}
                  />
                ),
              }}
            />
          </h2>
          <p className="mt-6 text-lg sm:text-xl text-[var(--wl-sub)] leading-relaxed max-w-xl">
            {t('hero.subhead')}
          </p>
          <div className="mt-8 grid grid-cols-2 sm:flex sm:flex-wrap items-center gap-2 sm:gap-3">
            <button
              type="button"
              onClick={() => openAuth('create')}
              className="pn-fx-conic-btn cursor-pointer rounded-full bg-[var(--wl-ink)] text-[var(--wl-bg)] px-3 sm:px-7 py-3.5 text-sm sm:text-base font-bold"
            >
              {t('header.createVault')}
            </button>
            <a
              href="https://try.privacynotes.app/"
              className="pn-fx-amber inline-flex items-center justify-center gap-2 rounded-full border-2 border-[var(--wl-amber-border)] text-[var(--wl-amber-text)] px-3 sm:px-6 py-3 text-sm sm:text-base font-bold transition"
            >
              {t('hero.tryDemo')}
              <ArrowUpRight size={16} className="shrink-0" aria-hidden="true" />
            </a>
          </div>
          <p className="mt-3 text-xs text-[var(--wl-muted)]">
            {t('hero.microcopy')}
            {' '}
            <button
              type="button"
              onClick={() => openAuth('login')}
              className="cursor-pointer text-accent font-semibold underline hover:no-underline"
            >
              {t('hero.alreadyHaveVault')}
            </button>
          </p>
          {/* Trust chip: release-integrity proof at the moment of the first
              decision. Deliberately just this one - the PrivacyTools badge
              and the nosubscription.org badge keep their own sections. */}
          <div className="mt-6 flex flex-wrap items-center gap-2">
            <a
              href={GITHUB_RELEASES_URL}
              target="_blank"
              rel="noopener"
              className="pn-fx-arrow inline-flex items-center gap-1.5 rounded-full border border-[var(--wl-line)] bg-[var(--wl-card)]/70 px-3 py-1.5 text-xs font-semibold text-[var(--wl-sub)] hover:text-[var(--wl-ink)] transition"
            >
              <GithubLogo size={14} weight="fill" className="shrink-0" aria-hidden="true" />
              {t('hero.trustSigned')}
            </a>
          </div>
        </div>

        {/* Hero visual: tilted product-shaped cards, pure CSS */}
        <div className="relative hidden lg:block h-[480px]" aria-hidden="true">
          {/* Asanoha (hemp leaf) patch in faint brand blue: the washi
              pattern behind the tilted cards, replacing the old sparkle
              glyph. Inline SVG, about 1 KB; the radial mask dissolves the
              edges so it reads as a watermark, not a tile. */}
          <svg
            viewBox="0 0 240 240"
            className="pointer-events-none absolute -top-10 -start-16 h-[560px] w-[560px] text-accent opacity-[0.13] dark:opacity-[0.17]"
            fill="none"
          >
            <defs>
              <pattern id="pn-asanoha" width="40" height="46" patternUnits="userSpaceOnUse">
                <g stroke="currentColor" strokeWidth="1.4">
                  <path d="M20 0 L20 23 M20 23 L0 11.5 M20 23 L40 11.5 M20 23 L0 34.5 M20 23 L40 34.5 M20 23 L20 46" />
                  <path d="M0 11.5 L20 0 L40 11.5 M0 34.5 L20 46 L40 34.5 M0 11.5 L0 34.5 M40 11.5 L40 34.5" />
                </g>
              </pattern>
              <radialGradient id="pn-asanoha-fade">
                <stop offset="45%" stopColor="#fff" />
                <stop offset="100%" stopColor="#fff" stopOpacity="0" />
              </radialGradient>
              <mask id="pn-asanoha-mask">
                <circle cx="120" cy="120" r="120" fill="url(#pn-asanoha-fade)" />
              </mask>
            </defs>
            <rect width="240" height="240" fill="url(#pn-asanoha)" mask="url(#pn-asanoha-mask)" />
          </svg>
          {/* Vault card */}
          <div className="pn-fx-straighten absolute top-4 end-0 w-60 rotate-3 rounded-2xl border-2 border-[var(--wl-ink)] bg-[var(--wl-card)] p-4">
            <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--wl-sub)] mb-3">{t('heroCard.vault')}</div>
            <div className="space-y-2">
              {['github.com', 'proton.me', 'bank login'].map((site) => (
                <div key={site} className="flex items-center justify-between rounded-lg border border-[var(--wl-line)] px-3 py-2">
                  <span className="text-xs font-semibold text-[var(--wl-ink)]">{site}</span>
                  <span className="font-mono text-[10px] text-[var(--wl-sub)]">••••••••</span>
                </div>
              ))}
            </div>
          </div>
          {/* Note card */}
          <div className="pn-fx-straighten absolute top-44 start-0 w-64 -rotate-2 rounded-2xl border-2 border-[var(--wl-ink)] bg-[var(--wl-card)] p-4">
            <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--wl-sub)] mb-2">{t('heroCard.today')}</div>
            <div className="text-sm font-extrabold text-[var(--wl-ink)] mb-2.5">{t('heroCard.tripTitle')}</div>
            <div className="space-y-2 text-xs text-[var(--wl-sub)]">
              <div className="flex items-center gap-2">
                <Check size={13} className="shrink-0 text-accent" />
                <span className="line-through text-[var(--wl-sub)]">{t('heroCard.taskPassport')}</span>
              </div>
              <div className="flex items-center gap-2">
                <Check size={13} className="shrink-0 text-accent" />
                <span className="line-through text-[var(--wl-sub)]">{t('heroCard.taskInsurance')}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="inline-block w-3 h-3 rounded-[3px] border border-[var(--wl-muted)]/60 shrink-0" />
                <span>{t('heroCard.taskChargers')}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="inline-block w-3 h-3 rounded-[3px] border border-[var(--wl-muted)]/60 shrink-0" />
                <span>{t('heroCard.taskHotel')}</span>
              </div>
            </div>
          </div>
          {/* Phrase card (front) */}
          <div className="pn-fx-straighten absolute bottom-2 end-4 w-72 rotate-1 rounded-2xl border-2 border-[var(--wl-ink)] bg-[var(--wl-ink)] p-4">
            <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-emerald-400 dark:text-emerald-800 mb-3">{t('heroCard.yourKey')}</div>
            <div className="flex flex-wrap gap-1.5">
              {/*
                DECORATIVE ONLY, AND DELIBERATELY NOT A REAL MNEMONIC.
                Five of these twelve words (quartz, ember, willow, prism, cedar) are not in
                the BIP-39 English wordlist at all, so this set can never pass
                validateMnemonic() and can never open a vault no matter how the checksum
                falls. Do not "refresh" it with a generated phrase: phrase identity is
                derived client-side, so a valid mnemonic printed on the homepage is a live
                account that every visitor co-owns. Re-check with validateMnemonic() if any
                word here changes.
                Spec: ops/docs/design-decisions.md (Phrase mockups must never be valid BIP-39)
              */}
              {['velvet', 'canyon', 'orbit', 'maple', 'quartz', 'ember', 'willow', 'prism', 'cedar', 'noble', 'drift', 'lunar'].map((word) => (
                <span key={word} className="font-mono text-[11px] px-2 py-1 rounded bg-[var(--wl-bg)]/15 text-[var(--wl-bg)]">{word}</span>
              ))}
            </div>
          </div>
        </div>
        </div>

        {/* ── Ribbon marquee (tilted) ─────────────────────────── */}
        <div className="-mx-5 sm:-mx-8 mb-14 sm:mb-20" style={{ transform: 'rotate(-1.5deg) scale(1.03)' }}>
          <Marquee
            items={RIBBON_ITEM_KEYS.map((k) => t(k))}
            separator="✦"
            className="bg-[var(--wl-ink)] text-[var(--wl-bg)] text-[13px] font-extrabold uppercase tracking-[0.15em]"
          />
        </div>

        {/* ── Live demo shot: click-through into the sandbox ────
            Sits directly under the ribbon, ABOVE the pillar grid: the real
            app is the strongest proof on the page, so it comes before the
            feature claims. */}
        <div className="max-w-5xl mx-auto mb-8 sm:mb-10">
          <Kicker className="text-[var(--wl-amber-text)]">{t('demoShot.kicker')}</Kicker>
          <a
            href="https://try.privacynotes.app/"
            className="group relative block overflow-hidden rounded-2xl border-2 border-[var(--wl-ink)] bg-[var(--wl-card)]"
          >
            {/* Two captures of the same screen, one per mode, so the shot
                matches the page around it instead of pasting a white app
                onto sumi ink. `key` forces a fresh element on a toggle:
                React reuses one <img> across a src change, and the browser
                keeps painting the old frame until the new file decodes.

                2048 wide for a column that caps at 1024, so the shot stays
                sharp on a 2x screen.

                loading=lazy keeps the shot out of the first-paint fetch
                race on mobile, where it sits below the fold. NOT
                decoding=async - that attribute left this exact image
                decoded but never painted in Chromium (see the section 49
                gotcha in ui-patterns.md). */}
            <img
              key={theme}
              src={theme === 'dark' ? '/marketing/demo-app-dark.webp' : '/marketing/demo-app-light.webp'}
              alt=""
              width={2048}
              height={1116}
              loading="lazy"
              className="block w-full"
            />
            <span aria-hidden="true" className="absolute inset-0 bg-neutral-950/0 transition group-hover:bg-neutral-950/[0.06]" />
            {/* Amber, like every other "try the demo" CTA on this page. Filled
                rather than the outlined pill used elsewhere, because this one
                sits on a photograph and an outline disappears into it. Note it
                does NOT take pn-fx-conic-btn: that hover paints a black
                background, which would flip an amber button back to black. */}
            <span className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 inline-flex items-center gap-2 whitespace-nowrap rounded-full bg-amber-500 px-5 sm:px-7 py-3 sm:py-3.5 text-sm sm:text-base font-bold text-neutral-950 shadow-[0_4px_14px_rgba(10,10,10,0.28)] transition group-hover:bg-amber-400">
              {t('hero.tryDemo')}
              <ArrowUpRight size={16} className="shrink-0" aria-hidden="true" />
            </span>
          </a>
          <p className="mt-3 text-center text-xs text-[var(--wl-muted)]">{t('demoShot.caption')}</p>
        </div>

        {/* ── Featured on PrivacyTools.io badge ─────────────────
            Live star rating, served from our own origin: worker.ts
            proxies it at /badge/privacytools.svg for the same reason
            it proxies favicons - this page promises no tracking, so
            it stays single-origin. The badge is a fixed brand asset;
            its light artwork sits on its own card in both modes. */}
        <div className="mb-14 sm:mb-20 flex flex-col items-center gap-2">
          <a href="https://privacytools.io/app/privacynotes" target="_blank" rel="noopener">
            <img
              src="/badge/privacytools.svg"
              alt={t('badges.privacyToolsAlt')}
              width="272"
              height="46"
              loading="lazy"
            />
          </a>
          <p className="text-xs text-[var(--wl-muted)]">{t('badges.privacyToolsCaption')}</p>
        </div>

        {/* ── Five pillars (tile grid) ────────────────────────── */}
        <div className="max-w-5xl mx-auto mb-2">
          <Kicker>{t('pillars.kicker')}</Kicker>
          <div className="grid grid-cols-2 sm:grid-cols-6 gap-2.5 sm:gap-3">
            <div className="pn-fx-invert col-span-2 rounded-2xl bg-[var(--wl-ink)] p-4 sm:p-6">
              <FileText size={30} weight="duotone" className="text-blue-400 dark:text-blue-600" />
              <div className="mt-2.5 sm:mt-3 text-xl sm:text-2xl font-extrabold tracking-tight text-[var(--wl-bg)]">{t('pillars.notesName')}</div>
              <p className="mt-1 text-sm leading-relaxed text-[var(--wl-slab-sub)]">
                {t('pillars.notesBlurb')}
              </p>
            </div>
            <div className="pn-fx-draw sm:col-span-2 rounded-2xl bg-[var(--wl-tint-blue)] border-2 border-accent/30 p-4 sm:p-6">
              <svg className="pn-fx-draw-rect" aria-hidden="true"><rect /></svg>
              <CheckCircle size={30} weight="duotone" className="text-accent" />
              <div className="mt-2.5 sm:mt-3 text-xl sm:text-2xl font-extrabold tracking-tight text-[var(--wl-ink)]">{t('pillars.tasksName')}</div>
              <p className="mt-1 text-sm leading-relaxed text-[var(--wl-sub)]">
                {t('pillars.tasksBlurb')}
              </p>
            </div>
            <div className="pn-fx-stamp sm:col-span-2 rounded-2xl bg-[var(--wl-tint-green)] border-2 border-[var(--wl-emerald)]/30 p-4 sm:p-6" data-stamp="SAFE">
              <Shield size={30} weight="duotone" className="text-[var(--wl-emerald)]" />
              <div className="mt-2.5 sm:mt-3 text-xl sm:text-2xl font-extrabold tracking-tight text-[var(--wl-ink)]">{t('pillars.vaultName')}</div>
              <p className="mt-1 text-sm leading-relaxed text-[var(--wl-sub)]">
                {t('pillars.vaultBlurb')}
              </p>
            </div>
            <div className="pn-fx-grid col-span-2 sm:col-span-2 rounded-2xl bg-[var(--wl-card)] border-2 border-accent p-4 sm:p-6">
              <Book size={30} weight="duotone" className="text-[var(--wl-ink)]" />
              <div className="mt-2.5 sm:mt-3 text-xl sm:text-2xl font-extrabold tracking-tight text-[var(--wl-ink)]">{t('pillars.journalName')}</div>
              <p className="mt-1 text-sm leading-relaxed text-[var(--wl-sub)]">
                {t('pillars.journalBlurb')}
              </p>
            </div>
            {/* The one tile that shows a number. "Storage tracking" is in the
                blurb, so the meter states the claim instead of decorating
                around it, and the fill sweeps on hover. Warm grey rather than
                a hue: row two already carries violet, and only a neutral
                ground lets the fill stay pure black.
                It carries the Vault tile's stamp as well, reading ENCRYPTED
                rather than SAFE, so the two tiles that hold your bytes share
                one gesture. The stamp text is a literal for the same reason
                SAFE is, and pn-fx-stamp supplies its own position: relative.
                The bar and the digits move together (160 MB / 32% at rest,
                412 MB / 82.4% on hover) instead of the bar sweeping next to a
                frozen number, which is what it used to do. Keep the two pairs
                in step: they are one fact written twice, four lines apart in
                FX_CSS.
                The whole effect sits behind (hover:hover) and (pointer:fine),
                so a phone gets the rest state and nothing else. iOS fakes a
                hover on tap and then keeps it, which left the meter animating
                at random while scrolling. The first attempt drove both halves
                from one animated @property and read the digits out of a CSS
                counter; that is elegant on Chrome and stuttered through 0 MB
                on iOS, so the digits are plain ::before literals now.
                Those literals are not locale keys - a numeral pair and a unit
                symbol read identically in every catalog, the same call the
                ~/notes/ideas.md path below makes.
                Spec: ops/docs/pro-features.md (Pro storage cap is 500 MB) */}
            <div className="pn-fx-meter pn-fx-stamp col-span-2 sm:col-span-2 rounded-2xl bg-[var(--wl-tile-files)] border-2 border-[var(--wl-ink)] p-4 sm:p-6 pb-11 sm:pb-12" data-stamp="ENCRYPTED">
              <Folder size={30} weight="duotone" className="text-[var(--wl-ink)]" />
              <div className="mt-2.5 sm:mt-3 text-xl sm:text-2xl font-extrabold tracking-tight text-[var(--wl-ink)]">{t('pillars.filesName')}</div>
              <p className="mt-1 text-sm leading-relaxed text-[var(--wl-sub)]">
                {t('pillars.filesBlurb')}
              </p>
              <span dir="ltr" aria-hidden="true" className="pn-fx-meter-readout absolute end-4 sm:end-6 bottom-6 sm:bottom-7 font-mono text-[10px] text-[var(--wl-sub)]">{' / 500 MB'}</span> {/* rtl-ok: a numeric readout stays LTR */}
              <span aria-hidden="true" className="absolute start-4 end-4 sm:start-6 sm:end-6 bottom-4 sm:bottom-5 h-1.5 overflow-hidden rounded-full bg-[var(--wl-ink)]/15">
                <span className="pn-fx-meter-fill block h-full rounded-full bg-[var(--wl-ink)]" />
              </span>
            </div>
            {/* The accent bookmark ribbon sits tucked into the tile at rest
                (a bookmark IS the feature) and slides away on hover - the
                inverse of its original drop-in, flipped 2026-08-24. Still
                the one hover on this grid that moves on the vertical axis;
                every sibling animates a border, a stamp or a background. */}
            <div className="pn-fx-ribbon col-span-2 sm:col-span-2 rounded-2xl bg-[var(--wl-tile-marks)] border-2 border-[var(--wl-line)] p-4 sm:p-6">
              <Bookmarks size={30} weight="duotone" className="text-accent" />
              <div className="mt-2.5 sm:mt-3 text-xl sm:text-2xl font-extrabold tracking-tight text-[var(--wl-ink)]">{t('pillars.bookmarksName')}</div>
              <p className="mt-1 text-sm leading-relaxed text-[var(--wl-sub)]">
                {t('pillars.bookmarksBlurb')}
              </p>
            </div>
          </div>
          {/* Row three of the same grid, and deliberately outside the "one key"
              story above it: the Markdown editor works on plain local files with
              no sync and no encryption, so it keeps the dashed (marching-ants)
              border the small tile used to carry - the selection marquee marks
              the odd one out. It spans the full width because it is the "and one
              on your disk" half of the kicker, not a seventh pillar. */}
          <div className="pn-fx-ants mt-2.5 sm:mt-3 grid sm:grid-cols-2 gap-6 sm:gap-8 items-center rounded-2xl p-6 sm:p-8">
            <div>
              <h2 className="text-2xl sm:text-3xl font-black tracking-tight text-[var(--wl-ink)]">
                {t('mdEditor.title')}
              </h2>
              <p className="mt-3 text-sm leading-relaxed text-[var(--wl-sub)]">
                {t('mdEditor.body')}
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                {['mdEditor.chipObsidian', 'mdEditor.chipGit', 'mdEditor.chipAgents'].map((k) => (
                  <span key={k} className="rounded-full border border-[var(--wl-amber-border)] px-3 py-1 text-xs font-semibold text-[var(--wl-amber-text)]">
                    {t(k)}
                  </span>
                ))}
              </div>
              <p className="mt-4 text-xs text-[var(--wl-sub)]">{t('mdEditor.platforms')}</p>
            </div>
            <div className="overflow-hidden rounded-xl border-2 border-[var(--wl-ink)] bg-[var(--wl-card)]">
              <div className="flex items-center gap-1.5 border-b border-[var(--wl-line)] px-3.5 py-2.5">
                <span aria-hidden="true" className="h-2 w-2 rounded-full bg-red-400" />
                <span aria-hidden="true" className="h-2 w-2 rounded-full bg-amber-400" />
                <span aria-hidden="true" className="h-2 w-2 rounded-full bg-emerald-400" />
                <span dir="ltr" className="ms-2 font-mono text-[11px] text-[var(--wl-muted)]">~/notes/ideas.md</span> {/* rtl-ok: file path stays LTR */}
              </div>
              <div className="px-4 py-3.5">
                <div className="text-base font-extrabold tracking-tight text-[var(--wl-ink)]">{t('mdEditor.sampleTitle')}</div>
                <div className="mt-2 space-y-1 text-sm text-[var(--wl-sub)]">
                  <div className="flex items-center gap-1.5">
                    <CheckSquare size={15} weight="fill" className="shrink-0 text-[var(--wl-emerald)]" aria-hidden="true" />
                    <span className="line-through decoration-[var(--wl-muted)]">{t('mdEditor.sampleTask1')}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Square size={15} className="shrink-0 text-[var(--wl-muted)]" aria-hidden="true" />
                    <span>{t('mdEditor.sampleTask2')}</span>
                  </div>
                </div>
                <span className="mt-2.5 inline-block rounded bg-[var(--wl-tint-blue)] px-1.5 py-0.5 text-[11px] font-semibold text-accent dark:text-blue-300">
                  {t('mdEditor.sampleTag')}
                </span>
              </div>
              <div className="flex items-center justify-between border-t border-[var(--wl-line)] px-3.5 py-2">
                <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-[var(--wl-muted)]">{t('mdEditor.savedToDisk')}</span>
                <span className="rounded-full bg-amber-500 px-2 py-0.5 text-[10px] font-extrabold uppercase tracking-[0.08em] text-neutral-950">{t('pillars.markdownFree')}</span>
              </div>
            </div>
          </div>
        </div>

        {/* ── Downloads ─────────────────────────────────────── */}
        <div id="downloads" className="max-w-4xl mx-auto mt-16 sm:mt-24 mb-14 scroll-mt-24 text-center">
          <Kicker>{t('downloads.kicker')}</Kicker>
          <h2 className="text-3xl sm:text-4xl font-black tracking-tight text-[var(--wl-ink)]">
            {t('downloads.heading')}
          </h2>
          {/* Below sm the row is width-capped to three tiles, so the five
              platforms always wrap 3+2. Uncapped, widths between about 420
              and 500px wrapped 4+1, one orphan tile under the row. */}
          <div className="mx-auto mt-9 flex max-w-[22rem] flex-wrap justify-center gap-5 sm:max-w-none sm:gap-7">
            <DownloadTile href={MAC_DMG_URL} name="macOS" version={platformVersions.macOS} tileBg="#EDE8D8" iconColor="#1C1917" icon={<AppleLogo size={42} weight="fill" />} />
            <DownloadTile href={WINDOWS_SETUP_URL} name="Windows" version={platformVersions.Windows} tileBg="#E7EFF8" iconColor="#0078D4" icon={<WindowsLogo size={42} weight="fill" />} />
            <DownloadTile onClick={() => { setAndroidOpen(false); setPkgOpen(false); setLinuxOpen((v) => !v); }} expanded={linuxOpen} name="Linux" version={platformVersions.Linux} tileBg="#F5E9C8" icon={<TuxMark size={46} />} />
            <DownloadTile onClick={() => { setLinuxOpen(false); setPkgOpen(false); setAndroidOpen((v) => !v); }} expanded={androidOpen} name="Android" version={platformVersions.Android} tileBg="#E7F0E0" iconColor="#3DDC84" icon={<AndroidLogo size={44} weight="fill" />} />
            <DownloadTile href={APP_STORE_URL} name="iOS" note={t('downloads.appStore')} tileBg="#EDE8D8" iconColor="#1C1917" icon={<AppleLogo size={42} weight="fill" />} />
          </div>
          {linuxOpen && (
            <div dir="ltr" className="mx-auto mt-6 max-w-lg overflow-hidden rounded-2xl border border-[var(--wl-ink)]/15 bg-[var(--wl-card)]/70 text-left"> {/* rtl-ok: code sample stays LTR */}
              {/* The distro floor sits ABOVE the artifact list, not in debFootnote below it:
                  it applies to the AppImage as much as the .deb (both are built against
                  libwebkit2gtk-4.1-0), and a floor read after the download has already
                  started is the false-hope failure issue #227 reported on macOS.
                  Spec: ops/docs/linux-release.md (dependency floor) */}
              <p className="border-b border-[var(--wl-ink)]/10 px-4 py-3 text-xs leading-relaxed text-[var(--wl-sub)]">
                {t('downloads.linuxRequirement')}
              </p>
              {/* One group per architecture, detected one first. The AppImage carries the
                  Recommended pill because of the formats offered here it is the one that
                  updates itself, the .deb being root-owned. One pill per panel, the same
                  rule the Android panel follows: a second one turns a recommendation into
                  a category. Spec: ops/docs/linux-release.md (the sole updater payload) */}
              {linuxArchShown.map((a, i) => (
                <div key={a} className={i > 0 ? 'border-t border-[var(--wl-ink)]/10' : undefined}>
                  <div className="flex items-start justify-between gap-3 px-4 pt-3 pb-1.5">
                    <span>
                      <span className="block font-semibold text-accent">{t(LINUX_BUILDS[a].label)}</span>
                      <span className="mt-0.5 block text-xs leading-relaxed text-[var(--wl-sub)]">{t(LINUX_BUILDS[a].desc)}</span>
                    </span>
                    {linuxArch === a && (
                      <span className="flex shrink-0 items-center gap-1 text-xs font-semibold text-[var(--wl-emerald)]">
                        <CheckCircle size={14} weight="fill" aria-hidden="true" />
                        {t('downloads.linuxDetected')}
                      </span>
                    )}
                  </div>
                  <LinuxDl recommended icon={<Cube size={17} weight="fill" />} href={LINUX_BUILDS[a].appimage} label="AppImage" desc={t('downloads.linuxAppImageDesc')} />
                  <LinuxDl divider icon={<Archive size={17} weight="fill" />} href={LINUX_BUILDS[a].deb} label=".deb" desc={t('downloads.linuxDebDesc')} />
                </div>
              ))}
              {linuxArch !== null && !linuxOtherArch && (
                <button
                  type="button"
                  onClick={() => setLinuxOtherArch(true)}
                  className="flex w-full cursor-pointer items-center gap-2 border-t border-[var(--wl-ink)]/10 px-4 py-3 text-sm font-semibold text-accent transition hover:bg-[var(--wl-ink)]/5"
                >
                  <CaretDown size={14} weight="bold" aria-hidden="true" />
                  {t('downloads.linuxShowOther', { arch: t(LINUX_BUILDS[linuxSecondArch].label) })}
                </button>
              )}
              {/* The .deb cannot self-update (root-owned /usr), so every release is a
                  manual re-install - and the obvious move, double-clicking the file,
                  dead-ends in Ubuntu's App Center, which reports "Installed" and offers
                  no update or remove action. Uninstalling first is never necessary:
                  installing over the old version IS the upgrade. Spec: ops/docs/linux-release.md (App Center's untrusted-source note persists until a signed apt repo ships) */}
              <div className="border-t border-[var(--wl-ink)]/10 px-4 py-3">
                <p className="text-xs leading-relaxed text-[var(--wl-sub)]">
                  <Trans
                    i18nKey="landing:downloads.debFootnote"
                    components={{
                      highlight: (
                        <strong className="font-semibold text-[var(--wl-ink)]" />
                      ),
                    }}
                  />
                </p>
                {linuxArchShown.map((a) => (
                  <DebCmd key={a} arch={t(LINUX_BUILDS[a].label)} file={LINUX_BUILDS[a].debFile} />
                ))}
              </div>
            </div>
          )}
          {androidOpen && (
            <div dir="ltr" className="mx-auto mt-6 max-w-lg overflow-hidden rounded-2xl border border-[var(--wl-ink)]/15 bg-[var(--wl-card)]/70 text-left"> {/* rtl-ok: code sample stays LTR */}
              {/* The two self-updating routes lead, and each badge sits at the end of its own
                  row rather than under it: the badge art already carries the store's name, so
                  a title line above it would print the same word twice. What the row adds is
                  the one thing the art cannot say - who installs the next version. That is the
                  chip, and it is why the APK carries an amber one: a reader who skips every
                  sentence still learns that two routes keep themselves current and one is a
                  chore. Zapstore takes the Recommended word because it is the only route that
                  verifies before it installs: it holds the file hash and the signing
                  certificate we published and refuses a mismatch, which is the check this
                  whole page asks people to care about. The row wraps below about 384px, so a
                  phone stacks the badge under the text instead of squeezing both. */}
              <div className="flex flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3">
                <div className="min-w-[175px] flex-1">
                  <span className="flex flex-wrap items-center gap-x-2 gap-y-1 font-semibold text-[var(--wl-ink)]">
                    <a href={ZAPSTORE_SITE_URL} target="_blank" rel="noopener" className="underline hover:no-underline">Zapstore</a>
                    <span className="whitespace-nowrap rounded-full bg-[var(--wl-tint-green)] px-2 py-0.5 text-xs font-semibold text-[var(--wl-emerald)]">{t('downloads.autoUpdates')}</span>
                  </span>
                  <span className="mt-0.5 block text-sm text-[var(--wl-sub)]">
                    <Trans
                      i18nKey="landing:downloads.zapstoreDesc"
                      components={{ rec: <strong className="font-semibold text-[var(--wl-emerald)]" /> }}
                    />
                  </span>
                </div>
                {/* Zapstore's own badge, served from our origin like every other image here.
                    It links the listing rather than an install scheme, which is the whole
                    difference from the Obtainium badge below: that one hands the phone an app
                    entry to add, this one opens a page a person reads first. No copy block
                    underneath for the same reason - the URL is a destination, not something
                    to paste into another app. Kept as the supplied SVG rather than rasterised
                    to match its neighbour, because vector art stays sharp at any density and
                    the row renders it at 48px on a phone and a desktop alike. */}
                <a href={ZAPSTORE_LISTING_URL} target="_blank" rel="noopener" className="shrink-0 transition hover:opacity-80">
                  <img
                    src="/marketing/badge-zapstore.svg"
                    alt={t('downloads.zapstoreBadgeAlt')}
                    width={157}
                    height={48}
                    loading="lazy"
                    className="block h-12 w-auto"
                  />
                </a>
              </div>
              <div className="border-t border-[var(--wl-ink)]/10 px-4 py-3">
                <div className="flex flex-wrap items-center gap-x-4 gap-y-3">
                  <div className="min-w-[175px] flex-1">
                    <span className="flex flex-wrap items-center gap-x-2 gap-y-1 font-semibold text-[var(--wl-ink)]">
                      <a href={OBTAINIUM_SITE_URL} target="_blank" rel="noopener" className="underline hover:no-underline">Obtainium</a>
                      <span className="whitespace-nowrap rounded-full bg-[var(--wl-tint-green)] px-2 py-0.5 text-xs font-semibold text-[var(--wl-emerald)]">{t('downloads.autoUpdates')}</span>
                    </span>
                    <span className="mt-0.5 block text-sm text-[var(--wl-sub)]">{t('downloads.obtainiumDesc')}</span>
                  </div>
                  {/* Obtainium's own badge, served from our origin like every other image here.
                      It is the whole point of the row on a phone, so it sits in the row itself:
                      the copy block below is the fallback for a desktop reader and for a browser
                      that refuses to hand a custom scheme to an app. */}
                  <a href={OBTAINIUM_ADD_URL} target="_blank" rel="noopener" className="shrink-0 transition hover:opacity-80">
                    <img
                      src="/marketing/badge-obtainium.webp"
                      alt={t('downloads.obtainiumBadgeAlt')}
                      width={161}
                      height={48}
                      loading="lazy"
                      className="block h-12 w-auto"
                    />
                  </a>
                </div>
                {/* The URL is what Obtainium wants pasted, and nothing else on this page has a
                    use for it, so it hangs inside this row with no rule on either side. A rule
                    would read as a route of its own and invite a reader to paste it somewhere
                    that has no idea what to do with it. */}
                <CmdBlock className="mt-2.5" cmd={OBTAINIUM_SOURCE_URL} />
                {/* The house FAQ-link design, same component the sign-in and settings
                    modals use, so a /help link looks identical wherever it appears. It
                    carries the real FAQ question rather than a label of our own, which
                    is why this row needs no string of its own. */}
                <HelpChip surface="downloads" className="mt-2.5" />
              </div>
              {/* One row for the two routes nobody has to keep current by choice: the APK you
                  update by hand, and the store that is not open yet. The APK half is its own
                  positioned block because the digest link cannot nest inside the download
                  link, so the anchor is stretched across that block alone - which is also what
                  keeps the hover highlight off the Play line underneath. This is the one
                  Android route where a checksum earns its place, because a sideloaded APK is
                  installed by hand outside any store's verification. */}
              <div className="border-t border-[var(--wl-ink)]/10 py-1">
                <div className="relative px-4 py-2 hover:bg-[var(--wl-ink)]/5">
                  <span className="mb-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 font-semibold text-[var(--wl-ink)]">
                    <a href={ANDROID_APK_URL} className="flex items-center gap-2 after:absolute after:inset-0">
                      <span aria-hidden="true" className="shrink-0 text-accent"><AndroidLogo size={17} weight="fill" /></span>
                      APK
                    </a>
                    <span className="whitespace-nowrap rounded-full bg-[var(--wl-tint-amber)] px-2 py-0.5 text-xs font-semibold text-[var(--wl-amber-text)]">{t('downloads.manualUpdates')}</span>
                    <ChecksumLink href={ANDROID_APK_URL} label="APK" className="ms-auto" />
                  </span>
                  <span className="mt-0.5 block text-sm text-[var(--wl-sub)]">{t('downloads.apkDesc')}</span>
                </div>
                <div className="flex items-center justify-between gap-3 px-4 py-2">
                  <span className="flex items-center gap-2 font-semibold text-[var(--wl-muted)]">
                    <span aria-hidden="true" className="shrink-0"><GooglePlayLogo size={17} weight="fill" /></span>
                    Google Play
                  </span>
                  <span className="shrink-0 rounded-full border border-[var(--wl-ink)]/15 px-2.5 py-1 text-xs font-semibold text-[var(--wl-sub)]">
                    {t('downloads.comingSoon')}
                  </span>
                </div>
              </div>
              <p className="border-t border-[var(--wl-ink)]/10 px-4 py-3 text-xs leading-relaxed text-[var(--wl-sub)]">
                {t('downloads.apkFootnote')}
              </p>
            </div>
          )}
          {/* Package managers are a minority path, so they get a closed disclosure rather
              than room next to the tiles: the macOS and Windows tiles stay one-click
              downloads for everyone else. Same panel shape as the Linux and Android
              disclosures above, and only one of the three is ever open.
              Spec: mockups/downloads-pkgmgr.html */}
          <div className="mt-8 flex flex-wrap items-center justify-center gap-x-8 gap-y-3">
            <button
              type="button"
              onClick={() => { setLinuxOpen(false); setAndroidOpen(false); setPkgOpen((v) => !v); }}
              aria-expanded={pkgOpen}
              className="flex cursor-pointer items-start gap-2 text-sm font-semibold text-accent transition hover:opacity-80"
            >
              {/* Centred inside a 20px box, which is the text's own line height, so the
                  mark sits on the first line instead of floating between two. These
                  labels name their platforms, so they are long in English and longer in
                  German, and a centred icon beside a wrapped label reads as orphaned.
                  Same box the help chip uses, for the same reason. */}
              <span className="flex h-5 shrink-0 items-center">
                <Package size={17} weight="fill" aria-hidden="true" />
              </span>
              {/* This label names the rows in the panel below. Adding or removing a row
                  means editing both, or it promises a platform nobody finds. */}
              <span>{t('downloads.pkgToggle', { platforms: 'macOS, Windows' })}</span>
            </button>
            <a
              href={GITHUB_RELEASES_URL}
              target="_blank"
              rel="noopener"
              className="flex items-start gap-2 text-sm font-semibold text-accent transition hover:opacity-80"
            >
              <span className="flex h-5 shrink-0 items-center">
                <GithubLogo size={17} weight="fill" aria-hidden="true" />
              </span>
              <span>
                {t('downloads.githubLink')}
                <ArrowUpRight size={13} className="ms-1.5 inline align-[-1px]" aria-hidden="true" />
              </span>
            </a>
          </div>
          <p className="mt-4 font-mono text-[11px] font-semibold uppercase tracking-[0.18em] leading-relaxed text-[var(--wl-emerald)]">
            {t('downloads.githubNote')}
          </p>
          {pkgOpen && (
            <div dir="ltr" className="mx-auto mt-5 max-w-lg overflow-hidden rounded-2xl border border-[var(--wl-ink)]/15 bg-[var(--wl-card)]/70 text-left"> {/* rtl-ok: code sample stays LTR */}
              <PkgCmd
                icon={<AppleLogo size={17} weight="fill" />}
                name="macOS"
                tool="Homebrew"
                desc={t('downloads.pkgBrewDesc')}
                cmd="brew install privacynotes"
              />
              <PkgCmd
                divider
                icon={<WindowsLogo size={17} weight="fill" />}
                name="Windows"
                tool="winget"
                desc={t('downloads.pkgWingetDesc')}
                cmd="winget install LifetimeLabs.PrivacyNotes"
              />
              {/* Two lines, and CmdBlock renders `cmd` with whitespace-pre-wrap, so the
                  break survives and the copy button hands over both. Scoop resolves a
                  short name only against buckets it already knows, so the bucket has to
                  be added before the install can name it. */}
              <PkgCmd
                divider
                icon={<WindowsLogo size={17} weight="fill" />}
                name="Windows"
                tool="Scoop"
                desc={t('downloads.pkgScoopDesc')}
                cmd={'scoop bucket add lifetimelabs https://github.com/LifetimeLabsDev/scoop-bucket\nscoop install lifetimelabs/privacynotes'}
              />
              <p className="border-t border-[var(--wl-ink)]/10 px-4 py-3 text-xs leading-relaxed text-[var(--wl-sub)]">
                {t('downloads.pkgFootnote')}
              </p>
            </div>
          )}
          <p className="mt-8 text-sm text-[var(--wl-sub)]">
            {t('downloads.availability')}
          </p>
          <p className="mx-auto mt-3 max-w-md text-sm leading-relaxed text-balance text-[var(--wl-ink)]">
            {t('downloads.betaNote')}
          </p>
        </div>

        {/* ── CTA repeat ──────────────────────────────────────── */}
        <div className="max-w-4xl mx-auto mb-14 grid grid-cols-2 sm:flex sm:flex-wrap justify-center items-center gap-2 sm:gap-3">
          <button
            type="button"
            onClick={() => openAuth('create')}
            className="pn-fx-conic-btn cursor-pointer rounded-full bg-[var(--wl-ink)] text-[var(--wl-bg)] px-3 sm:px-7 py-3.5 text-sm sm:text-base font-bold"
          >
            {t('ctaRepeat.getStarted')}
          </button>
          <a
            href="https://try.privacynotes.app/"
            className="pn-fx-amber inline-flex items-center justify-center gap-2 rounded-full border-2 border-[var(--wl-amber-border)] text-[var(--wl-amber-text)] px-3 sm:px-6 py-3 text-sm sm:text-base font-bold transition"
          >
            {t('hero.tryDemo')}
            <ArrowUpRight size={16} className="shrink-0" aria-hidden="true" />
          </a>
          <p className="col-span-2 basis-full text-center mt-1 text-xs text-[var(--wl-muted)]">
            {t('hero.microcopy')}
          </p>
        </div>

        {/* ── Under the hood - dark terminal aesthetic ─────────── */}
        <div className="max-w-4xl mx-auto mb-14">
          <div className="pn-fx-stamp pn-fx-stamp-bright rounded-xl border border-[var(--wl-ink-line)] bg-[var(--wl-ink-card)] p-6 sm:p-7 relative overflow-hidden" data-stamp="ENCRYPTED">
            {/* Subtle grid background */}
            <div
              aria-hidden
              className="pointer-events-none absolute inset-0 opacity-[0.04]"
              style={{ backgroundImage: 'linear-gradient(rgba(255,255,255,.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.1) 1px, transparent 1px)', backgroundSize: '24px 24px' }}
            />
            <div className="relative">
              {/* The crypto-claims strip lives inside this card so the
                  page has one security moment instead of two. */}
              <div className="mb-5 border-b border-[var(--wl-ink-line)] pb-4 overflow-hidden whitespace-nowrap font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-[var(--wl-ink-text)]">
                {CRYPTO_ITEM_KEYS.map((k) => t(k)).join('  ·  ')}
              </div>
              <div className="flex items-center gap-2 mb-5">
                <TerminalWindow size={16} className="text-emerald-400" />
                <span className="text-xs font-mono font-medium text-emerald-400 uppercase tracking-widest">{t('underHood.heading')}</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-5">
                <div className="space-y-1">
                  <div className="font-mono text-sm font-semibold text-white">{t('underHood.cipherTerm')}</div>
                  <div className="text-xs text-[var(--wl-ink-sub)]">{t('underHood.cipherDesc')}</div>
                </div>
                <div className="space-y-1">
                  <div className="font-mono text-sm font-semibold text-white">{t('underHood.phraseTerm')}</div>
                  <div className="text-xs text-[var(--wl-ink-sub)]">{t('underHood.phraseDesc')}</div>
                </div>
                <div className="space-y-1">
                  <div className="font-mono text-sm font-semibold text-white">{t('underHood.rlsTerm')}</div>
                  <div className="text-xs text-[var(--wl-ink-sub)]">{t('underHood.rlsDesc')}</div>
                </div>
                <div className="space-y-1">
                  <div className="font-mono text-sm font-semibold text-white">{t('underHood.trackingTerm')}</div>
                  <div className="text-xs text-[var(--wl-ink-sub)]">{t('underHood.trackingDesc')}</div>
                </div>
                <div className="space-y-1">
                  <div className="font-mono text-sm font-semibold text-white">{t('underHood.authTerm')}</div>
                  <div className="text-xs text-[var(--wl-ink-sub)]">{t('underHood.authDesc')}</div>
                </div>
                <div className="space-y-1">
                  <div className="font-mono text-sm font-semibold text-white">{t('underHood.serversTerm')}</div>
                  <div className="text-xs text-[var(--wl-ink-sub)]">{t('underHood.serversDesc')}</div>
                </div>
                <div className="space-y-1">
                  <div className="font-mono text-sm font-semibold text-white">{t('underHood.sshTerm')}</div>
                  <div className="text-xs text-[var(--wl-ink-sub)]">{t('underHood.sshDesc')}</div>
                </div>
                <div className="space-y-1">
                  <div className="font-mono text-sm font-semibold text-white">{t('underHood.pwgenTerm')}</div>
                  <div className="text-xs text-[var(--wl-ink-sub)]">{t('underHood.pwgenDesc')}</div>
                </div>
                {/* The one cell in the grid that goes somewhere. Every other
                    term names a property of the build; this one names a place
                    the reader can go and check, so it reads as a dead end
                    while the other eight are meant to. */}
                <div className="space-y-1">
                  <a
                    href={GITHUB_REPO_URL}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 font-mono text-sm font-semibold text-white transition hover:text-[var(--wl-emerald)]"
                  >
                    {t('underHood.opensourceTerm')}
                    <ArrowUpRight size={13} className="shrink-0" aria-hidden="true" />
                  </a>
                  <div className="text-xs text-[var(--wl-ink-sub)]">{t('underHood.opensourceDesc')}</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ── Mood & Wellness Tracker deep dive ─────────────── */}
        <div className="max-w-4xl mx-auto mb-14">
          <Kicker className="text-[var(--wl-emerald)]">{t('mood.kicker')}</Kicker>
          <h2 className="text-3xl sm:text-5xl font-black tracking-tight text-[var(--wl-ink)]">
            {t('mood.heading')}
          </h2>
          <p className="mt-4 text-base text-[var(--wl-sub)] leading-relaxed max-w-xl">
            {t('mood.intro')}
          </p>

          <div className="mt-8 grid sm:grid-cols-2 gap-4">
            {/* Mood & Emotions */}
            <div className="pn-fx-scan rounded-2xl border-2 border-[var(--wl-ink)] bg-[var(--wl-card)] p-5 space-y-2">
              <div className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--wl-tint-green)] text-[var(--wl-emerald)]">
                <Smiley size={20} weight="duotone" />
              </div>
              <div className="font-extrabold text-[var(--wl-ink)]">{t('mood.cardEmotionsTitle')}</div>
              <p className="text-sm text-[var(--wl-sub)] leading-relaxed">
                {t('mood.cardEmotionsBody')}
              </p>
            </div>

            {/* Sleep & Activity */}
            <div className="pn-fx-scan rounded-2xl border-2 border-[var(--wl-ink)] bg-[var(--wl-card)] p-5 space-y-2">
              <div className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--wl-tint-green)] text-[var(--wl-emerald)]">
                <Moon size={20} weight="duotone" />
              </div>
              <div className="font-extrabold text-[var(--wl-ink)]">{t('mood.cardSleepTitle')}</div>
              <p className="text-sm text-[var(--wl-sub)] leading-relaxed">
                {t('mood.cardSleepBody')}
              </p>
            </div>

            {/* Medication Tracking */}
            <div className="pn-fx-scan rounded-2xl border-2 border-[var(--wl-ink)] bg-[var(--wl-card)] p-5 space-y-2">
              <div className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--wl-tint-green)] text-[var(--wl-emerald)]">
                <Pill size={20} weight="duotone" />
              </div>
              <div className="font-extrabold text-[var(--wl-ink)]">{t('mood.cardMedsTitle')}</div>
              <p className="text-sm text-[var(--wl-sub)] leading-relaxed">
                {t('mood.cardMedsBody')}
              </p>
            </div>

            {/* Analytics & Export */}
            <div className="pn-fx-scan rounded-2xl border-2 border-[var(--wl-ink)] bg-[var(--wl-card)] p-5 space-y-2">
              <div className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--wl-tint-green)] text-[var(--wl-emerald)]">
                <ChartBar size={20} weight="duotone" />
              </div>
              <div className="font-extrabold text-[var(--wl-ink)]">{t('mood.cardAnalyticsTitle')}</div>
              <p className="text-sm text-[var(--wl-sub)] leading-relaxed">
                {t('mood.cardAnalyticsBody')}
              </p>
            </div>
          </div>

          {/* Privacy angle callout - terminal style, matching Under the hood */}
          <div className="pn-fx-stamp pn-fx-stamp-bright mt-4 rounded-xl border border-[var(--wl-ink-line)] bg-[var(--wl-ink-card)] p-6 relative overflow-hidden" data-stamp="NO BACKDOOR">
            <div
              aria-hidden
              className="pointer-events-none absolute inset-0 opacity-[0.04]"
              style={{ backgroundImage: 'linear-gradient(rgba(255,255,255,.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.1) 1px, transparent 1px)', backgroundSize: '24px 24px' }}
            />
            <div className="relative">
              <div className="flex items-center gap-2 mb-3">
                <TerminalWindow size={16} className="text-emerald-400" />
                <span className="text-xs font-mono font-medium text-emerald-400 uppercase tracking-widest">{t('mood.encryptedHeading')}</span>
              </div>
              <p className="text-sm text-[var(--wl-ink-text)] leading-relaxed">
                {t('mood.encryptedBody')}
              </p>
            </div>
          </div>
        </div>

        {/* ── Comparison: why not three apps? ─────────────────── */}
        <div className="max-w-4xl mx-auto mb-14">
          <Kicker>{t('comparison.kicker')}</Kicker>
          <h2 className="text-2xl sm:text-4xl font-black tracking-tight text-[var(--wl-ink)] max-w-2xl mb-6">
            {t('comparison.heading')}
          </h2>
          <div className="pn-fx-slab grid sm:grid-cols-2 rounded-2xl border-2 border-[var(--wl-ink)] overflow-hidden text-sm">
            {/* "Them" column */}
            <div className="p-6 bg-[var(--wl-card)] space-y-2.5">
              <div className="font-mono font-semibold text-[var(--wl-sub)] uppercase tracking-[0.18em] text-[10px] mb-3">{t('comparison.typicalSetup')}</div>
              <div className="flex items-center gap-2 text-[var(--wl-sub)]">
                <X className="shrink-0 text-[var(--wl-muted)]" />
                {t('comparison.themStandardNotes')}
              </div>
              <div className="flex items-center gap-2 text-[var(--wl-sub)]">
                <X className="shrink-0 text-[var(--wl-muted)]" />
                {t('comparison.themObsidian')}
              </div>
              <div className="flex items-center gap-2 text-[var(--wl-sub)]">
                <X className="shrink-0 text-[var(--wl-muted)]" />
                {t('comparison.themDayOne')}
              </div>
              <div className="flex items-center gap-2 text-[var(--wl-sub)]">
                <X className="shrink-0 text-[var(--wl-muted)]" />
                {t('comparison.themPasswordManager')}
              </div>
              <div className="flex items-center gap-2 text-[var(--wl-sub)]">
                <X className="shrink-0 text-[var(--wl-muted)]" />
                {t('comparison.themLunatask')}
              </div>
              <div className="flex items-center gap-2 text-[var(--wl-sub)]">
                <X className="shrink-0 text-[var(--wl-muted)]" />
                {t('comparison.themDaylio')}
              </div>
              <div className="flex items-center gap-2 text-[var(--wl-sub)]">
                <X className="shrink-0 text-[var(--wl-muted)]" />
                {t('comparison.themSeparate')}
              </div>
            </div>
            {/* "Us" column - inverted */}
            <div className="p-6 bg-[var(--wl-ink)] space-y-2.5">
              <div className="font-mono uppercase tracking-[0.18em] text-[10px] mb-3 text-[var(--wl-bg)]"><Brand tone="invert" /></div>
              {[
                t('comparison.usAllInOne'),
                t('comparison.usTracking'),
                t('comparison.usEncrypted'),
                t('comparison.usSignIn'),
                t('comparison.usExport'),
                t('comparison.usSync'),
                isBetaPricing()
                  ? t('comparison.usPriceBeta', { earlyPrice: EARLY_PRICE })
                  : t('comparison.usPrice', { proPrice: PRO_PRICE }),
              ].map((text) => (
                <div key={text} className="flex items-center gap-2 text-[var(--wl-card)]">
                  <Check className="shrink-0 text-emerald-400 dark:text-emerald-600" />
                  {text}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── CTA pair between the comparison and pricing slabs ── */}
        <div className="max-w-4xl mx-auto mb-14 grid grid-cols-2 sm:flex sm:flex-wrap justify-center items-center gap-2 sm:gap-3">
          <button
            type="button"
            onClick={() => openAuth('create')}
            className="pn-fx-conic-btn cursor-pointer rounded-full bg-[var(--wl-ink)] text-[var(--wl-bg)] px-3 sm:px-7 py-3.5 text-sm sm:text-base font-bold"
          >
            {t('ctaRepeat.getStarted')}
          </button>
          <a
            href="https://try.privacynotes.app/"
            className="pn-fx-amber inline-flex items-center justify-center gap-2 rounded-full border-2 border-[var(--wl-amber-border)] text-[var(--wl-amber-text)] px-3 sm:px-6 py-3 text-sm sm:text-base font-bold transition"
          >
            {t('hero.tryDemo')}
            <ArrowUpRight size={16} className="shrink-0" aria-hidden="true" />
          </a>
        </div>

        {/* ── Free vs Pro (split slab) ────────────────────────── */}
        <div id="pricing" className="max-w-4xl mx-auto mb-14 scroll-mt-24">
          <div className="pn-fx-slab grid sm:grid-cols-2 rounded-2xl border-2 border-[var(--wl-ink)] overflow-hidden">
          {/* Free tier */}
          <div className="bg-[var(--wl-card)] p-6 sm:p-7 space-y-4">
            <div>
              <div className="text-[11px] font-extrabold uppercase tracking-[0.15em] text-[var(--wl-sub)]">{t('pricing.freeLabel')}</div>
              <div className="mt-1 text-5xl font-black text-[var(--wl-ink)]">$0</div>
              <div className="text-xs text-[var(--wl-sub)] mt-1.5">{t('pricing.freeSubLabel')}</div>
            </div>
            <ul className="space-y-2.5 text-sm text-[var(--wl-ink)]">
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-500" />
                <span>{t('pricing.freeAllPillars')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-500" />
                <span>{t('pricing.freeSync')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-500" />
                <span>{t('pricing.freeVault')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-500" />
                <span>{t('pricing.freeSearch')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-500" />
                <span>{t('pricing.freeImport')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-500" />
                <span>{t('pricing.freeBurn')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-500" />
                <span>{t('pricing.freeMood')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-500" />
                <span>{t('pricing.freeTheme')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-500" />
                <span>{t('pricing.freeAnon')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-500" />
                <span>{t('pricing.freeGoogle')}</span>
              </li>
            </ul>
          </div>

          {/* Pro tier */}
          <div className="bg-[var(--wl-pro)] p-6 sm:p-7 space-y-4 relative">
            <div className="absolute top-5 end-5 flex items-center gap-1.5">
              <span className="text-[10px] font-bold uppercase tracking-wider bg-red-600 text-white px-2.5 py-0.5 rounded-full flex items-center gap-1">
                <X size={10} />
                {t('pricing.noSubscription')}
              </span>
            </div>
            <div>
              <div className="text-[11px] font-extrabold uppercase tracking-[0.15em] text-white/70">{t('pricing.proLabel')}</div>
              {isBetaPricing() ? (
                <>
                  <div className="mt-1 flex items-baseline gap-2.5 flex-wrap">
                    <span className="text-2xl font-bold text-white/50 line-through">${PRO_PRICE}</span>
                    <span className="text-5xl font-black text-white">${EARLY_PRICE}</span>
                    <span className="text-[10px] font-bold uppercase tracking-wider bg-white/15 text-white px-2 py-0.5 rounded-full">{t('pricing.earlyAdopterBadge')}</span>
                  </div>
                  <div className="text-xs text-blue-100 mt-1.5 leading-relaxed">
                    <Trans i18nKey="landing:pricing.proOnceDesc" components={{ b: <span className="font-semibold text-white" /> }} />
                  </div>
                  <div className="text-[11px] text-white font-medium mt-1.5">{t('pricing.proCompareBeta', { earlyPrice: EARLY_PRICE, proPrice: PRO_PRICE })}</div>
                </>
              ) : (
                <>
                  <div className="mt-1 flex items-baseline gap-2">
                    <span className="text-5xl font-black text-white">${PRO_PRICE}</span>
                    <span className="text-sm text-blue-100">{t('pricing.oneTime')}</span>
                  </div>
                  <div className="text-xs text-blue-100 mt-1.5 leading-relaxed">
                    <Trans i18nKey="landing:pricing.proOnceDesc" components={{ b: <span className="font-semibold text-white" /> }} />
                  </div>
                  <div className="text-[11px] text-white font-medium mt-1.5">{t('pricing.proCompare', { proPrice: PRO_PRICE })}</div>
                </>
              )}
            </div>
            <ul className="space-y-2.5 text-sm text-white">
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-400" />
                <span>{t('pricing.proEverythingFree')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-400" />
                <span>{t('pricing.proSync')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-400" />
                <span>{t('pricing.proHistory')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-400" />
                <span>{t('pricing.proLock')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-400" />
                <span>{t('pricing.proPin')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-400" />
                <span>{t('pricing.proAnalytics')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-400" />
                <span>{t('pricing.proZen')}</span>
              </li>
              <li className="flex items-start gap-2">
                <CheckFat size={14} weight="fill" className="shrink-0 mt-1 text-emerald-400" />
                <span><Trans i18nKey="landing:pricing.proStorage" components={{ expand: <a href="#storage-addons" className="text-white underline hover:no-underline" /> }} /></span>
              </li>
            </ul>
          </div>
          </div>
        </div>

        {/* ── Storage add-on detail ───────────────────────────── */}
        <div id="storage-addons" className="max-w-4xl mx-auto mb-14 scroll-mt-24">
          <div className="pn-fx-lift rounded-2xl border-2 border-[var(--wl-ink)] bg-[var(--wl-card)] px-6 py-5 text-sm text-[var(--wl-sub)]">
            <div className="flex items-center gap-4">
              <Package size={64} weight="duotone" className="shrink-0 text-accent" />
              <div>
                <p className="font-extrabold text-[var(--wl-ink)] mb-1">{t('storageAddon.heading')}</p>
                <p className="leading-relaxed">
                  <Trans
                    i18nKey="landing:storageAddon.body"
                    values={{ price: STORAGE_ADDON_PRICE.toFixed(2) }}
                    components={{ brand: <Brand /> }}
                  />
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* ── Plus extras pills ───────────────────────────────── */}
        <div className="max-w-4xl mx-auto mb-2">
          <Kicker>{t('extras.kicker')}</Kicker>
        </div>
        <div className="pn-fx-popmix flex flex-wrap gap-2 text-xs text-[var(--wl-sub)] mb-14 max-w-4xl mx-auto">
          <FeaturePill>{t('extras.fileVault')}</FeaturePill>
          <FeaturePill>{t('extras.passwordVault')}</FeaturePill>
          <FeaturePill>{t('extras.cardStorage')}</FeaturePill>
          <FeaturePill>{t('extras.browserImport')}</FeaturePill>
          <FeaturePill>{t('extras.moodScale')}</FeaturePill>
          <FeaturePill>{t('extras.emotionTags')}</FeaturePill>
          <FeaturePill>{t('extras.sleepTracking')}</FeaturePill>
          <FeaturePill>{t('extras.activityLevel')}</FeaturePill>
          <FeaturePill>{t('extras.medAdherence')}</FeaturePill>
          <FeaturePill>{t('extras.energyFocus')}</FeaturePill>
          <FeaturePill>{t('extras.patternDetection')}</FeaturePill>
          <FeaturePill>{t('extras.doctorExport')}</FeaturePill>
          <FeaturePill>{t('extras.weekInReview')}</FeaturePill>
          <FeaturePill>{t('extras.selfDestruct')}</FeaturePill>
          <FeaturePill>{t('extras.anonAccounts')}</FeaturePill>
          <FeaturePill>{t('extras.zenMode')}</FeaturePill>
          <FeaturePill>{t('extras.darkMode')}</FeaturePill>
        </div>

        {/* ── Why privacy first? ──────────────────────────────────
             Concrete, pedestrian example. Kept neutral on purpose:
             the homepage has to read as a normal consumer product
             for payment processors. No law-enforcement angle, no
             surveillance framing - just the everyday "your notes
             shouldn't shop for you" story. */}
        <div className="max-w-4xl mx-auto mb-14">
          <Kicker>{t('whyPrivacy.kicker')}</Kicker>
          <h3 className="text-2xl sm:text-4xl font-black tracking-tight text-[var(--wl-ink)] max-w-2xl">
            <Trans i18nKey="landing:whyPrivacy.heading" components={{ accent: <span className="block text-accent" /> }} />
          </h3>
          <div className="mt-7 grid sm:grid-cols-2 gap-6 items-start">
            <div className="text-sm text-[var(--wl-sub)] leading-relaxed">
              <p>
                {t('whyPrivacy.para1')}
              </p>
              <p className="mt-3">
                {t('whyPrivacy.para2')}
              </p>
            </div>
            <div className="pn-fx-stamp rounded-2xl border-2 border-accent bg-[var(--wl-tint-blue)] p-5 sm:p-6" data-stamp="PRIVATE">
              <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-accent dark:text-blue-300 mb-2">
                {t('whyPrivacy.differenceLabel')}
              </div>
              <p className="text-sm leading-relaxed text-[var(--wl-ink)]">
                <Trans
                  i18nKey="landing:whyPrivacy.differenceBody"
                  components={{ brand: <Brand /> }}
                />
              </p>
            </div>
          </div>
          <div className="mt-6 border-t border-[var(--wl-line)] pt-3 text-xs text-[var(--wl-muted)] leading-relaxed">
            <Trans i18nKey="landing:whyPrivacy.keyboardNote" components={{ b: <span className="font-semibold text-[var(--wl-sub)]" /> }} />
          </div>
        </div>

        {/* ── Read it yourself ────────────────────────────────────
             Placed directly after the trust claim above, because it is
             the answer to it: the section before says we cannot read
             your notes, and this one hands over the files that prove
             it. The four rows are the whole route - the walkthrough,
             the attacker's view, the server's view, and the cipher.
             Every label names a real file, so a reader who does not
             recognise "threat model" still sees where they land. */}
        <div className="max-w-4xl mx-auto mb-14">
          <div className="rounded-xl border border-[var(--wl-ink-line)] bg-[var(--wl-ink-card)] p-6 sm:p-7">
            {/* 60/40 rather than even halves: the left column is a heading,
                a paragraph and a button, and at 50% the paragraph broke into
                short ragged lines while the file rows on the right sat in
                empty space. */}
            <div className="grid gap-7 sm:grid-cols-[3fr_2fr] sm:items-start">
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <GithubLogo size={16} weight="fill" className="text-emerald-400" />
                  <span className="text-xs font-mono font-medium text-emerald-400 uppercase tracking-widest">{t('readIt.kicker')}</span>
                </div>
                <h3 className="text-2xl font-black tracking-tight text-white">{t('readIt.heading')}</h3>
                <p className="mt-3 text-sm leading-relaxed text-[var(--wl-ink-sub)]">{t('readIt.body')}</p>
                <a
                  href={GITHUB_REPO_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="mt-5 inline-flex items-center gap-2 rounded-lg bg-white px-4 py-2.5 text-sm font-bold text-[var(--wl-ink-card)] transition hover:opacity-90"
                >
                  <GithubLogo size={17} weight="fill" className="shrink-0" aria-hidden="true" />
                  {t('readIt.cta')}
                </a>
              </div>
              <div className="flex flex-col">
                {READ_IT_DOCS.map((d, i) => (
                  <a
                    key={d.file}
                    href={d.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={`group flex items-center gap-3 py-3 transition ${i > 0 ? 'border-t border-[var(--wl-ink-line)]' : ''}`}
                  >
                    <d.icon size={18} className="shrink-0 text-emerald-400" aria-hidden="true" />
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm font-bold text-white transition group-hover:text-emerald-400">{t(d.labelKey)}</span>
                      <span dir="ltr" className="block font-mono text-xs text-[var(--wl-ink-sub)]">{d.file}</span> {/* rtl-ok: file name stays LTR */}
                    </span>
                    <ArrowUpRight size={15} className="shrink-0 text-[var(--wl-ink-sub)]" aria-hidden="true" />
                  </a>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── What you won't find ─────────────────────────────── */}
        <div className="max-w-4xl mx-auto mb-4">
          <Kicker className="text-[var(--wl-amber-text)]">{t('wontFind.kicker')}</Kicker>
          <div className="flex flex-wrap gap-2">
            {WONT_FIND_KEYS.map((k) => (
              <span key={k} className="pn-fx-shake rounded-full border-[1.5px] border-[var(--wl-amber-border)] bg-[var(--wl-tint-amber)] text-[var(--wl-amber-text)] px-3.5 py-1.5 text-xs font-bold">{t(k)}</span>
            ))}
          </div>
        </div>

      </div>

      {/* No recovery warning - dark terminal style matching "Under the Hood" */}
      <div className="mx-auto max-w-5xl px-5 sm:px-8">
        <div className="pn-fx-stamp pn-fx-stamp-bright max-w-4xl mx-auto rounded-xl border border-[var(--wl-ink-line)] bg-[var(--wl-ink-card)] p-6 sm:p-7 relative overflow-hidden" data-stamp="YOUR KEY">
          {/* Subtle grid background */}
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0 opacity-[0.04]"
            style={{ backgroundImage: 'linear-gradient(rgba(255,255,255,.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.1) 1px, transparent 1px)', backgroundSize: '24px 24px' }}
          />
          <div className="relative">
            <div className="flex items-center gap-2 mb-5">
              <TerminalWindow size={16} className="text-emerald-400" />
              <span className="text-xs font-mono font-medium text-emerald-400 uppercase tracking-widest">{t('noRecovery.heading')}</span>
            </div>
            <p className="text-sm text-[var(--wl-ink-text)] leading-relaxed mb-5">
              {t('noRecovery.body')}
            </p>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-5">
              <div className="space-y-1">
                <div className="font-mono text-sm font-semibold text-white">{t('noRecovery.noRecoveryTerm')}</div>
                <div className="text-xs text-[var(--wl-ink-sub)]">{t('noRecovery.noRecoveryDesc')}</div>
              </div>
              <div className="space-y-1">
                <div className="font-mono text-sm font-semibold text-white">{t('noRecovery.deviceTerm')}</div>
                <div className="text-xs text-[var(--wl-ink-sub)]">{t('noRecovery.deviceDesc')}</div>
              </div>
              <div className="space-y-1">
                <div className="font-mono text-sm font-semibold text-white">{t('noRecovery.zkTerm')}</div>
                <div className="text-xs text-[var(--wl-ink-sub)]">{t('noRecovery.zkDesc')}</div>
              </div>
              <div className="space-y-1">
                <div className="font-mono text-sm font-semibold text-white">{t('noRecovery.writeTerm')}</div>
                <div className="text-xs text-[var(--wl-ink-sub)]">{t('noRecovery.writeDesc')}</div>
              </div>
              <div className="space-y-1">
                <div className="font-mono text-sm font-semibold text-white">{t('noRecovery.printTerm')}</div>
                <div className="text-xs text-[var(--wl-ink-sub)]">{t('noRecovery.printDesc')}</div>
              </div>
              <div className="space-y-1">
                <div className="font-mono text-sm font-semibold text-white">{t('noRecovery.googleTerm')}</div>
                <div className="text-xs text-[var(--wl-ink-sub)]">{t('noRecovery.googleDesc')}</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── As seen on: the three sites that list us ──────────
           A credential strip, not an endorsement: each mark links
           back to the listing it names. The PrivacyTools badge keeps
           its own place up by the demo shot, because it carries a
           live star rating and these three do not. */}
      <div className="mx-auto max-w-5xl px-5 sm:px-8 mt-12">
        <div className="max-w-4xl mx-auto">
          <Kicker className="text-center text-[var(--wl-muted)]">{t('badges.asSeenOn')}</Kicker>
          <div className="flex flex-wrap items-center justify-center gap-x-10 gap-y-6">
            <a href="https://alternativeto.net" target="_blank" rel="noopener noreferrer">
              {/* Painted through a mask rather than drawn as an image: the
                  lockup is one flat colour, and the page ink is two
                  different colours by mode. A mask takes the ink token
                  itself, so there is one file instead of a light and a
                  dark copy that have to be kept identical by hand.
                  Spec: ops/docs/ui-patterns.md (section 93, one-colour partner logo) */}
              <span
                role="img"
                aria-label={t('badges.alternativeToAlt')}
                className="block h-[47px] w-[198px] bg-[var(--wl-ink)]"
                style={{
                  maskImage: 'url(/marketing/alternativeto.svg)',
                  WebkitMaskImage: 'url(/marketing/alternativeto.svg)',
                  maskSize: 'contain',
                  WebkitMaskSize: 'contain',
                  maskRepeat: 'no-repeat',
                  WebkitMaskRepeat: 'no-repeat',
                  maskPosition: 'center',
                  WebkitMaskPosition: 'center',
                }}
              />
            </a>
            {/* nosubscription.org has no logo, so the domain is set as one:
                the name in page ink, the TLD in accent blue. The hover rule
                paints its underline from --pn-fx-underline, so the two blues
                are one declaration and cannot drift apart. The accent is too
                dark to read on sumi ink, hence the lighter blue in dark. */}
            <a
              href="https://nosubscription.org"
              target="_blank"
              rel="noopener noreferrer"
              className="pn-fx-navlink text-[22px] font-bold tracking-tight text-[var(--wl-ink)] [--pn-fx-underline:var(--color-accent)] dark:[--pn-fx-underline:var(--color-blue-500)]"
            >
              <Trans
                i18nKey="landing:badges.nosubscription"
                components={{ tld: <span className="text-accent dark:text-blue-500" /> }}
              />
            </a>
            <a href="https://itsfoss.com" target="_blank" rel="noopener noreferrer">
              {/* Two brand greens that hold up on cream and on sumi ink
                  alike, so this one mark stays as it was drawn. */}
              <img
                src="/marketing/itsfoss.webp"
                alt={t('badges.itsFossAlt')}
                width="114"
                height="41"
                loading="lazy"
                className="block"
              />
            </a>
          </div>
        </div>
      </div>

      {/* ── Closing CTA: the page ends on an ask, not a warning ── */}
      <div className="mx-auto max-w-5xl px-5 sm:px-8 mt-16 sm:mt-24">
        <div className="max-w-4xl mx-auto text-center">
          <Kicker>{t('closing.kicker')}</Kicker>
          <h2 className="text-3xl sm:text-5xl font-black tracking-tight text-[var(--wl-ink)]">
            {t('closing.heading')}
          </h2>
          <div className="mt-7 grid grid-cols-2 sm:flex sm:flex-wrap justify-center items-center gap-2 sm:gap-3">
            <button
              type="button"
              onClick={() => openAuth('create')}
              className="pn-fx-conic-btn cursor-pointer rounded-full bg-[var(--wl-ink)] text-[var(--wl-bg)] px-3 sm:px-7 py-3.5 text-sm sm:text-base font-bold"
            >
              {t('header.createVault')}
            </button>
            <a
              href="https://try.privacynotes.app/"
              className="pn-fx-amber inline-flex items-center justify-center gap-2 rounded-full border-2 border-[var(--wl-amber-border)] text-[var(--wl-amber-text)] px-3 sm:px-6 py-3 text-sm sm:text-base font-bold transition"
            >
              {t('hero.tryDemo')}
              <ArrowUpRight size={16} className="shrink-0" aria-hidden="true" />
            </a>
          </div>
          <p className="mt-3 text-xs text-[var(--wl-muted)]">{t('hero.microcopy')}</p>
          <p className="mx-auto mt-6 max-w-md text-sm leading-relaxed text-[var(--wl-sub)]">
            {t('closing.importNote')}
          </p>
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            {GUIDE_ORDER.map((id) => {
              const meta = GUIDE_META[id];
              if (!meta) return null;
              return (
                <a
                  key={id}
                  href={`${helpPath(activeLocale())}/import/${id}`}
                  className="pn-fx-arrow inline-flex items-center gap-1.5 rounded-full border-[1.5px] border-[var(--wl-chip-border)] bg-[var(--wl-tint)] px-3 py-1.5 text-xs font-semibold text-[var(--wl-chip-text)] hover:bg-[var(--wl-card)] transition"
                >
                  {meta.icon ? (
                    <img src={`/help/icons/${meta.icon}`} alt="" width={16} height={16} loading="lazy" className="h-4 w-4 shrink-0" />
                  ) : (
                    // A guide with no app logo wears the pillar glyph instead.
                    <Key size={16} aria-hidden="true" className="h-4 w-4 shrink-0" />
                  )}
                  {meta.name}
                </a>
              );
            })}
          </div>
        </div>
      </div>

      </main>

      <SiteFooter />

    </div>
  );
}
