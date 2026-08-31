/**
 * Lightweight device fingerprint for dedup.
 *
 * Prevents the same physical machine from consuming multiple device
 * slots after a cache clear or browser switch. Signals are chosen for
 * stability (survive cache wipes, browser switches, travel) and
 * discrimination (distinguish two machines owned by the same user).
 *
 * Raw values stay in this module. Callers receive only hashed output
 * via `hashFingerprint`; the server never sees the underlying OS, GPU,
 * cores, or language strings.
 *
 * See ops/docs/device-fingerprint.md for collection rationale and
 * ops/docs/device-fingerprint-hash.md for the hashing design.
 */

import { computeFpHashes, type FpHashes } from '@notes/shared';

export interface DeviceFingerprint {
  /** Normalized OS: "macOS", "Windows", "Linux", "iPhone", "iPad", "Android". */
  platform: string;
  /** WebGL unmasked renderer, e.g. "ANGLE (Apple, Apple M4, OpenGL 4.1)" */
  gpu: string;
  /** navigator.hardwareConcurrency, e.g. 10 */
  cores: number;
  /** navigator.language, e.g. "en-US" */
  language: string;
}

/** Collect the four fingerprint signals from the current browser. */
export function collectFingerprint(): DeviceFingerprint {
  return {
    platform: detectDeviceOs(),
    gpu: getGpuRenderer(),
    cores: navigator.hardwareConcurrency || 0,
    language: navigator.language || 'unknown',
  };
}

/**
 * Stable OS/device identifier from User-Agent.
 *
 * `navigator.platform` is deprecated and unreliable:
 *   - Returns "MacIntel" on ALL Macs (including Apple Silicon)
 *   - Returns "MacIntel" on iPads (iOS 13+ desktop mode)
 *   - `navigator.userAgentData` only works on Chrome/Edge, not Safari
 *
 * UA string parsing is the only reliable cross-browser method. Order
 * matters: iPhone/iPad must come before "Macintosh" because iPads in
 * desktop mode include "Macintosh" in the UA.
 */
export function detectDeviceOs(): string {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'iPad';
  if (/Android/.test(ua)) return 'Android';
  if (/Windows NT/.test(ua)) return 'Windows';
  if (/Mac OS X|Macintosh/.test(ua)) return 'macOS';
  if (/CrOS/.test(ua)) return 'ChromeOS';
  if (/Linux/.test(ua)) return 'Linux';
  return navigator.platform || 'unknown';
}

/**
 * Hash this device's fingerprint with the user-derived pepper. The raw
 * DeviceFingerprint stays inside this module - callers only see the
 * four opaque per-field hashes.
 */
// Spec: ops/docs/device-fingerprint-hash.md (per-field client-side hashing)
export function hashFingerprint(
  fp: DeviceFingerprint,
  pepper: Uint8Array,
): FpHashes {
  return computeFpHashes(pepper, fp);
}

/**
 * GPU renderer string via gl.RENDERER.
 *
 * We intentionally skip WEBGL_debug_renderer_info (deprecated in Firefox,
 * blocked by Brave). gl.RENDERER is less specific but consistent across
 * browsers on the same machine - which is exactly what we need for
 * same-device grouping.
 *
 * Typical values:
 *   Chrome/Edge: "ANGLE (Apple, Apple M4, OpenGL 4.1)"
 *   Firefox:     "Apple M4" or "ANGLE (...)" (varies by version)
 *   Safari:      "Apple GPU"
 *
 * Spec: ops/docs/device-fingerprint.md (section 3.6)
 */
function getGpuRenderer(): string {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2') || canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'unknown';
    const glCtx = gl as WebGLRenderingContext;
    const renderer = glCtx.getParameter(glCtx.RENDERER);
    return renderer || 'unknown';
  } catch {
    return 'unknown';
  }
}
