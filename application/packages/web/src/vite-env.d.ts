/// <reference types="vite/client" />

/**
 * The platform Tauri is building for ('ios' | 'android' | 'darwin' |
 * 'windows' | 'linux'), injected by vite.config.ts from TAURI_ENV_PLATFORM.
 * Empty string for the plain web build. Authoritative: it is decided by the
 * build, not sniffed from the browser at runtime.
 */
declare const __PN_BUILD_PLATFORM__: string;
