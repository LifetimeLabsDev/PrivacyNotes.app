import { createClient, type SupabaseClient } from '@supabase/supabase-js';

/**
 * Minimal subset of the DOM `Storage` interface that supabase-js will
 * actually call. Declared locally so non-browser callers (Tauri, SSR)
 * don't need `lib: ["dom"]` to import this module.
 */
export interface SupabaseAuthStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

export type CreateSupabaseClientOptions = {
  /**
   * Optional storage backing for the auth session. When omitted,
   * supabase-js falls back to its own default (localStorage in a
   * browser). Callers that want "trust this device" semantics pass
   * a wrapper that routes writes between local and session storage.
   */
  storage?: SupabaseAuthStorage;
  /**
   * Whether supabase-js should consume an OAuth return from the URL on
   * init: a `?code=` exchange under `pkce`, a token fragment under
   * `implicit`. Defaults to false (safe for Tauri / SSR). The web client
   * sets this to true so OAuth redirects work.
   */
  detectSessionInUrl?: boolean;
  /**
   * Whether to persist the auth session at all. Defaults to true.
   * Set to false for lightweight anon clients (e.g. burn-after-reading)
   * that don't need session state and would otherwise create duplicate
   * GoTrueClient instances sharing the same storage key.
   */
  persistSession?: boolean;
  /**
   * Custom storage key prefix for the auth session. Defaults to
   * supabase-js's built-in key. Use a unique value when creating
   * secondary clients to avoid the "Multiple GoTrueClient instances"
   * warning.
   */
  storageKey?: string;
  /**
   * OAuth flow. `pkce` sends a code challenge with the authorize request
   * and gets back a one-time `?code=` that only the client holding the
   * matching verifier can exchange; `implicit` gets tokens in the URL
   * fragment. Omitted, supabase-js applies its own default (implicit).
   * The app client sets `pkce`.
   */
  flowType?: 'implicit' | 'pkce';
};

/**
 * Create a Supabase client configured for PrivacyNotes.
 * Called once on app boot with the URL + anon key from env.
 */
export function createSupabaseClient(
  url: string,
  anonKey: string,
  options?: CreateSupabaseClientOptions
): SupabaseClient {
  return createClient(url, anonKey, {
    auth: {
      persistSession: options?.persistSession ?? true,
      autoRefreshToken: options?.persistSession ?? true,
      detectSessionInUrl: options?.detectSessionInUrl ?? false,
      ...(options?.storage ? { storage: options.storage } : {}),
      ...(options?.storageKey ? { storageKey: options.storageKey } : {}),
      ...(options?.flowType ? { flowType: options.flowType } : {}),
    },
  });
}

export type { SupabaseClient };
