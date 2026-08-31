// Build-time replacement for @supabase/realtime-js.
//
// PrivacyNotes never opens a realtime subscription: notes sync through
// sync.ts polling plus the edge functions, and nothing in the app calls
// supabase.channel(). But @supabase/supabase-js constructs a RealtimeClient
// in its own constructor and re-exports the whole module, so the real
// package (plus its @supabase/phoenix dependency) shipped in the entry
// chunk regardless. Aliased away in vite.config.ts.
//
// setAuth() is a silent no-op on purpose: supabase-js calls it on every
// auth state change, so throwing there would break sign-in. Everything
// that means "the app actually wants realtime" throws instead, loudly, so
// a future feature that needs it fails immediately rather than going
// quietly dead.
//
// Spec: ops/docs/bundle-size.md (section 5). Storage-js was stubbed the
// same way in 0.264.0 and broke every attachment upload (#202) - before
// stubbing another client, grep its call surface, not its import name.

const UNAVAILABLE =
  'Realtime is stubbed out of this build (packages/web/stubs/realtime-js.js). ' +
  'Remove the alias in vite.config.ts to use @supabase/realtime-js.';

export class RealtimeClient {
  constructor() {}
  setAuth() {
    return Promise.resolve();
  }
  connect() {}
  disconnect() {}
  getChannels() {
    return [];
  }
  channel() {
    throw new Error(UNAVAILABLE);
  }
  removeChannel() {
    throw new Error(UNAVAILABLE);
  }
  removeAllChannels() {
    throw new Error(UNAVAILABLE);
  }
}

export class RealtimeChannel {}
export class RealtimePresence {}

export const REALTIME_LISTEN_TYPES = {};
export const REALTIME_SUBSCRIBE_STATES = {};
export const REALTIME_POSTGRES_CHANGES_LISTEN_EVENT = {};
export const REALTIME_CHANNEL_STATES = {};

export default RealtimeClient;
