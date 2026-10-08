/**
 * Removing one account's copy of a credential, and nobody else's.
 *
 * A credential key can have a copy in this tab's sessionStorage and another in
 * the localStorage every tab shares (trustStorage.ts). The two can belong to
 * different accounts: a tab the person did not trust keeps its own, while the
 * shared one is another tab's. trustAwareStorage reads the tab copy first and
 * removes both, so a check made through it can authorize the removal of a copy
 * it never looked at. Every copy is therefore read, judged and removed in its
 * own store, and removed only while it is still the value that was judged,
 * because the judgement can await and another tab can write meanwhile.
 *
 * The demo keeps its session keys in memory, never in these stores, and
 * shares the origin with a real install, so it removes nothing here.
 */
import { isDemoMode } from './demo';

function stores(): Storage[] {
  const out: Storage[] = [];
  try { out.push(sessionStorage); } catch { /* unavailable */ }
  try { out.push(localStorage); } catch { /* unavailable */ }
  return out;
}

/** Remove each store's copy of `key` that `matches` accepts. Answers the
 *  values removed. */
export async function removeMatchingCopies(
  key: string,
  matches: (value: string) => boolean | Promise<boolean>,
): Promise<string[]> {
  const removed: string[] = [];
  if (isDemoMode()) return removed;
  for (const store of stores()) {
    let value: string | null;
    try {
      value = store.getItem(key);
    } catch {
      continue;
    }
    if (value === null || !(await matches(value))) continue;
    try {
      if (store.getItem(key) === value) {
        store.removeItem(key);
        removed.push(value);
      }
    } catch {
      /* unavailable: nothing was removed */
    }
  }
  return removed;
}

/** The access token of a stored Supabase session, or null. */
export function storedAccessToken(value: string): string | null {
  try {
    const token = (JSON.parse(value) as { access_token?: unknown } | null)?.access_token;
    return typeof token === 'string' ? token : null;
  } catch {
    return null;
  }
}
