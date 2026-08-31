/**
 * Holder for the local-data key (the at-rest seal key derived from the
 * phrase, deriveLocalDataKey in @notes/shared). Auth registers it the
 * moment it is derived - BEFORE setAuth, because the fresh-vault seed
 * writes notes before the auth state exists - and clears it on sign-out.
 *
 * Consumers never keep the registered reference across an await:
 * sign-out zeroes key material in place (the imageStore keyCopy
 * precedent), so every use takes a fresh copy and treats an all-zero
 * read as "no key".
 *
 * Spec: ops/docs/plans/local-at-rest.md (key lifecycle, section 3.1)
 */

let current: Uint8Array | null = null;
const clearListeners = new Set<() => void>();

/** Runs whenever the key is cleared. The seal layer drops its plaintext
 *  memo through this, so cached content can never outlive the key. */
export function onLocalDataKeyCleared(cb: () => void): void {
  clearListeners.add(cb);
}

export function registerLocalDataKey(key: Uint8Array): void {
  current = key;
}

export function clearLocalDataKey(): void {
  if (current) current.fill(0);
  current = null;
  for (const cb of clearListeners) cb();
}

/**
 * A defensive copy of the key, or null when no usable key exists. An
 * all-zero buffer means sign-out already zeroed the registered array in
 * place - callers must treat that exactly like "no key registered".
 */
export function localDataKeyCopy(): Uint8Array | null {
  if (!current) return null;
  let nonZero = false;
  for (const b of current) {
    if (b !== 0) {
      nonZero = true;
      break;
    }
  }
  if (!nonZero) return null;
  return new Uint8Array(current);
}
