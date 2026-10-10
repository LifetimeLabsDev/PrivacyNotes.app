/**
 * The text of an SSH key as a file that `ssh` accepts.
 *
 * OpenSSH reads an Ed25519 private key only in its own format on every build:
 * the LibreSSL build macOS ships refuses a PKCS#8 "BEGIN PRIVATE KEY" file as
 * "invalid format". So the generator writes the OpenSSH format, and a stored
 * PKCS#8 Ed25519 key is converted when it is downloaded. Any other key is
 * written as stored, with LF line ends and the final newline OpenSSH needs.
 */

import { saveBlob, type SaveResult } from './saveFile';

// The whole DER of a PKCS#8 v1 Ed25519 key, minus the 32-byte seed at its end.
const PKCS8_ED25519_PREFIX = [
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const enc = new TextEncoder();

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function uint32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

/** The SSH wire `string`: a big-endian length, then the bytes. */
function sshString(bytes: Uint8Array): Uint8Array {
  return concat(uint32(bytes.length), bytes);
}

function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function fromBase64Url(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  return fromBase64(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
}

/** The 32-byte seed of a PKCS#8 Ed25519 key, or null for any other key. */
export function ed25519SeedFromPkcs8(der: Uint8Array): Uint8Array | null {
  if (der.length !== PKCS8_ED25519_PREFIX.length + 32) return null;
  if (!PKCS8_ED25519_PREFIX.every((b, i) => der[i] === b)) return null;
  return der.slice(PKCS8_ED25519_PREFIX.length);
}

/** An unencrypted "openssh-key-v1" private key, the format `ssh-keygen` writes. */
export function openSshEd25519PrivateKey(seed: Uint8Array, publicKey: Uint8Array, comment: string): string {
  const type = enc.encode('ssh-ed25519');
  const none = enc.encode('none');
  const check = crypto.getRandomValues(new Uint8Array(4));
  const priv = concat(
    check,
    check,
    sshString(type),
    sshString(publicKey),
    sshString(concat(seed, publicKey)),
    sshString(enc.encode(comment)),
  );
  // Padded to the 8-byte block of the "none" cipher with the bytes 1, 2, 3...
  const pad = Uint8Array.from({ length: (8 - (priv.length % 8)) % 8 }, (_, i) => i + 1);
  const body = concat(
    enc.encode('openssh-key-v1\0'),
    sshString(none),
    sshString(none),
    sshString(new Uint8Array(0)),
    uint32(1),
    sshString(concat(sshString(type), sshString(publicKey))),
    sshString(concat(priv, pad)),
  );
  const lines = toBase64(body).match(/.{1,70}/g) ?? [];
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

/** The 32 public bytes of an "ssh-ed25519 <base64>" line, or null. */
function ed25519PublicFromLine(line: string): Uint8Array | null {
  const [type, b64] = line.trim().split(/\s+/);
  if (type !== 'ssh-ed25519' || !b64) return null;
  try {
    const wire = fromBase64(b64);
    const name = enc.encode('ssh-ed25519');
    const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
    if (wire.length !== 4 + name.length + 4 + 32 || view.getUint32(0) !== name.length) return null;
    if (view.getUint32(4 + name.length) !== 32) return null;
    return wire.slice(wire.length - 32);
  } catch {
    return null;
  }
}

async function pkcs8ToOpenSsh(pem: string, comment: string, publicLine: string): Promise<string | null> {
  const der = fromBase64(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
  const seed = ed25519SeedFromPkcs8(der);
  if (!seed) return null;
  let pub: Uint8Array | null = null;
  try {
    const key = await crypto.subtle.importKey('pkcs8', der as Uint8Array<ArrayBuffer>, 'Ed25519' as unknown as AlgorithmIdentifier, true, ['sign']);
    const jwk = await crypto.subtle.exportKey('jwk', key);
    if (jwk.x) pub = fromBase64Url(jwk.x);
  } catch {
    // A WebView without Ed25519 in Web Crypto (Firefox before 130, older
    // WebKitGTK): the item's own public key line holds the same 32 bytes.
  }
  pub = pub ?? ed25519PublicFromLine(publicLine);
  return pub ? openSshEd25519PrivateKey(seed, pub, comment) : null;
}

export async function privateKeyFileText(privateKey: string, comment: string, publicLine = ''): Promise<string> {
  const text = privateKey.replace(/\r\n?/g, '\n').trim();
  if (text.startsWith('-----BEGIN PRIVATE KEY-----')) {
    try {
      const converted = await pkcs8ToOpenSsh(text, comment, publicLine);
      if (converted) return converted;
    } catch {
      // A key that is not Ed25519 PKCS#8 is written as stored.
    }
  }
  return `${text}\n`;
}

export function publicKeyFileText(publicKey: string): string {
  return `${publicKey.replace(/\s+/g, ' ').trim()}\n`;
}

/** Saves one half of a key pair as `id_<type>` or `id_<type>.pub`. */
export async function downloadSshKey(
  which: 'private' | 'public',
  key: { privateKey: string; publicKey: string },
): Promise<SaveResult> {
  const name = keyFileName(key.publicKey);
  const comment = key.publicKey.trim().split(/\s+/).slice(2).join(' ');
  const text = which === 'private' ? await privateKeyFileText(key.privateKey, comment, key.publicKey) : publicKeyFileText(key.publicKey);
  return saveBlob(new Blob([text], { type: 'application/octet-stream' }), which === 'private' ? name : `${name}.pub`);
}

/** The file name `ssh-keygen` gives a key of this type. */
export function keyFileName(publicKey: string): string {
  const type = publicKey.trim().split(/\s+/)[0] ?? '';
  if (type === 'ssh-ed25519') return 'id_ed25519';
  if (type === 'ssh-rsa') return 'id_rsa';
  if (type.startsWith('ecdsa-sha2-')) return 'id_ecdsa';
  if (type === 'sk-ssh-ed25519@openssh.com') return 'id_ed25519_sk';
  if (type === 'sk-ecdsa-sha2-nistp256@openssh.com') return 'id_ecdsa_sk';
  return 'ssh_key';
}
