/**
 * Ambient fallback declaration for `qr-scanner`.
 *
 * The real package ships its own .d.ts so this declaration is only
 * used as a fallback when the dep hasn't been installed yet (e.g.
 * right after a fresh pull before `pnpm install`). Once the real
 * types load, TypeScript prefers those over this stub.
 *
 * We import the library via dynamic `import('qr-scanner')` and cast
 * to `any` at the call site, so we don't care about fidelity here -
 * we just need TypeScript to stop complaining about the missing
 * module during typecheck.
 */
declare module 'qr-scanner';
