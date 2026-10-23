/**
 * Every key of a stored vault body, as an object to spread under the fields
 * a form writes.
 *
 * The login, card and SSH key forms save an item by writing the fields they
 * know. A newer version can store more keys in the same JSON body, and a save
 * from here must carry them back unchanged: a dropped key is data lost, and a
 * dropped `pn:file/` reference lets blob GC delete the file it names. The
 * caller writes its own fields after the spread, so they always win.
 */
export function storedVaultKeys(previous: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(previous);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
