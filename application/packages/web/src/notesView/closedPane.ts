/**
 * Closing the last tab empties the editor pane. The list would otherwise put
 * its first item back at once, so the pane stays empty while the list keeps
 * the scope it had at the close: a sync refresh or a re-sort keeps it empty,
 * and a new view, folder, tag, space or search lets the list pick again.
 * Spec: ops/issues/0568.md (Spec)
 */
export function listScopeKey(
  view: string,
  folder: string | null,
  tag: string | null,
  space: string | null,
  search: string,
): string {
  return JSON.stringify([view, folder, tag, space, search]);
}

/** True while the pane stays empty after a close in this scope. */
export function keepsEmptyPane(closedScope: string | null, scope: string, selectedId: string | null): boolean {
  return selectedId === null && closedScope !== null && closedScope === scope;
}
