/**
 * A note's tags in reading order: alphabetical, case-insensitive, with
 * digit runs compared as numbers so `tag2` precedes `tag10`. Same collator
 * settings as the folder sibling sorter, so a folder chip and the tag chips
 * beside it order their names by one rule.
 *
 * A DISPLAY order, never a stored one. The array on the note keeps the order
 * the tags were typed in, so nothing is rewritten and no note is marked dirty;
 * every existing note reads sorted from the moment it is drawn. Call it at
 * each place tags are rendered, and derive any position-based action (which
 * chip is last) from the result rather than from the note's own array.
 *
 * Its own module so the settings code can read the same order without
 * loading the note store: which tag gives a note its color follows it too.
 * Spec: issue #259.
 */
export function sortTags(tags: string[]): string[] {
  return tags
    .slice()
    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base', numeric: true }));
}
