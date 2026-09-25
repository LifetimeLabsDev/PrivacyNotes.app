/**
 * The sidebar's selected-state token - the single source of truth for what a
 * selected row, segmented half or rail button looks like. Used by TagsRail,
 * FolderTree, MarkdownRail and CollapsedSidebar, which are one control family
 * and must never drift apart.
 *
 * The accent TINT carries "selected"; the label stays at full strength. An
 * accent label on an accent tint measured 3.5:1 (Cream) to 4.8:1 (Slate) -
 * under AA for the 12-15px text the sidebar uses, and weaker than the
 * unselected rows beside it, which is backwards for the one row that matters.
 * Full-strength text on the same tint measures 7.9:1 to 14.2:1 in every theme.
 * Icons stay `text-accent`: a 16px glyph needs 3:1, and the worst theme clears
 * it, so the row keeps its accent identity.
 *
 * The settings segmented control (color-themes.md, "The segmented control")
 * already makes the same trade with a raised surface instead of a tint.
 *
 * Spec: ops/docs/ui-patterns.md section 37 (sidebar selection)
 */
export const SIDEBAR_ACTIVE =
  'bg-accent/15 hover:bg-accent/20 dark:bg-accent/20 dark:hover:bg-accent/25 text-pn';

/**
 * The "..." that opens a folder or tag row's menu, in the sidebar and in the
 * Move to folder window. A pointer reveals it on hover. Tailwind gates `hover:`
 * behind `(hover: hover)`, so on a touch screen it has to stay visible on its
 * own: there it is the only visible way into rename, move and delete.
 *
 * On touch the button also fills the row's height, and the `::after` layer
 * widens it to 44px, so each target is exactly its own row and never reaches
 * into a neighbour's. The height stays the row's: every drawer row is 39px on
 * a phone, and a 44px-tall target would need taller rows.
 * Spec: ops/docs/ui-patterns.md section 53 (sidebar rows)
 */
export const SIDEBAR_ROW_MENU_BUTTON =
  'shrink-0 inline-flex items-center justify-center w-6 h-6 rounded text-neutral-500 hover:text-accent hover:bg-neutral-300/60 dark:hover:bg-neutral-800/60 opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity [@media(hover:none)]:opacity-100 [@media(hover:none)]:self-stretch [@media(hover:none)]:h-auto [@media(hover:none)]:relative [@media(hover:none)]:after:absolute [@media(hover:none)]:after:inset-y-0 [@media(hover:none)]:after:-inset-x-2.5';
