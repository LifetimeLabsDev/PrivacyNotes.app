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
