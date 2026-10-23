// The UI library: the one import for every control in the app.
// `ops/design/COMPONENTS.md` is generated from the @catalog blocks below and in
// each part's file (`pnpm check:components` fails when it is stale).
// Spec: ops/docs/archive/design-system.md

export { Button, IconButton, CloseButton } from './Button';
export { VaultFieldAction } from './VaultFieldAction';
export { TextField, Select } from './fields';
export { DeleteButton } from './DeleteButton';
export { EditRow } from './EditRow';
export { useProGate } from './proGate';
export { Modal, ModalFooter } from './Modal';
export { FeedbackButton, Callout, Banner, Snackbar, Badge, Spinner, ProgressBar, StatusLine, EmptyState } from './feedback';
export { Checkbox } from './Checkbox';
export { TaskCheckbox } from './TaskCheckbox';
export { Popover, Kbd, Divider, CopyButton, IconTile } from './misc';

/**
 * @catalog Switch
 * use: every on/off setting. The whole row is the label; `description` sits under it; `icon` before it.
 * never: a checkbox for a setting; an On/Off segmented control; a hand-drawn knob.
 */
export { Switch } from '../Switch';

/**
 * @catalog Segmented (SettingsSegmented, SETTINGS_TRACK + settingsSegClass)
 * use: one choice out of two to seven, visible at once: a range, a layer, Same day / Next day. `SettingsSegmented` in a toolbar or chart header; `SETTINGS_TRACK` with `settingsSegClass` in a setting row.
 * never: a black or green pill; rounded-full chips for a choice; a select for three options.
 */
export { SettingsSegmented, SETTINGS_TRACK, settingsSegClass } from '../settingsUI';

/**
 * @catalog SectionEyebrow (SETTINGS_EYEBROW)
 * use: the heading of a section: uppercase, accent, with a 13px glyph (`icon`).
 * never: a hand-written uppercase class string; a bold sentence-case section heading.
 */
export { SectionEyebrow, SETTINGS_EYEBROW, EYEBROW_ICON_ROW, EyebrowGlyph } from '../settingsUI';

/**
 * @catalog RowTitle (ROW_TITLE, SETTINGS_ROW)
 * use: a setting row: `RowTitle` with its glyph and a `SETTINGS_HELP` line on the left, the control on the right; `SETTINGS_ROW` lays it out.
 * never: a row title without a glyph; a helper line in another size or tone.
 */
export { RowTitle, ROW_TITLE, SETTINGS_ROW, SETTINGS_HELP } from '../settingsUI';

/**
 * @catalog SETTINGS_BTN, SETTINGS_BTN_PRIMARY, SETTINGS_BTN_DANGER, SETTINGS_BTN_UPGRADE, SETTINGS_SELECT
 * use: the class strings behind Button and the fields, for a link or a label that must look like one.
 * never: a near copy of these strings with one class changed.
 */
export { SETTINGS_BTN, SETTINGS_BTN_PRIMARY, SETTINGS_BTN_DANGER, SETTINGS_BTN_UPGRADE, SETTINGS_SELECT } from '../settingsUI';

/**
 * @catalog StatTile
 * use: one number with its label (label above, value below, an optional line under it), in Statistics and Week in review.
 * never: a bare big number with an uppercase label under it.
 */
export { StatTile } from '../settingsUI';

/**
 * @catalog SettingsCallout
 * use: `Callout` in its info tone, under the name the settings panes use.
 * never: a warning as a grey helper line; an amber box of your own.
 */
export { SettingsCallout } from '../settingsUI';

/**
 * @catalog ResetDefaultsButton
 * use: the foot of every preference pane or tab that has defaults. It resets what the pane shows, never a person's own lists.
 * never: a reset without the armed confirm; a reset that clears custom data.
 */
export { ResetDefaultsButton } from '../settingsUI';

/**
 * @catalog SettingsTabStrip (settingsTabClass)
 * use: the tabs of a pane, directly under the pane title and outside its scroll area.
 * never: tabs inside the scroll area; a second tab style.
 */
export { SettingsTabStrip, settingsTabClass } from '../settingsUI';

/**
 * @catalog ProMark, IconUpgrade
 * use: `ProMark` (rocket and "Pro") after a heading or a row title; `IconUpgrade` (the rocket alone) on a button or a tab.
 * never: an amber "PRO" pill; a gold color of your own.
 */
export { ProMark, IconUpgrade } from '../UpgradeModal';

/**
 * @catalog HelpChip
 * use: the link to the help question this screen raises, at the foot of a settings pane or tab.
 * never: a help link at the top of a pane or between rows; a hand-written help link.
 */
export { HelpChip } from '../HelpChip';

/**
 * @catalog ScaleTiles, MoodScale
 * use: every 0 to 10 or 1 to 10 choice (mood, energy, focus, pain): one tile row, one height. `MoodScale` for mood.
 * never: a second scale component; a slider for a scale.
 */
export { ScaleTiles, MoodScale } from '../MoodScale';

/**
 * @catalog HoverLabel
 * use: the tooltip of a control; `keys` shows its shortcut. `IconButton` already wraps it.
 * never: a `title` attribute as the only tooltip; a tooltip of your own.
 */
export { HoverLabel } from '../HoverLabel';

/**
 * @catalog Tracker panel parts (PanelQuestion, ChoiceGrid, Segmented, NumberStepper, chipClass, CHIP_ADD)
 * use: inside a tracker panel of the check-in card or a journal entry only: the question, equal choice tiles, a joined pair (Taken | Skipped, kg | lb), the number stepper with quick picks, a many-value chip and the dashed add chip. Their compact sizes are part of the panel language.
 * never: in a Settings pane (use the settings parts); a second stepper, chip or choice grid for a tracker.
 */
export { PanelQuestion, ChoiceGrid, Segmented as PanelSegmented, NumberStepper, chipClass, CHIP_ADD } from '../trackers/panelUI';

/**
 * @catalog FieldLabel, GroupHeading, FIELD_CLASS, FIELD_BUTTON
 * use: the item-form kit (login, card, SSH key, contact): `FieldLabel` over a field you lay out yourself (a field with a copy or reveal button beside it), `GroupHeading` over a section of a form, `FIELD_CLASS` for a textarea or a field `TextField` cannot be, `FIELD_BUTTON` for a button beside a field.
 * never: a second label or section-heading style; a button inside the field box.
 */
export { FieldLabel, GroupHeading, FIELD_CLASS, FIELD_BUTTON } from '../formFields';

/**
 * @catalog ContextMenu (useContextMenu)
 * use: every menu of actions, from a right-click, a long press or a "more" button: rows with a 16px accent icon, a shortcut, a check for a toggle, a Pro mark, a red destructive row, separators and an uppercase header. `useContextMenu` holds its state.
 * never: a menu list of your own; a menu row in another size, hover or separator style; a Delete row for an item whose row has a DeleteButton (delete confirms in place).
 */
export { ContextMenu, useContextMenu } from '../ContextMenu';

export { BackRow } from './BackRow';
export { GlyphTile, ItemSwitcher, SubViewHeader, type SwitcherItem } from './ItemSwitcher';

/**
 * @catalog ListSearchInput
 * use: the search field over a list or a picker: the glass, the field, the clear button.
 * never: a search input of your own, with its own glass size or height.
 */
export { ListSearchInput } from '../ListSearchInput';

/**
 * @catalog ColorSwatch
 * use: one color choice (a note, tag or folder color, a text or highlight color): the round swatch, its selected ring, the "no color" swatch, the label as a tooltip.
 * never: a colored dot of your own as a choice; a legend dot is not a choice.
 */
export { ColorSwatch } from '../ColorSwatch';

/**
 * @catalog ColorSwatchRow
 * use: every choice of a palette color for an item (a note, a folder or tag look, a Kanban column): "no color" first, the palette through the theme's label tokens, the touch size, an optional dashed ring for an inherited color.
 * never: a row of ColorSwatch of your own over LOOK_COLORS; another gap, size or color source for the same choice.
 */
export { ColorSwatchRow } from '../ColorSwatch';

/**
 * @catalog InlineRenameField
 * use: renaming in place (a file chip, a device row): Enter and blur commit, Escape cancels, an input method's Enter is left alone.
 * never: a rename input of your own with its own underline or key handling.
 */
export { InlineRenameField } from '../InlineRenameField';

/**
 * @catalog MonthGrid
 * use: (import from `MonthGrid.tsx` directly, not from ui) every date choice and every month view: the title with the arrows, the week row, dots on days with items, today ringed, the chosen day filled; `weeks={1}` for the week strip.
 * never: a native date input; a calendar grid of your own.
 */
// MonthGrid is imported from '../MonthGrid' directly: it loads the note row,
// and through this index it would load into every file that imports ui.

/**
 * @catalog StorageBar
 * use: storage used against the limit: the "N% used (X / Y)" line, the fill track and the refresh control.
 * never: a usage bar of your own.
 */
export { StorageBar } from '../StorageBar';

/**
 * @catalog UpdateToast
 * use: a toast with an icon tile, a title, a meta line and one action, at the bottom end of the window: an update, a reminder.
 * never: a toast card of your own.
 */
export { UpdateToast } from '../UpdateToast';

/**
 * @catalog DetailHero, DetailGroup, DetailRow, DetailAction, DetailCopyAction, DetailLink, DetailNotes, DETAIL_COLUMN
 * use: a read-only label-and-value pane (a login, a card, a contact): the hero with its tile and Edit, a group heading with a rule, rows with an accent icon and label, one outlined group of row actions with copy, a link, the notes block.
 * never: a value row, a copy button or a group heading of your own in such a pane.
 */
export { DetailHero, DetailGroup, DetailRow, DetailAction, DetailCopyAction, DetailLink, DetailNotes, DetailTile, DETAIL_COLUMN } from '../detailPane';

export { VaultFormActions } from './VaultFormActions';
