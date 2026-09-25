/**
 * The icons a folder or a tag can wear, in the groups the picker shows them.
 *
 * Loaded on its own (`lookIconsLoader.ts`), so no boot path carries it: the
 * picker opens it, and so does the first glyph that has an icon to draw. It
 * holds data only, the bold-weight paths generated from Phosphor
 * (`lookIconPaths.gen.ts`): a chunk that imported icon components the rest of
 * the app also uses would pull those shared icons out of the boot chunks.
 *
 * An id is stored in the synced settings and is permanent: never rename or
 * remove one. A retired icon leaves LOOK_ICON_GROUPS and moves to
 * RETIRED_LOOK_ICON_IDS, so its paths are still generated and a folder that
 * wears it still draws it. A name is `looks:icons.<id>`; the numbers share
 * `looks:number`. After any change to the ids here, run
 * `node tools/gen-look-icons.mjs`.
 * Spec: ops/docs/plans/folder-tag-icons.md (section 3)
 */
import { LOOK_ICON_PATHS } from './lookIconPaths.gen';

/** Picker order. */
export const LOOK_ICON_GROUPS: readonly { key: string; ids: readonly string[] }[] = [
  {
    key: 'mark',
    ids: [
      'folder', 'archive', 'star', 'heart', 'flag', 'check-circle', 'lightbulb', 'sparkle',
      'bookmark-simple', 'push-pin', 'notebook', 'books', 'question', 'warning', 'target',
      'trophy', 'tag', 'paperclip', 'link', 'sticker', 'stack', 'tray', 'medal', 'certificate',
    ],
  },
  {
    key: 'work',
    ids: [
      'briefcase', 'laptop', 'calendar', 'clipboard-text', 'chart-line', 'graduation-cap',
      'book-open', 'pencil', 'code', 'users', 'envelope', 'chat', 'phone', 'flask', 'puzzle-piece',
      'rocket-launch', 'kanban', 'presentation-chart', 'desk', 'printer', 'calculator',
      'handshake', 'identification-card', 'megaphone', 'translate', 'scales', 'gavel', 'pen-nib',
      'scissors', 'signature', 'stamp', 'lectern',
    ],
  },
  {
    key: 'files',
    ids: [
      'file-md', 'file-txt', 'file-pdf', 'file-doc', 'file-xls', 'file-ppt', 'file-csv', 'file-zip',
      'file-image', 'file-video', 'file-audio', 'file-code',
    ],
  },
  {
    key: 'shopping',
    ids: [
      'wallet', 'piggy-bank', 'receipt', 'bank', 'coins', 'credit-card', 'shopping-cart',
      'shopping-bag', 'basket', 'storefront', 'barcode', 'package', 'truck', 'seal-percent',
      'tote', 'cash-register', 'money', 'ticket', 'invoice', 'tip-jar', 'vault', 'cardholder',
      'currency-eur', 'currency-dollar',
    ],
  },
  {
    key: 'home',
    ids: [
      'house', 'couch', 'broom', 'gift', 'cake', 'baby', 'car', 'key', 't-shirt', 'plant',
      'hammer', 'wrench', 'shield', 'bed', 'bathtub', 'lamp', 'door', 'washing-machine', 'oven',
      'baby-carriage', 'toolbox', 'screwdriver', 'ladder', 'paint-roller',
    ],
  },
  {
    key: 'health',
    ids: [
      'heartbeat', 'barbell', 'pill', 'tooth', 'smiley', 'first-aid-kit', 'stethoscope', 'syringe',
      'bandaids', 'brain', 'dna', 'virus', 'eyeglasses', 'footprints', 'drop', 'hospital',
    ],
  },
  {
    key: 'food',
    ids: [
      'fork-knife', 'cooking-pot', 'coffee', 'tea-bag', 'bread', 'cheese', 'egg', 'pizza',
      'hamburger', 'carrot', 'avocado', 'cherries', 'orange', 'pepper', 'ice-cream', 'cookie',
      'popcorn', 'bowl-food', 'chef-hat', 'knife', 'jar', 'wine', 'beer-stein', 'martini',
    ],
  },
  {
    key: 'travel',
    ids: [
      'airplane', 'suitcase', 'globe', 'map-pin', 'compass', 'tent', 'bicycle', 'train', 'boat',
      'bus', 'taxi', 'motorcycle', 'scooter', 'sailboat', 'gas-pump', 'map-trifold', 'signpost',
      'lighthouse', 'island', 'city', 'castle-turret', 'bridge', 'road-horizon', 'park',
    ],
  },
  {
    key: 'nature',
    ids: [
      'tree', 'leaf', 'mountains', 'sun', 'moon', 'snowflake', 'umbrella', 'flower',
      'flower-tulip', 'flower-lotus', 'cactus', 'tree-palm', 'tree-evergreen', 'clover', 'cloud',
      'rainbow', 'wind', 'thermometer', 'campfire', 'planet', 'shooting-star', 'waves', 'tornado',
      'feather',
    ],
  },
  {
    key: 'animals',
    ids: [
      'dog', 'cat', 'paw-print', 'horse', 'cow', 'rabbit', 'bird', 'fish', 'butterfly', 'bug',
      'shrimp', 'bone', 'barn', 'tractor',
    ],
  },
  {
    key: 'hobbies',
    ids: [
      'music-note', 'headphones', 'camera', 'film-slate', 'game-controller', 'dice-five',
      'palette', 'guitar', 'piano-keys', 'microphone-stage', 'vinyl-record', 'television',
      'paint-brush', 'yarn', 'needle', 'magic-wand', 'image', 'cassette-tape', 'disco-ball',
      'balloon', 'confetti', 'mask-happy', 'ghost', 'book-bookmark',
    ],
  },
  {
    key: 'sport',
    ids: [
      'soccer-ball', 'basketball', 'baseball', 'tennis-ball', 'volleyball', 'football', 'golf',
      'bowling-ball', 'ping-pong', 'boxing-glove', 'hockey', 'person-simple-swim',
      'person-simple-run', 'person-simple-ski', 'person-simple-hike', 'sneaker',
    ],
  },
  {
    key: 'tech',
    ids: [
      'atom', 'test-tube', 'microscope', 'cpu', 'circuitry', 'robot', 'desktop', 'device-mobile',
      'wifi-high', 'battery-full', 'plug', 'magnet', 'binoculars', 'database', 'terminal-window',
      'keyboard',
    ],
  },
  {
    key: 'signals',
    ids: [
      'fire', 'lightning', 'crown', 'thumbs-up', 'lock', 'bell', 'clock', 'hourglass', 'eye',
      'prohibit', 'info', 'siren', 'infinity', 'peace', 'recycle', 'radioactive', 'fingerprint',
    ],
  },
  {
    key: 'numbers',
    ids: ['number-circle-zero', 'number-circle-one', 'number-circle-two', 'number-circle-three', 'number-circle-four', 'number-circle-five', 'number-circle-six', 'number-circle-seven', 'number-circle-eight', 'number-circle-nine'],
  },
];

/** Ids no longer offered, still drawn. Empty so far. */
export const RETIRED_LOOK_ICON_IDS: readonly string[] = [];

/** Id -> the icon's paths, for every id above. */
export const LOOK_ICONS = LOOK_ICON_PATHS;

const NUMBER_IDS = LOOK_ICON_GROUPS.find((g) => g.key === 'numbers')!.ids;

/** The digit a number icon shows, or null for every other icon. The group
 *  runs from zero, so the position is the digit. */
export function lookIconNumber(id: string): number | null {
  const i = NUMBER_IDS.indexOf(id);
  return i === -1 ? null : i;
}
