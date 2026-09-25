import { useTranslation } from 'react-i18next';
import { HelpChip } from './HelpChip';
import { CONTACT_PHOTO_PX, IMAGE_FIT_PX, IMAGE_JPEG_QUALITY } from './imageProcessing';
import { SETTINGS_HELP } from './settingsUI';
import { Switch } from './Switch';
import type { ImageSwitch } from './userSettings';

type Field = 'imageSpaceSaver' | 'imageStripMetadata' | 'imageContactCeiling';

type Props = {
  spaceSaver: ImageSwitch;
  stripMetadata: ImageSwitch;
  contactCeiling: ImageSwitch;
  onChange: (field: Field, value: ImageSwitch) => void;
};

/**
 * Images settings pane: the two switches every image door obeys, plus
 * the ceiling a contact photo keeps on top of them.
 *
 * All three are synced settings, so a choice made on one device holds on
 * every device. The rows say what the code does, numbers included: the
 * ceilings and the JPEG quality are read from imageProcessing.ts so the
 * copy cannot drift from the constant it describes. The switches apply
 * to new images only, which the footer states, because a user who turns
 * the space saver on to free space frees nothing.
 *
 * Spec: ops/docs/plans/image-quality-handoff.md (section 9)
 */
export function ImagesSheet({ spaceSaver, stripMetadata, contactCeiling, onChange }: Props) {
  const { t } = useTranslation('settings');

  const rows: { field: Field; setting: string; value: ImageSwitch; title: string; desc: string }[] = [
    {
      field: 'imageSpaceSaver',
      setting: 'images.spaceSaver',
      value: spaceSaver,
      title: t('images.spaceSaverTitle'),
      desc: t('images.spaceSaverDesc', { px: IMAGE_FIT_PX, quality: Math.round(IMAGE_JPEG_QUALITY * 100) }),
    },
    {
      field: 'imageContactCeiling',
      setting: 'images.contactPhotos',
      value: contactCeiling,
      title: t('images.contactTitle'),
      desc: t('images.contactDesc', { px: CONTACT_PHOTO_PX }),
    },
    {
      field: 'imageStripMetadata',
      setting: 'images.removeLocation',
      value: stripMetadata,
      title: t('images.removeLocationTitle'),
      desc: t('images.removeLocationDesc'),
    },
  ];

  return (
    <div className="flex-1 min-h-0 overflow-y-auto text-pn">
      <div className="px-6 pt-2 pb-4">
        <HelpChip surface="images" className="mb-1" />
        {/* Boolean rows: the whole row is the label, the switch sits beside
            it at every width.
            Spec: ops/docs/ui-patterns.md section 36 (compact setting rows) */}
        <div className="divide-y divide-divider">
          {rows.map((row) => (
            <Switch
              key={row.field}
              setting={row.setting}
              label={row.title}
              description={row.desc}
              checked={row.value === 'on'}
              onChange={(on) => onChange(row.field, on ? 'on' : 'off')}
              className="gap-x-5 py-3"
            />
          ))}
        </div>
        <p className={`${SETTINGS_HELP} mt-3`}>{t('images.applyNote')}</p>
      </div>
    </div>
  );
}
