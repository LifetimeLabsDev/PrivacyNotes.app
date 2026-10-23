import { useTranslation } from 'react-i18next';
import { HelpChip } from './HelpChip';
import { CONTACT_PHOTO_PX, IMAGE_FIT_PX, IMAGE_JPEG_QUALITY } from './imageProcessing';
import { ROW_TITLE, ResetDefaultsButton, SETTINGS_HELP } from './settingsUI';
import { ArrowsIn, MapPinLine, UserCircle, type Icon } from './icons';
import { Switch } from './Switch';
import type { ImageSwitch } from './userSettings';
import { defaultSettings } from './userSettingsShape';

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
 * Spec: ops/docs/archive/image-quality-handoff.md (section 9)
 */
export function ImagesSheet({ spaceSaver, stripMetadata, contactCeiling, onChange }: Props) {
  const { t } = useTranslation('settings');

  const rows: { field: Field; setting: string; value: ImageSwitch; title: string; desc: string; icon: Icon }[] = [
    {
      field: 'imageSpaceSaver',
      setting: 'images.spaceSaver',
      value: spaceSaver,
      title: t('images.spaceSaverTitle'),
      icon: ArrowsIn,
      desc: t('images.spaceSaverDesc', { px: IMAGE_FIT_PX, quality: Math.round(IMAGE_JPEG_QUALITY * 100) }),
    },
    {
      field: 'imageContactCeiling',
      setting: 'images.contactPhotos',
      value: contactCeiling,
      title: t('images.contactTitle'),
      icon: UserCircle,
      desc: t('images.contactDesc', { px: CONTACT_PHOTO_PX }),
    },
    {
      field: 'imageStripMetadata',
      setting: 'images.removeLocation',
      value: stripMetadata,
      title: t('images.removeLocationTitle'),
      icon: MapPinLine,
      desc: t('images.removeLocationDesc'),
    },
  ];

  return (
    <div className="flex-1 min-h-0 overflow-y-auto text-pn">
      <div className="px-6 pt-2 pb-4">
        {/* Boolean rows: the whole row is the label, the switch sits beside
            it at every width.
            Spec: ops/docs/archive/ui-patterns.md section 36 (compact setting rows) */}
        <div className="divide-y divide-divider">
          {rows.map((row) => (
            <Switch
              key={row.field}
              setting={row.setting}
              icon={<row.icon size={14} className="text-accent" />}
              labelClassName={ROW_TITLE}
              label={row.title}
              description={row.desc}
              checked={row.value === 'on'}
              onChange={(on) => onChange(row.field, on ? 'on' : 'off')}
              className="gap-x-5 py-3"
            />
          ))}
        </div>
        <p className={`${SETTINGS_HELP} mt-3`}>{t('images.applyNote')}</p>
        <ResetDefaultsButton
          onReset={() => {
            const d = defaultSettings();
            onChange('imageSpaceSaver', d.imageSpaceSaver);
            onChange('imageStripMetadata', d.imageStripMetadata);
            onChange('imageContactCeiling', d.imageContactCeiling);
          }}
        />
        <HelpChip surface="images" className="mt-4" />
      </div>
    </div>
  );
}
