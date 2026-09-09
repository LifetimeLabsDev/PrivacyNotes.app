import { useTranslation } from 'react-i18next';
import { HelpChip } from './HelpChip';
import { CONTACT_PHOTO_PX, IMAGE_FIT_PX, IMAGE_JPEG_QUALITY } from './imageProcessing';
import { SETTINGS_HELP } from './settingsUI';
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

  const rows: { field: Field; value: ImageSwitch; title: string; desc: string }[] = [
    {
      field: 'imageSpaceSaver',
      value: spaceSaver,
      title: t('images.spaceSaverTitle'),
      desc: t('images.spaceSaverDesc', { px: IMAGE_FIT_PX, quality: Math.round(IMAGE_JPEG_QUALITY * 100) }),
    },
    {
      field: 'imageContactCeiling',
      value: contactCeiling,
      title: t('images.contactTitle'),
      desc: t('images.contactDesc', { px: CONTACT_PHOTO_PX }),
    },
    {
      field: 'imageStripMetadata',
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
            it at every width. Switch idiom: security/BiometricTab.tsx.
            Spec: ops/docs/ui-patterns.md section 36 (compact setting rows) */}
        <div className="divide-y divide-divider">
          {rows.map((row) => (
            <label key={row.field} className="flex items-center justify-between gap-x-5 py-3 cursor-pointer">
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{row.title}</p>
                <p className={`${SETTINGS_HELP} mt-0.5`}>{row.desc}</p>
              </div>
              <div className="relative shrink-0">
                <input
                  type="checkbox"
                  checked={row.value === 'on'}
                  onChange={(e) => onChange(row.field, e.target.checked ? 'on' : 'off')}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-pn-muted/35 peer-checked:bg-accent rounded-full transition-colors" />
                <div className="absolute start-0.5 top-0.5 w-4 h-4 bg-white rounded-full shadow-sm transition-transform peer-checked:translate-x-4 peer-checked:rtl:-translate-x-4" />
              </div>
            </label>
          ))}
        </div>
        <p className={`${SETTINGS_HELP} mt-3`}>{t('images.applyNote')}</p>
      </div>
    </div>
  );
}
