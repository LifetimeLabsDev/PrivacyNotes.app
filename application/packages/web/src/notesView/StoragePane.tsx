import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Database, Image as ImageIcon } from '../icons';
import { SettingsTabStrip, settingsTabClass } from '../settingsUI';
import { usePaneTab } from '../settingsPaneTab';

type Section = 'storage' | 'images';

/**
 * Settings > Storage: the storage plan on one tab, the image settings on the
 * other. Images moved in from a category of their own (2026-10-22), because
 * what they decide is how much room pictures take. `storage` gets the way to
 * the Images tab, for its "image settings" links.
 * Spec: ops/docs/archive/image-quality-handoff.md (section 9)
 */
export function StoragePane({
  initialTab,
  storage,
  images,
}: {
  initialTab?: string;
  storage: (openImages: () => void) => ReactNode;
  images: ReactNode;
}) {
  const { t } = useTranslation('notes');
  const [section, setSection] = usePaneTab<Section>('storage', initialTab === 'images' ? 'images' : 'storage');
  useEffect(() => { setSection(initialTab === 'images' ? 'images' : 'storage'); }, [initialTab]);
  // The Images tab carries the search id of the whole image settings, so a
  // search for "images" still lands on it.
  const tabs = [
    { id: 'storage', setting: undefined, label: t('settings.storageLabel'), Icon: Database },
    { id: 'images', setting: 'storage.images', label: t('settings.imagesLabel'), Icon: ImageIcon },
  ] as const;
  return (
    <div className="flex-1 min-h-0 flex flex-col">
      <SettingsTabStrip className="shrink-0 px-4 sm:px-6">
        {tabs.map(({ id, setting, label, Icon }) => (
          <button
            key={id}
            type="button"
            data-setting={setting}
            aria-pressed={section === id}
            onClick={() => setSection(id)}
            className={settingsTabClass(section === id)}
          >
            <Icon className="shrink-0 text-accent" aria-hidden="true" />
            <span className="min-w-0">{label}</span>
          </button>
        ))}
      </SettingsTabStrip>
      {section === 'storage' ? storage(() => setSection('images')) : images}
    </div>
  );
}
