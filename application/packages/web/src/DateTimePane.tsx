import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { PILLAR_GLYPHS, TextAa } from './icons';
import { SettingsTabStrip, settingsTabClass } from './settingsUI';

type DateTimeTab = 'format' | 'calendar';

/** Settings > Date & Time: how dates and times read everywhere, and the
 * calendar's own settings, on two tabs of one pane. */
export function DateTimePane({ initialTab, format, calendar }: { initialTab?: string; format: ReactNode; calendar: ReactNode }) {
  const { t } = useTranslation('notes');
  const [tab, setTab] = useState<DateTimeTab>(initialTab === 'calendar' ? 'calendar' : 'format');
  const CalendarGlyph = PILLAR_GLYPHS.calendar;
  const tabs = [
    { id: 'format' as const, label: t('settings.dateTabFormat'), icon: <TextAa aria-hidden="true" /> },
    { id: 'calendar' as const, label: t('settings.calendarLabel'), icon: <CalendarGlyph aria-hidden="true" /> },
  ];
  return (
    <div className="flex-1 min-h-0 flex flex-col">
      <SettingsTabStrip role="tablist" aria-label={t('settings.dateLabel')} className="shrink-0 px-4 sm:px-6">
        {tabs.map((tb) => (
          <button key={tb.id} type="button" data-setting={`date.${tb.id}`} role="tab" aria-selected={tab === tb.id}
            onClick={() => setTab(tb.id)} className={settingsTabClass(tab === tb.id)}>
            {tb.icon}
            <span>{tb.label}</span>
          </button>
        ))}
      </SettingsTabStrip>
      {tab === 'format' ? format : calendar}
    </div>
  );
}
