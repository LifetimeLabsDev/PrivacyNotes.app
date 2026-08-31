import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { UpdateToast } from './UpdateToast';
import { startVersionPolling } from './versionCheck';
import { detectPlatform } from './devices';

const IS_DESKTOP = detectPlatform() !== 'web';

/**
 * Bottom-right toast that appears when the server is running a newer
 * version than the currently loaded client. Slides up on first detection
 * and on every re-detection after dismiss. The Update button reloads the
 * page; the dismiss × hides the toast until the next poll re-detects the
 * mismatch, so a long-running session can't permanently silence updates.
 *
 * Skipped in Tauri builds - desktop apps bundle their own version and
 * shouldn't compare against the web deployment.
 */
export function VersionUpdateToast() {
  const { t } = useTranslation('common');
  const [serverVersion, setServerVersion] = useState<string | null>(null);
  const [hidden, setHidden] = useState(false);

  useEffect(() => {
    if (IS_DESKTOP) return;
    return startVersionPolling((v) => {
      setServerVersion(v);
      setHidden(false);
    });
  }, []);

  if (!serverVersion || hidden) return null;

  return (
    <UpdateToast
      version={serverVersion}
      actionLabel={t('updateToast.refresh')}
      onAction={() => window.location.reload()}
      onChangelog={() => window.open('/changelog', '_blank', 'noopener,noreferrer')}
      onDismiss={() => setHidden(true)}
    />
  );
}
