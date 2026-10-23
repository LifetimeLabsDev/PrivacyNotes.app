import { useTranslation } from 'react-i18next';
import { ACTIONS } from './actions';
import { Callout } from './feedback';

/**
 * @catalog VaultFormActions
 * use: LoginForm, CardForm and SshKeyForm actions: Save alone for a new item, Cancel then Save for an existing item, no actions when locked. Errors stay above the row. Icons come from ACTIONS; the vault's existing spacing is retained.
 * never: a general modal footer or inline edit; moving validation, draft persistence or Escape handling out of the owning form to reuse this row.
 */
export function VaultFormActions({ locked, isNew, saveError, onSave, onCancel }: {
  locked: boolean;
  isNew: boolean;
  saveError?: string;
  onSave: () => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation('common');
  const SaveIcon = ACTIONS.save.icon;
  const CancelIcon = ACTIONS.cancel.icon;
  return <>
    {saveError && <Callout tone="danger">{saveError}</Callout>}
    {!locked && <div className="flex gap-2 -mt-2">
      {!isNew && <button type="button" onClick={onCancel}
        className="flex-1 inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-md text-sm font-medium border border-divider text-pn-muted hover:bg-pn/5 transition">
        <CancelIcon aria-hidden="true" />
        {t('actions.cancel')}
      </button>}
      <button type="button" onClick={onSave}
        className="flex-1 inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-md text-sm font-medium bg-accent-fill text-white hover:bg-accent-fill-hover transition">
        <SaveIcon aria-hidden="true" />
        {t('actions.save')}
      </button>
    </div>}
  </>;
}
