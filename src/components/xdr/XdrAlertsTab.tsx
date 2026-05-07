/**
 * Security Alerts tab — embeds the live XDR anomaly table for the Logs page.
 * Click row → /xdr (the full Command Centre opens with the drawer).
 */

import { useNavigate } from 'react-router-dom';

import AnomalyTable from '@/components/xdr/AnomalyTable';
import { useAnomalies, useNewIds } from '@/hooks/useXdr';

const XdrAlertsTab = () => {
  const nav = useNavigate();
  const { data, isLoading } = useAnomalies({ limit: 200 }, 5_000);
  const items = data?.items ?? [];
  const newIds = useNewIds(items);

  return (
    <AnomalyTable
      anomalies={items}
      loading={isLoading}
      newIds={newIds}
      onSelect={() => nav('/xdr')}
      maxRows={200}
    />
  );
};

export default XdrAlertsTab;
