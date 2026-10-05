import { Navigate } from 'react-router';
import { useScanContext } from '@/hooks/useScanContext';
import { isTerminalState } from '@/lib/scanState';

/** /scans/:id → live view while the scan runs, overview once it has finished. */
export default function ScanIndexRedirect() {
  const { scan } = useScanContext();
  return <Navigate to={isTerminalState(scan.state) ? 'overview' : 'live'} replace />;
}
