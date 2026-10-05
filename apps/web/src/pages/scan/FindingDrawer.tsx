import { useNavigate, useParams } from 'react-router';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';

/**
 * TODO(FindingDrawer): spec screen 5 — right-side Sheet over the findings list: code (CodeBlock with
 * highlight range), permalink, risk factors, taint flow visualizer (finding.taintTrace), credential
 * details (finding.secret), dependency details, explanation/impact, remediation + patch, triage
 * actions (useTriage: PUT/DELETE).
 * Data: useFinding(scanId, findingId). Closing navigates back to `..` (the list keeps its filters
 * if they live in the search params — preserve `location.search`).
 */
export default function FindingDrawer() {
  const { findingId } = useParams();
  const navigate = useNavigate();
  return (
    <Sheet open onOpenChange={(open) => !open && navigate({ pathname: '..', search: window.location.search }, { relative: 'path' })}>
      <SheetContent className="w-full sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle>Finding</SheetTitle>
          <SheetDescription className="font-mono text-xs">{findingId}</SheetDescription>
        </SheetHeader>
        <p className="px-4 text-sm text-muted-foreground">Finding drawer — coming soon.</p>
      </SheetContent>
    </Sheet>
  );
}
