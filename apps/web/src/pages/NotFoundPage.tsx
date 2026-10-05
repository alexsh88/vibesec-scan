import { FileQuestionMark } from 'lucide-react';
import { Link } from 'react-router';
import { EmptyState } from '@/components/feedback/EmptyState';
import { Page } from '@/components/layout/Page';
import { Button } from '@/components/ui/button';

export default function NotFoundPage() {
  return (
    <Page className="py-20">
      <EmptyState
        icon={FileQuestionMark}
        title="Page not found"
        description="This address doesn't match any page in VibeSec."
        action={
          <Button asChild size="sm">
            <Link to="/">Start a new scan</Link>
          </Button>
        }
      />
    </Page>
  );
}
