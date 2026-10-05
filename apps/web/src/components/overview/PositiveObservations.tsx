import { CircleCheck } from 'lucide-react';
import { Panel } from '@/components/common/Panel';

/** Evidenced strengths only (the summary never invents them); hidden when there are none. */
export function PositiveObservations({ items }: { items: string[] }) {
  if (items.length === 0) return null;
  return (
    <Panel id="positives" title="What’s going well">
      <ul className="space-y-2.5">
        {items.map((t, i) => (
          <li key={i} className="flex gap-2.5 text-sm leading-relaxed">
            <CircleCheck aria-hidden className="mt-0.5 size-4 shrink-0 text-status-fixed" />
            <span className="text-pretty">{t}</span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
