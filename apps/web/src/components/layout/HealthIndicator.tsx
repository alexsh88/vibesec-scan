import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { useHealth } from '@/hooks/queries';
import { cn } from '@/lib/utils';

const MODE_LABEL = { live: 'Claude live', record: 'Claude · recording', mock: 'Mock LLM' } as const;

/** API + LLM mode indicator for the top bar (GET /api/health every 30 s). */
export function HealthIndicator() {
  const { data, isError, isPending } = useHealth();

  const tone = isPending ? 'pending' : isError ? 'down' : data.llm.mode === 'live' ? 'live' : 'mock';
  const dot = {
    pending: 'bg-muted-foreground/50',
    down: 'bg-sev-critical',
    live: 'bg-status-fixed',
    mock: 'bg-sev-medium',
  }[tone];
  const label = isPending ? 'Connecting…' : isError ? 'API offline' : MODE_LABEL[data.llm.mode];

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="inline-flex h-7 items-center gap-2 rounded-full border px-2.5 font-mono text-[11px] text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          aria-label={`API status: ${label}`}
        >
          <span className="relative flex size-2">
            {tone === 'live' && <span className="absolute inset-0 animate-ping rounded-full bg-status-fixed/60" />}
            <span className={cn('relative size-2 rounded-full', dot)} />
          </span>
          <span className="hidden sm:inline">{label}</span>
        </button>
      </TooltipTrigger>
      <TooltipContent side="bottom" align="end" className="max-w-xs">
        {isError ? (
          <p>The VibeSec API is not responding on :4000. Start it with <code>npm run dev:api</code>.</p>
        ) : data ? (
          <div className="space-y-1 font-mono text-[11px]">
            <p>
              llm <b>{data.llm.mode}</b>
              {data.llm.mode !== 'live' && ' — results come from recorded/mocked model output'}
            </p>
            <p>fast {data.llm.models.fast}</p>
            <p>deep {data.llm.models.deep}</p>
            <p>synthesis {data.llm.models.synthesis}</p>
            <p>
              queue {data.queue.pending}/{data.queue.capacity}
              {data.git ? ` · git ${data.git}` : ''}
            </p>
          </div>
        ) : (
          <p>Checking API…</p>
        )}
      </TooltipContent>
    </Tooltip>
  );
}
