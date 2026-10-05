import { useRef } from 'react';
import { RecentRepos } from './RecentRepos';
import { ScanForm, type ScanFormHandle } from './ScanForm';

const PROOF_POINTS = [
  { n: '01', title: 'Proof, not noise', body: 'Exact file and line, a permalink, and the source → sink trace for every injection.' },
  { n: '02', title: 'Fix plans, not CVE lists', body: 'Vulnerable libraries grouped and ranked: “upgrade X fixes N issues”.' },
  { n: '03', title: 'Bounded and private', body: 'Hard AI budget per scan. Tokens are used once and never stored.' },
];

/** Spec screen 1 — Connect: start a scan, or jump back into a recent repository. */
export default function ConnectPage() {
  const form = useRef<ScanFormHandle>(null);

  return (
    <div className="relative flex-1 overflow-hidden">
      {/* Blueprint grid, faded out toward the bottom-right. */}
      <div
        aria-hidden
        className="bg-grid pointer-events-none absolute inset-0 [mask-image:radial-gradient(ellipse_80%_60%_at_20%_0%,black,transparent)]"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute -top-40 -left-40 size-[520px] rounded-full bg-signal/[0.07] blur-3xl"
      />

      <div className="relative mx-auto grid w-full max-w-6xl gap-10 px-4 pt-10 pb-16 sm:px-6 lg:grid-cols-[minmax(0,1fr)_380px] lg:gap-14 lg:pt-16">
        <div className="min-w-0">
          <div className="mb-8 max-w-2xl animate-rise space-y-4">
            <p className="eyebrow flex items-center gap-2">
              <span aria-hidden className="inline-block size-1.5 rounded-full bg-signal" />
              AI security review · powered by Claude
            </p>
            <h1 className="text-[2rem] leading-[1.1] font-semibold tracking-[-0.035em] text-balance sm:text-[2.6rem]">
              Point it at a repo.
              <br />
              <span className="text-muted-foreground">Get the risks that matter — with proof.</span>
            </h1>
            <p className="max-w-xl text-[15px] text-pretty text-muted-foreground">
              VibeSec clones read-only, traces untrusted input to dangerous sinks, checks every dependency for CVEs and
              hunts leaked credentials — then tells you what to fix first.
            </p>
          </div>

          <div className="animate-rise rounded-xl border bg-card/80 p-5 shadow-[0_1px_0_0_oklch(1_0_0/0.04)_inset,0_20px_40px_-24px_oklch(0_0_0/0.5)] backdrop-blur-sm [animation-delay:80ms] sm:p-6">
            <ScanForm ref={form} />
          </div>

          <ol className="mt-10 grid animate-rise gap-6 [animation-delay:160ms] sm:grid-cols-3">
            {PROOF_POINTS.map((p) => (
              <li key={p.n} className="space-y-1.5 border-t pt-4">
                <p className="font-mono text-[11px] text-signal">{p.n}</p>
                <p className="text-sm font-medium">{p.title}</p>
                <p className="text-[13px] leading-relaxed text-muted-foreground">{p.body}</p>
              </li>
            ))}
          </ol>
        </div>

        <aside className="animate-rise [animation-delay:120ms] lg:pt-[11.5rem]">
          <RecentRepos onRescan={(url) => form.current?.fillRepo(url)} />
        </aside>
      </div>
    </div>
  );
}
