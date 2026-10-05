/**
 * Lazy Shiki: nothing is downloaded until the first <CodeBlock> mounts, and each grammar is its own
 * chunk loaded on demand. Uses the JS regex engine (no WASM) and dual github themes driven by CSS
 * variables, so switching light/dark needs no re-highlight.
 */
import type { Root } from 'hast';
import type { HighlighterCore, ShikiTransformer } from 'shiki';

type Lang = string;

let highlighterPromise: Promise<HighlighterCore> | null = null;
const loadedLangs = new Set<string>();

async function getHighlighter(): Promise<HighlighterCore> {
  highlighterPromise ??= (async () => {
    const [{ createHighlighter }, { createJavaScriptRegexEngine }] = await Promise.all([
      import('shiki'),
      import('shiki/engine/javascript'),
    ]);
    return createHighlighter({
      themes: ['github-dark-default', 'github-light-default'],
      langs: [],
      engine: createJavaScriptRegexEngine(),
    });
  })();
  return highlighterPromise;
}

const EXT_LANG: Record<string, Lang> = {
  ts: 'typescript', mts: 'typescript', cts: 'typescript', tsx: 'tsx', js: 'javascript', mjs: 'javascript', cjs: 'javascript',
  jsx: 'jsx', py: 'python', json: 'json', yml: 'yaml', yaml: 'yaml', toml: 'toml', sh: 'shellscript', bash: 'shellscript',
  sql: 'sql', html: 'html', css: 'css', md: 'markdown', xml: 'xml', go: 'go', rb: 'ruby', java: 'java', php: 'php',
  env: 'dotenv', tf: 'hcl', diff: 'diff', patch: 'diff',
};

/** Best-effort language from a file path (Dockerfile, .env, extension). */
export function langFromPath(path: string): Lang {
  const base = path.split('/').pop()?.toLowerCase() ?? '';
  if (base === 'dockerfile' || base.startsWith('dockerfile.')) return 'docker';
  if (base.startsWith('.env')) return 'dotenv';
  const ext = base.includes('.') ? base.split('.').pop()! : '';
  return EXT_LANG[ext] ?? 'text';
}

export type HighlightOptions = {
  lang: Lang;
  /** 1-based lines (relative to the snippet) to mark with `.line-hl`. */
  highlightLines?: number[];
};

/** Returns a Shiki HAST tree (render with hast-util-to-jsx-runtime — no innerHTML). Unknown languages fall back to plain text. */
export async function highlight(code: string, opts: HighlightOptions): Promise<Root> {
  const hl = await getHighlighter();
  let lang = opts.lang;
  if (lang !== 'text' && !loadedLangs.has(lang)) {
    try {
      await hl.loadLanguage(lang as Parameters<HighlighterCore['loadLanguage']>[0]);
      loadedLangs.add(lang);
    } catch {
      lang = 'text';
    }
  }
  const marked = new Set(opts.highlightLines ?? []);
  const transformers: ShikiTransformer[] = [
    {
      line(node, line) {
        if (marked.has(line)) this.addClassToHast(node, 'line-hl');
      },
    },
  ];
  return hl.codeToHast(code, {
    lang,
    themes: { dark: 'github-dark-default', light: 'github-light-default' },
    defaultColor: false,
    transformers,
  });
}
