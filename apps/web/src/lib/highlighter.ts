/**
 * Lazy Shiki: nothing is downloaded until the first <CodeBlock> mounts, and each grammar is its own
 * chunk loaded on demand. Uses the JS regex engine (no WASM) and dual github themes driven by CSS
 * variables, so switching light/dark needs no re-highlight.
 *
 * Built from `shiki/core` + explicit `@shikijs/langs/*` / `@shikijs/themes/*` imports rather than the
 * `shiki` package's convenience `createHighlighter` + generic `loadLanguage(name)`: those resolve
 * names through Shiki's full bundled-language/theme maps, so the bundler has to assume any of its
 * ~240 grammars could be requested and ships every one of them (several alone over 500 kB) even
 * though `EXT_LANG` below only ever asks for a couple dozen.
 */
import type { Root } from 'hast';
import type { HighlighterCore, ShikiTransformer } from 'shiki';

type Lang = string;

let highlighterPromise: Promise<HighlighterCore> | null = null;
const loadedLangs = new Set<string>();

/** Only the languages `EXT_LANG` / `langFromPath` can actually produce. */
const LANG_LOADERS: Record<string, () => Promise<unknown>> = {
  typescript: () => import('@shikijs/langs/typescript'),
  tsx: () => import('@shikijs/langs/tsx'),
  javascript: () => import('@shikijs/langs/javascript'),
  jsx: () => import('@shikijs/langs/jsx'),
  python: () => import('@shikijs/langs/python'),
  json: () => import('@shikijs/langs/json'),
  yaml: () => import('@shikijs/langs/yaml'),
  toml: () => import('@shikijs/langs/toml'),
  shellscript: () => import('@shikijs/langs/shellscript'),
  sql: () => import('@shikijs/langs/sql'),
  html: () => import('@shikijs/langs/html'),
  css: () => import('@shikijs/langs/css'),
  markdown: () => import('@shikijs/langs/markdown'),
  xml: () => import('@shikijs/langs/xml'),
  go: () => import('@shikijs/langs/go'),
  ruby: () => import('@shikijs/langs/ruby'),
  java: () => import('@shikijs/langs/java'),
  php: () => import('@shikijs/langs/php'),
  dotenv: () => import('@shikijs/langs/dotenv'),
  hcl: () => import('@shikijs/langs/hcl'),
  diff: () => import('@shikijs/langs/diff'),
  docker: () => import('@shikijs/langs/docker'),
};

async function getHighlighter(): Promise<HighlighterCore> {
  highlighterPromise ??= (async () => {
    const [{ createHighlighterCore }, { createJavaScriptRegexEngine }] = await Promise.all([
      import('shiki/core'),
      import('shiki/engine/javascript'),
    ]);
    return createHighlighterCore({
      themes: [() => import('@shikijs/themes/github-dark-default'), () => import('@shikijs/themes/github-light-default')],
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
    const load = LANG_LOADERS[lang];
    try {
      if (!load) throw new Error(`No grammar registered for ${lang}`);
      await hl.loadLanguage(load as Parameters<HighlighterCore['loadLanguage']>[0]);
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
