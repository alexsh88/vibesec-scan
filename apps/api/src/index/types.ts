export type Language =
  | 'typescript' | 'javascript' | 'python' | 'json' | 'yaml' | 'toml' | 'sql' | 'shell'
  | 'dockerfile' | 'html' | 'css' | 'markdown' | 'env' | 'xml' | 'other';
export type FileCategory = 'source' | 'config' | 'lockfile' | 'doc' | 'other';
export type FileTag = 'test' | 'example' | 'ci' | 'infra';
export type SkipReason = 'vendor' | 'binary' | 'too_large' | 'minified' | 'generated' | 'symlink' | 'submodule' | 'file_limit';

export type IndexedFile = {
  path: string; blobSha: string; size: number; language: Language; category: FileCategory;
  tags: FileTag[]; skipReason: SkipReason | null;
};

export type ImportKind = 'local' | 'package' | 'builtin' | 'unresolved';
export type ImportEdge = {
  from: string; specifier: string; kind: ImportKind;
  /** repo-relative path when kind === 'local' */
  to: string | null;
  /** npm package / PyPI distribution name when kind === 'package' */
  pkg: string | null;
  line: number;
};

export type EntrypointKind =
  | 'next-route' | 'next-api' | 'server-action' | 'http-route' | 'django-urls'
  | 'serverless' | 'edge-function' | 'cli' | 'script';
export type Entrypoint = { path: string; kind: EntrypointKind; line: number | null; detail: string | null };

export type IndexStats = {
  totalFiles: number;
  indexedFiles: number;
  skipped: Partial<Record<SkipReason, number>>;
  byLanguage: Partial<Record<Language, number>>;
  imports: number;
  entrypoints: number;
  /** true when MAX_FILES was reached and the rest were marked file_limit */
  truncated: boolean;
};

export type RepoIndex = { files: IndexedFile[]; imports: ImportEdge[]; entrypoints: Entrypoint[]; stats: IndexStats };
