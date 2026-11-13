/**
 * Exclusion matching & filename sanitization utilities mirroring the PHP
 * implementation in OscarPx Backup & Restore.
 */

export const DEFAULT_EXCLUDED_PATHS = [
  'wp-content/cache/',
  'wp-content/updraft/',
  'wp-content/oscarpx-backups/',
  'wp-content/ai1wm-backups/',
  'wp-content/backups-dup-lite/',
  'wp-content/et-cache/',
  'wp-content/w3tc-config/',
  'wp-content/debug.log',
];

export interface ExclusionRule {
  raw: string;
  normalized: string;
  isDirectory: boolean;
}

/**
 * Parses raw textarea lines into normalized relative path rules.
 * Mirrors PHP's OscarPx_File_Engine::parse_exclusion_rules().
 */
export function parseExclusionRules(rawText: string): ExclusionRule[] {
  const lines = rawText.split(/\r?\n/);
  const rules: ExclusionRule[] = [];
  const seen = new Set<string>();

  for (const line of lines) {
    let clean = line.trim().replace(/\\/g, '/');
    if (!clean) continue;

    // Strip leading slashes and dot-slash segments
    clean = clean.replace(/^(\.\/|\/)+/, '');
    // Reject path traversal segments
    if (clean.includes('..')) continue;
    if (!clean) continue;

    const isDirectory = clean.endsWith('/');
    const normalized = clean.replace(/\/+$/, '');
    if (!normalized || seen.has(normalized)) continue;

    seen.add(normalized);
    rules.push({
      raw: line.trim(),
      normalized,
      isDirectory,
    });
  }

  return rules;
}

/**
 * Checks whether a relative file path (e.g. "wp-content/cache/page.html")
 * matches any exclusion rule using fast prefix matching (PHP strpos / strncmp).
 */
export function isPathExcluded(
  relativePath: string,
  rules: ExclusionRule[],
): { excluded: boolean; matchedRule?: string } {
  const cleanPath = relativePath
    .replace(/\\/g, '/')
    .replace(/^(\.\/|\/)+/, '');

  for (const rule of rules) {
    if (cleanPath === rule.normalized) {
      return { excluded: true, matchedRule: rule.raw };
    }
    if (cleanPath.startsWith(rule.normalized + '/')) {
      return { excluded: true, matchedRule: rule.raw };
    }
  }

  return { excluded: false };
}

/**
 * Sanitizes a backup filename to match PHP's sanitize_file_name + whitelist.
 */
export function sanitizeBackupFilename(filename: string): string | null {
  const base = filename.replace(/\\/g, '/').split('/').pop() ?? '';
  const cleaned = base.replace(/[^a-zA-Z0-9._-]/g, '');
  if (!cleaned || !/^[a-zA-Z0-9._-]+\.zip$/i.test(cleaned)) {
    return null;
  }
  return cleaned;
}
