import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_EXCLUDED_PATHS,
  parseExclusionRules,
  isPathExcluded,
  sanitizeBackupFilename,
} from './exclusionMatcher';

test('parseExclusionRules normalizes trailing slashes, backslashes, and removes path traversal', () => {
  const input = [
    '  wp-content/cache/  ',
    './wp-content\\updraft\\',
    '/wp-content/ai1wm-backups/',
    '../../etc/passwd',
    '',
    'wp-content/cache/',
  ].join('\n');

  const rules = parseExclusionRules(input);
  assert.deepEqual(
    rules.map((r) => r.normalized),
    ['wp-content/cache', 'wp-content/updraft', 'wp-content/ai1wm-backups'],
  );
});

test('isPathExcluded accurately excludes nested files and directories without partial prefix false positives', () => {
  const rules = parseExclusionRules(DEFAULT_EXCLUDED_PATHS.join('\n'));

  assert.equal(isPathExcluded('wp-content/cache/page-123.html', rules).excluded, true);
  assert.equal(isPathExcluded('wp-content/oscarpx-backups/backup.zip', rules).excluded, true);
  assert.equal(isPathExcluded('wp-content/debug.log', rules).excluded, true);

  // Must NOT exclude similarly prefixed folders
  assert.equal(isPathExcluded('wp-content/cache-custom/file.php', rules).excluded, false);
  assert.equal(isPathExcluded('wp-content/themes/flavor/style.css', rules).excluded, false);
  assert.equal(isPathExcluded('wp-config.php', rules).excluded, false);
});

test('sanitizeBackupFilename blocks traversal and non-zip extensions', () => {
  assert.equal(sanitizeBackupFilename('oscarpx-backup-20261113.zip'), 'oscarpx-backup-20261113.zip');
  assert.equal(sanitizeBackupFilename('../../evil.zip'), 'evil.zip');
  assert.equal(sanitizeBackupFilename('shell.php'), null);
  assert.equal(sanitizeBackupFilename('no-extension'), null);
});
