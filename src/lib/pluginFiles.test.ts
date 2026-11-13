import test from 'node:test';
import assert from 'node:assert/strict';
import { PLUGIN_FILES } from './pluginFiles';

test('PLUGIN_FILES contains required WordPress metadata and all architectural classes', () => {
  const mainFile = PLUGIN_FILES.find((f) => f.path === 'oscarpx-backup-restore.php');
  assert.ok(mainFile, 'Main plugin file must exist');
  assert.match(mainFile.content, /Plugin Name:\s+OscarPx Backup & Restore/);
  assert.match(mainFile.content, /Author:\s+OscarPx/);
  assert.match(mainFile.content, /Author URI:\s+https:\/\/oscarpx\.com/);
  assert.match(mainFile.content, /Version:\s+1\.0\.0/);

  const securityFile = PLUGIN_FILES.find((f) => f.path === 'includes/class-oscarpx-security.php');
  assert.ok(securityFile);
  assert.match(securityFile.content, /check_ajax_referer/);
  assert.match(securityFile.content, /manage_options/);
  assert.match(securityFile.content, /Deny from all/);
  assert.match(securityFile.content, /index\.php/);

  const dbFile = PLUGIN_FILES.find((f) => f.path === 'includes/class-oscarpx-db-engine.php');
  assert.ok(dbFile);
  assert.match(dbFile.content, /global \$wpdb/);
  assert.equal(dbFile.content.includes('mysqldump'), false);
});
