import test from 'node:test';
import assert from 'node:assert/strict';
import { buildZipArchive, crc32 } from './zipBuilder';

test('crc32 matches standard IEEE 802.3 vector', () => {
  const data = new TextEncoder().encode('123456789');
  assert.equal(crc32(data), 0xcbf43926);
});

test('buildZipArchive produces valid PKZIP headers and Central Directory', () => {
  const zip = buildZipArchive([
    { path: 'oscarpx-backup-restore/oscarpx-backup-restore.php', content: '<?php echo "ok";' },
    { path: 'oscarpx-backup-restore/assets/css/oscarpx-admin.css', content: 'body {}' },
  ]);

  const view = new DataView(zip.buffer);
  // Local file header magic PK\x03\x04
  assert.equal(view.getUint32(0, true), 0x04034b50);
  // EOCD magic PK\x05\x06 at tail - 22 bytes
  assert.equal(view.getUint32(zip.length - 22, true), 0x06054b50);
  // Entry count = 2
  assert.equal(view.getUint16(zip.length - 12, true), 2);
});
