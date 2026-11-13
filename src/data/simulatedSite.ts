export interface SimulatedDbTable {
  name: string;
  rows: number;
  sizeKb: number;
}

export interface SimulatedSiteFile {
  path: string;
  sizeBytes: number;
  category: 'core' | 'theme' | 'plugin' | 'uploads' | 'cache' | 'backup' | 'log';
}

export interface BackupArchiveItem {
  filename: string;
  sizeLabel: string;
  sizeBytes: number;
  createdAt: string;
  tablesCount: number;
  filesCount: number;
  skippedCount: number;
}

export const SIMULATED_DB_TABLES: SimulatedDbTable[] = [
  { name: 'wp_options', rows: 482, sizeKb: 1420 },
  { name: 'wp_posts', rows: 1240, sizeKb: 4890 },
  { name: 'wp_postmeta', rows: 6420, sizeKb: 3150 },
  { name: 'wp_users', rows: 24, sizeKb: 32 },
  { name: 'wp_usermeta', rows: 310, sizeKb: 128 },
  { name: 'wp_comments', rows: 185, sizeKb: 240 },
  { name: 'wp_terms', rows: 78, sizeKb: 48 },
  { name: 'wp_term_taxonomy', rows: 78, sizeKb: 44 },
  { name: 'wp_term_relationships', rows: 910, sizeKb: 96 },
];

export const SIMULATED_SITE_FILES: SimulatedSiteFile[] = [
  { path: 'wp-config.php', sizeBytes: 3420, category: 'core' },
  { path: 'wp-content/themes/flavor-child/style.css', sizeBytes: 18400, category: 'theme' },
  { path: 'wp-content/themes/flavor-child/functions.php', sizeBytes: 9240, category: 'theme' },
  { path: 'wp-content/themes/flavor-child/templates/single.html', sizeBytes: 6120, category: 'theme' },
  { path: 'wp-content/plugins/oscarpx-backup-restore/oscarpx-backup-restore.php', sizeBytes: 2150, category: 'plugin' },
  { path: 'wp-content/plugins/oscarpx-backup-restore/includes/class-oscarpx-admin.php', sizeBytes: 11200, category: 'plugin' },
  { path: 'wp-content/plugins/woocommerce/woocommerce.php', sizeBytes: 14500, category: 'plugin' },
  { path: 'wp-content/uploads/2026/10/hero-editorial.webp', sizeBytes: 348000, category: 'uploads' },
  { path: 'wp-content/uploads/2026/11/catalogo-productos.pdf', sizeBytes: 1420000, category: 'uploads' },
  { path: 'wp-content/uploads/2026/11/logo-oscarpx.svg', sizeBytes: 12400, category: 'uploads' },
  { path: 'wp-content/cache/page_enhanced/index.html_gzip', sizeBytes: 84200, category: 'cache' },
  { path: 'wp-content/cache/minify/bundle-9f32a.js', sizeBytes: 215000, category: 'cache' },
  { path: 'wp-content/et-cache/12/et-core-unified.min.css', sizeBytes: 164000, category: 'cache' },
  { path: 'wp-content/w3tc-config/master.php', sizeBytes: 22100, category: 'cache' },
  { path: 'wp-content/updraft/backup_2026-10-01-uploads.zip', sizeBytes: 42500000, category: 'backup' },
  { path: 'wp-content/ai1wm-backups/sitio-anterior.wpress', sizeBytes: 68400000, category: 'backup' },
  { path: 'wp-content/backups-dup-lite/installer.php', sizeBytes: 412000, category: 'backup' },
  { path: 'wp-content/oscarpx-backups/.htaccess', sizeBytes: 164, category: 'backup' },
  { path: 'wp-content/oscarpx-backups/index.php', sizeBytes: 32, category: 'backup' },
  { path: 'wp-content/oscarpx-backups/oscarpx-backup-20261110-091500.zip', sizeBytes: 11840000, category: 'backup' },
  { path: 'wp-content/debug.log', sizeBytes: 5120000, category: 'log' },
];

export const INITIAL_BACKUPS: BackupArchiveItem[] = [
  {
    filename: 'oscarpx-backup-20261110-091500.zip',
    sizeLabel: '11.29 MB',
    sizeBytes: 11840000,
    createdAt: '2026-11-10 09:15:00',
    tablesCount: 9,
    filesCount: 1428,
    skippedCount: 11,
  },
  {
    filename: 'oscarpx-backup-20261102-184210.zip',
    sizeLabel: '10.84 MB',
    sizeBytes: 11366400,
    createdAt: '2026-11-02 18:42:10',
    tablesCount: 9,
    filesCount: 1392,
    skippedCount: 11,
  },
];

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}
