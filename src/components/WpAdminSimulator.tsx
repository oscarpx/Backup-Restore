import { useEffect, useMemo, useRef, useState } from 'react';
import type { ChangeEvent, DragEvent } from 'react';
import {
  CheckCircle2,
  Database,
  Download,
  FileArchive,
  FolderOpen,
  FolderX,
  HardDrive,
  RotateCcw,
  ShieldCheck,
  Trash2,
  UploadCloud,
  Zap,
} from 'lucide-react';
import {
  BackupType,
  DEFAULT_EXCLUDED_PATHS,
  buildDynamicBackupFilename,
  isPathExcluded,
  parseExclusionRules,
  sanitizeBackupFilename,
  sanitizeSiteTitle,
} from '../lib/exclusionMatcher';
import { buildZipArchive } from '../lib/zipBuilder';
import {
  BackupArchiveItem,
  SIMULATED_DB_TABLES,
  SIMULATED_SITE_FILES,
  formatBytes,
} from '../data/simulatedSite';

interface WpAdminSimulatorProps {
  backups: BackupArchiveItem[];
  onBackupCreated: (item: BackupArchiveItem) => void;
  onBackupDeleted: (filename: string) => void;
}

type AdminTab = 'create' | 'manager' | 'restore';

interface UploadState {
  active: boolean;
  filename: string;
  pct: number;
  chunkIndex: number;
  totalChunks: number;
  isDragOver: boolean;
}

const UPLOAD_CHUNK_BYTES = 1048576; // 1 MB por fragmento (File.slice)

export function WpAdminSimulator({
  backups,
  onBackupCreated,
  onBackupDeleted,
}: WpAdminSimulatorProps) {
  const [activeTab, setActiveTab] = useState<AdminTab>('create');
  const [siteName, setSiteName] = useState<string>('Mi Sitio');
  const [backupType, setBackupType] = useState<BackupType>('completo');
  const [exclusionsText, setExclusionsText] = useState<string>(
    DEFAULT_EXCLUDED_PATHS.join('\n'),
  );
  const [selectedBackup, setSelectedBackup] = useState<string>(
    backups[0]?.filename ?? '',
  );
  const [confirmRestoreOpen, setConfirmRestoreOpen] = useState(false);
  const [pendingManagerRestore, setPendingManagerRestore] = useState<string | null>(null);
  const [targetUrl, setTargetUrl] = useState('https://produccion-ejemplo.com');
  const [maintenanceActive, setMaintenanceActive] = useState(false);
  const [simulateExistingPxTools, setSimulateExistingPxTools] = useState(true);
  const [managerNotice, setManagerNotice] = useState<{
    text: string;
    isError: boolean;
  } | null>(null);
  const [uploadState, setUploadState] = useState<UploadState>({
    active: false,
    filename: '',
    pct: 0,
    chunkIndex: 0,
    totalChunks: 0,
    isDragOver: false,
  });

  // Estado del proceso asíncrono AJAX por lotes
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressTitle, setProgressTitle] = useState('');
  const [logs, setLogs] = useState<string[]>([]);
  const [completedBanner, setCompletedBanner] = useState<string | null>(null);
  const [showFilePreview, setShowFilePreview] = useState(false);

  const timersRef = useRef<number[]>([]);
  const logBoxRef = useRef<HTMLPreElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!backups.some((b) => b.filename === selectedBackup)) {
      setSelectedBackup(backups[0]?.filename ?? '');
    }
  }, [backups, selectedBackup]);

  useEffect(() => {
    return () => {
      timersRef.current.forEach((id) => window.clearTimeout(id));
      timersRef.current = [];
    };
  }, []);

  useEffect(() => {
    if (logBoxRef.current) {
      logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight;
    }
  }, [logs]);

  const parsedRules = useMemo(
    () => parseExclusionRules(exclusionsText),
    [exclusionsText],
  );

  const evaluatedFiles = useMemo(() => {
    return SIMULATED_SITE_FILES.map((file) => {
      const check = isPathExcluded(file.path, parsedRules);
      return {
        ...file,
        excluded: check.excluded,
        matchedRule: check.matchedRule,
      };
    });
  }, [parsedRules]);

  const includedFiles = useMemo(
    () => evaluatedFiles.filter((f) => !f.excluded),
    [evaluatedFiles],
  );
  const skippedFiles = useMemo(
    () => evaluatedFiles.filter((f) => f.excluded),
    [evaluatedFiles],
  );
  const includedTotalBytes = useMemo(
    () => includedFiles.reduce((acc, f) => acc + f.sizeBytes, 0),
    [includedFiles],
  );
  const skippedTotalBytes = useMemo(
    () => skippedFiles.reduce((acc, f) => acc + f.sizeBytes, 0),
    [skippedFiles],
  );

  function pushLog(message: string) {
    const time = new Date().toTimeString().slice(0, 8);
    setLogs((prev) => [...prev, `[${time}] ${message}`]);
  }

  function clearScheduledSteps() {
    timersRef.current.forEach((id) => window.clearTimeout(id));
    timersRef.current = [];
  }

  function runSimulatedBackup() {
    if (isRunning) return;
    clearScheduledSteps();
    setIsRunning(true);
    setCompletedBanner(null);
    setConfirmRestoreOpen(false);
    setProgress(4);
    const typeLabel = backupType === 'solo-bd' ? 'Solo Base de Datos' : 'Completa';
    setProgressTitle(`Creando Copia de Seguridad ${typeLabel} (Lotes AJAX)...`);
    setLogs([]);

    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const rawZipName = buildDynamicBackupFilename(siteName, backupType, now);
    const zipName = sanitizeBackupFilename(rawZipName) ?? rawZipName;
    const siteSlug = sanitizeSiteTitle(siteName);

    const steps: Array<{ delay: number; fn: () => void }> = [];
    let t = 80;

    steps.push({
      delay: t,
      fn: () => {
        pushLog(`POST admin-ajax.php?action=oscarpx_start_backup (backup_type=${backupType}, nonce verificado + manage_options)`);
        pushLog(`Nomenclatura dinámica: sanitize_title(get_bloginfo('name'))="${siteSlug}" + tipo="${backupType}" + date('Y-m-d_H-i-s') => ${zipName}`);
        pushLog('Carpeta segura verificada: wp-content/oscarpx-backups/ (.htaccess Deny from all + index.php)');
        setProgress(8);
      },
    });

    // Lotes DB con $wpdb
    SIMULATED_DB_TABLES.forEach((table, idx) => {
      t += 140;
      steps.push({
        delay: t,
        fn: () => {
          pushLog(
            `[AJAX DB] $wpdb->get_results("SELECT * FROM ${table.name}") -> ${table.rows} filas volcadas a database-backup.sql`,
          );
          const maxDbPct = backupType === 'solo-bd' ? 75 : 30;
          const pct = 10 + ((idx + 1) / SIMULATED_DB_TABLES.length) * maxDbPct;
          setProgress(Math.round(pct));
        },
      });
    });

    if (backupType === 'solo-bd') {
      t += 180;
      steps.push({
        delay: t,
        fn: () => {
          pushLog(
            'POST admin-ajax.php?action=oscarpx_scan_files -> Modo solo-bd: omitiendo escaneo de wp-content.',
          );
          pushLog(
            `[AJAX ZipArchive] Empaquetando database-backup.sql en ${zipName}...`,
          );
          setProgress(92);
        },
      });
    } else {
      // Escaneo de manifiesto
      t += 180;
      steps.push({
        delay: t,
        fn: () => {
          pushLog(
            `POST admin-ajax.php?action=oscarpx_scan_files -> ${includedFiles.length} archivos válidos, ${skippedFiles.length} omitidos por reglas (${parsedRules.length} rutas activas).`,
          );
          setProgress(45);
        },
      });

      // Lotes ZipArchive
      const chunkSize = 4;
      const totalChunks = Math.max(1, Math.ceil(evaluatedFiles.length / chunkSize));
      for (let c = 0; c < totalChunks; c++) {
        const slice = evaluatedFiles.slice(c * chunkSize, (c + 1) * chunkSize);
        t += 190;
        steps.push({
          delay: t,
          fn: () => {
            const addedInChunk = slice.filter((f) => !f.excluded);
            const skippedInChunk = slice.filter((f) => f.excluded);
            skippedInChunk.forEach((s) => {
              pushLog(`[Omitido strpos()] ${s.path} (coincide con "${s.matchedRule}")`);
            });
            pushLog(
              `[AJAX ZipArchive] Lote ${c + 1}/${totalChunks}: +${addedInChunk.length} añadidos con addFile(), ${skippedInChunk.length} omitidos.`,
            );
            const pct = 48 + ((c + 1) / totalChunks) * 48;
            setProgress(Math.round(pct));
          },
        });
      }
    }

    // Finalización
    t += 200;
    steps.push({
      delay: t,
      fn: () => {
        const dbBytes = SIMULATED_DB_TABLES.reduce((acc, tbl) => acc + tbl.sizeKb * 1024, 0);
        const estimatedZipBytes =
          backupType === 'solo-bd'
            ? Math.round(dbBytes * 0.42)
            : Math.round((includedTotalBytes + dbBytes) * 0.58);
        const newBackup: BackupArchiveItem = {
          filename: zipName,
          sizeLabel: formatBytes(estimatedZipBytes),
          sizeBytes: estimatedZipBytes,
          createdAt: `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`,
          tablesCount: SIMULATED_DB_TABLES.length,
          filesCount: backupType === 'solo-bd' ? 1 : includedFiles.length,
          skippedCount: backupType === 'solo-bd' ? 0 : skippedFiles.length,
        };
        onBackupCreated(newBackup);
        setSelectedBackup(zipName);
        setProgress(100);
        pushLog(`Completado: wp-content/oscarpx-backups/${zipName} (${newBackup.sizeLabel}).`);
        setCompletedBanner(
          `Backup ${zipName} creado correctamente (${newBackup.sizeLabel}). Disponible en "Gestor de Backups" para descarga segura o restauración.`,
        );
        setIsRunning(false);
      },
    });

    steps.forEach((step) => {
      const id = window.setTimeout(step.fn, step.delay);
      timersRef.current.push(id);
    });
  }

  async function handleFileSliceUpload(file: File, reportedSizeBytes?: number) {
    if (isRunning || uploadState.active) return;

    const cleanName = sanitizeBackupFilename(file.name);
    if (!cleanName || !cleanName.toLowerCase().endsWith('.zip')) {
      setManagerNotice({
        text: 'Solo se permiten archivos de backup con extensión .zip válida.',
        isError: true,
      });
      return;
    }

    // Validar cabecera PKZIP en el primer fragmento antes de enviar
    const headerSlice = file.slice(0, 2);
    const headerBuf = await headerSlice.arrayBuffer();
    const headerBytes = new Uint8Array(headerBuf);
    if (headerBytes.length < 2 || headerBytes[0] !== 0x50 || headerBytes[1] !== 0x4b) {
      setManagerNotice({
        text: `El archivo "${cleanName}" no contiene una firma PKZIP válida.`,
        isError: true,
      });
      return;
    }

    const totalChunks = Math.max(1, Math.ceil(file.size / UPLOAD_CHUNK_BYTES));
    setManagerNotice(null);
    setCompletedBanner(null);
    setPendingManagerRestore(null);
    setLogs([]);
    setProgressTitle(`Subiendo Backup Externo por Fragmentos (File.slice): ${cleanName}`);
    setProgress(2);
    setUploadState({
      active: true,
      filename: cleanName,
      pct: 0,
      chunkIndex: 0,
      totalChunks,
      isDragOver: false,
    });

    pushLog(
      `[File.slice()] Preparando "${cleanName}" (${((reportedSizeBytes ?? file.size) / 1048576).toFixed(2)} MB) en ${totalChunks} fragmentos de 1 MB (sortea upload_max_filesize=2M).`,
    );

    for (let idx = 0; idx < totalChunks; idx++) {
      const start = idx * UPLOAD_CHUNK_BYTES;
      const end = Math.min(file.size, start + UPLOAD_CHUNK_BYTES);
      const chunkBlob = file.slice(start, end);
      await new Promise((resolve) => window.setTimeout(resolve, 210));

      const pct = Math.round(((idx + 1) / totalChunks) * 100);
      setUploadState({
        active: true,
        filename: cleanName,
        pct,
        chunkIndex: idx + 1,
        totalChunks,
        isDragOver: false,
      });
      setProgress(pct);
      pushLog(
        `POST admin-ajax.php?action=oscarpx_upload_backup_chunk -> fragmento ${idx + 1}/${totalChunks} (${(chunkBlob.size / 1048576).toFixed(2)} MB) ensamblado en .part`,
      );
    }

    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const finalBytes = reportedSizeBytes ?? file.size;
    const newItem: BackupArchiveItem = {
      filename: cleanName,
      sizeLabel: `${(finalBytes / 1048576).toFixed(2)} MB`,
      sizeBytes: finalBytes,
      createdAt: `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`,
      tablesCount: SIMULATED_DB_TABLES.length,
      filesCount: includedFiles.length,
      skippedCount: 0,
    };

    onBackupCreated(newItem);
    setSelectedBackup(cleanName);
    setUploadState({
      active: false,
      filename: '',
      pct: 100,
      chunkIndex: totalChunks,
      totalChunks,
      isDragOver: false,
    });
    pushLog(
      `[ZipArchive::open] Firma e integridad verificadas. Archivo movido a wp-content/oscarpx-backups/${cleanName} sin recargar página.`,
    );
    setManagerNotice({
      text: `Backup "${cleanName}" subido y ensamblado correctamente (${(finalBytes / 1048576).toFixed(2)} MB) sin recargar la página.`,
      isError: false,
    });
  }

  function handleFileInputChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) {
      void handleFileSliceUpload(file);
    }
    e.target.value = '';
  }

  function handleDropZoneDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setUploadState((prev) => ({ ...prev, isDragOver: false }));
    const file = e.dataTransfer.files?.[0];
    if (file) {
      void handleFileSliceUpload(file);
    }
  }

  function handleSimulateExternalUpload() {
    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
    const sampleFilename = `oscarpx-externo-${stamp}.zip`;
    // Crea un File real de 3.4 MB con cabecera PKZIP para ejercitar File.slice() en 4 fragmentos de 1 MB
    const payload = new Uint8Array(3 * 1048576 + 420 * 1024);
    payload[0] = 0x50; // 'P'
    payload[1] = 0x4b; // 'K'
    payload[2] = 0x03;
    payload[3] = 0x04;
    const simulatedFile = new File([payload], sampleFilename, {
      type: 'application/zip',
    });
    void handleFileSliceUpload(simulatedFile, 148_688_000);
  }

  function handleSecureAjaxDelete(filename: string) {
    if (isRunning || uploadState.active) return;
    const safeName = sanitizeBackupFilename(filename);
    if (!safeName) {
      setManagerNotice({
        text: 'Bloqueado por seguridad: ruta inválida o intento de Directory Traversal.',
        isError: true,
      });
      return;
    }

    onBackupDeleted(safeName);
    if (pendingManagerRestore === safeName) {
      setPendingManagerRestore(null);
    }
    setManagerNotice({
      text: `Backup "${safeName}" eliminado de forma segura vía AJAX (Nonce + manage_options + sanitize_file_name + realpath() validados).`,
      isError: false,
    });
    setProgressTitle(`Eliminación Segura AJAX: ${safeName}`);
    setProgress(100);
    pushLog(
      `POST admin-ajax.php?action=oscarpx_delete_backup -> check_ajax_referer() OK | current_user_can('manage_options') OK | sanitize_file_name("${safeName}") | realpath() dentro de oscarpx-backups/ -> unlink() completado.`,
    );
  }

  function handleSecureDownload(filename: string) {
    if (isRunning || uploadState.active) return;
    const safeName = sanitizeBackupFilename(filename);
    if (!safeName) {
      setManagerNotice({
        text: 'Bloqueado por seguridad: intento de Path Traversal o nombre inválido.',
        isError: true,
      });
      return;
    }

    const endpoint = `wp-admin/admin-post.php?action=download_oscarpx_backup&file=${encodeURIComponent(safeName)}&_wpnonce=9f4c2b81a7`;
    const sampleSql = `-- OscarPx Backup & Restore SQL Dump\n-- Archivo: ${safeName}\nDROP TABLE IF EXISTS \`wp_options\`;\n`;
    const zipBytes = buildZipArchive([
      { path: 'database-backup.sql', content: sampleSql },
      { path: 'MANIFEST.txt', content: `Backup: ${safeName}\nProtected via .htaccess Deny from all\n` },
    ]);
    const blob = new Blob([new Uint8Array(zipBytes).buffer], { type: 'application/zip' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = safeName;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);

    setProgressTitle(`Descarga Segura PHP Stream: ${safeName}`);
    setProgress(100);
    pushLog(
      `GET ${endpoint} -> wp_verify_nonce() OK | current_user_can('manage_options') OK | sanitize_file_name("${safeName}") | realpath() validado dentro de wp-content/oscarpx-backups/`,
    );
    pushLog(
      `[PHP Stream] ob_clean(); flush(); -> Content-Type: application/zip | Content-Disposition: attachment; filename="${safeName}" | Content-Length: ${blob.size} | fread(1 MB) -> exit;`,
    );
    setManagerNotice({
      text: `Descarga segura iniciada vía puente PHP (${endpoint}) mediante streaming fread() sin file_get_contents().`,
      isError: false,
    });
  }

  function runSimulatedRestore(overrideFilename?: string) {
    const targetFilename = overrideFilename ?? selectedBackup;
    if (isRunning || uploadState.active || !targetFilename) return;
    const safeName = sanitizeBackupFilename(targetFilename);
    if (!safeName) return;

    clearScheduledSteps();
    setConfirmRestoreOpen(false);
    setPendingManagerRestore(null);
    setManagerNotice(null);
    setIsRunning(true);
    setMaintenanceActive(false);
    setCompletedBanner(null);
    setProgress(5);
    setProgressTitle(`Restaurando Backup (Sistema Anticaídas): ${safeName}`);
    setLogs([]);

    const cleanTarget = targetUrl.trim().replace(/\/+$/, '') || 'https://produccion-ejemplo.com';
    const steps: Array<{ delay: number; fn: () => void }> = [];
    let t = 80;

    steps.push({
      delay: t,
      fn: () => {
        setMaintenanceActive(true);
        pushLog(`POST admin-ajax.php?action=oscarpx_start_restore -> archivo=${safeName}`);
        pushLog('[Regla 2 - Aislamiento] Archivo .maintenance creado en raíz (wp_maintenance()): tráfico y cronjobs detenidos.');
        pushLog('Estado guardado en job.json (inmune a DROP TABLE wp_options) y database-backup.sql verificado.');
        setProgress(10);
      },
    });

    // Fase 1: Extracción a staging aislado con bloqueo de wp-config.php y .htaccess
    for (let batch = 1; batch <= 3; batch++) {
      t += 190;
      steps.push({
        delay: t,
        fn: () => {
          const coreNote =
            batch === 1
              ? ' [Regla 1 - Protección Core: wp-config.php y .htaccess bloqueados y omitidos]'
              : '';
          pushLog(
            `[AJAX Staging] ZipArchive::extractTo lote ${batch}/3 hacia .tmp-*/stage/.${coreNote}`,
          );
          setProgress(10 + batch * 8);
        },
      });
    }

    // Fase 2: Inyección SQL Segura (Hot Swap) por fragmentos vía $wpdb
    SIMULATED_DB_TABLES.forEach((table, idx) => {
      t += 120;
      steps.push({
        delay: t,
        fn: () => {
          pushLog(
            `[Regla 3 - Hot Swap $wpdb] DROP TABLE IF EXISTS \`${table.name}\`; CREATE TABLE \`${table.name}\`; INSERT ${table.rows} filas (fragmento <= 2 MB, $wpdb->flush()).`,
          );
          const pct = 36 + ((idx + 1) / SIMULATED_DB_TABLES.length) * 30;
          setProgress(Math.round(pct));
        },
      });
    });

    // Fase 3: Aplicación desde staging manteniendo wp-config.php y .htaccess intactos
    t += 170;
    steps.push({
      delay: t,
      fn: () => {
        pushLog(
          '[AJAX Apply] Aplicando wp-content desde staging hacia ABSPATH (wp-config.php, .htaccess y wp-content/oscarpx-backups/ intactos).',
        );
        setProgress(82);
      },
    });

    // Fase 4: Search & Replace y eliminación automática de .maintenance
    t += 180;
    steps.push({
      delay: t,
      fn: () => {
        pushLog(
          `[AJAX Search & Replace] Serialización segura en $wpdb hacia ${cleanTarget} (wp_options, wp_posts, wp_postmeta)...`,
        );
        setProgress(94);
      },
    });

    t += 180;
    steps.push({
      delay: t,
      fn: () => {
        setProgress(100);
        setMaintenanceActive(false);
        pushLog('[Regla 2 - Aislamiento] Search & Replace finalizado con éxito -> .maintenance eliminado automáticamente.');
        pushLog('SET FOREIGN_KEY_CHECKS = 1; limpieza de carpeta temporal .tmp-* completada.');
        setCompletedBanner(
          `Restauración Anticaídas completada con ${safeName}. Credenciales en wp-config.php y .htaccess intactas; modo mantenimiento desactivado.`,
        );
        setIsRunning(false);
      },
    });

    steps.forEach((step) => {
      const id = window.setTimeout(step.fn, step.delay);
      timersRef.current.push(id);
    });
  }

  return (
    <div className="max-w-[1380px] mx-auto px-4 sm:px-6 py-6">
      <div className="bg-white border border-[#c3c4c7] rounded overflow-hidden flex flex-col lg:flex-row">
        {/* Barra lateral estilo WordPress Admin */}
        <aside
          aria-label="Menú simulado de WordPress Admin"
          className="bg-[#1d2327] text-[#f0f0f1] lg:w-[232px] shrink-0 flex lg:flex-col overflow-x-auto lg:overflow-visible"
        >
          <div className="hidden lg:block px-4 py-3 border-b border-white/10 text-xs font-medium text-[#a7aaad]">
            Escritorio WordPress
          </div>
          <div className="flex lg:flex-col w-full text-[13px]">
            {[
              { label: 'Escritorio', type: 'item' as const },
              { label: 'Entradas', type: 'item' as const },
              { label: 'Medios', type: 'item' as const },
              { label: 'Páginas', type: 'item' as const },
              { label: 'Plugins', type: 'item' as const },
              { label: 'PX Tools', type: 'px-tools' as const },
              { label: 'Ajustes', type: 'item' as const },
            ].map((item) =>
              item.type === 'px-tools' ? (
                <div key={item.label} className="shrink-0">
                  <div
                    className="px-4 py-2.5 whitespace-nowrap flex items-center gap-2.5 bg-[#2271b1] text-white font-semibold"
                    title="Slug maestro: px-tools · Icono: dashicons-superhero"
                  >
                    <Zap className="w-4 h-4 shrink-0" aria-hidden="true" />
                    <span>PX Tools</span>
                  </div>
                  <div className="hidden lg:block bg-[#2c3338] py-1.5 border-l-4 border-[#72aee6]">
                    {(simulateExistingPxTools
                      ? [
                          { label: 'PX Speed Cache', slug: 'px-speed-cache', active: false },
                          { label: 'Backup & Restore', slug: 'oscarpx-backup-restore', active: true },
                          { label: 'PX SEO Optimizer', slug: 'px-seo-optimizer', active: false },
                          { label: 'PX Security', slug: 'px-security', active: false },
                        ]
                      : [{ label: 'Backup & Restore', slug: 'oscarpx-backup-restore', active: true }]
                    ).map((sub) => (
                      <div
                        key={sub.slug}
                        className={`pl-9 pr-3 py-1.5 text-[12px] whitespace-nowrap ${
                          sub.active
                            ? 'text-white font-semibold'
                            : 'text-[#c3c4c7] opacity-80'
                        }`}
                      >
                        {sub.label}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div
                  key={item.label}
                  className="px-4 py-2.5 whitespace-nowrap shrink-0 flex items-center gap-2.5 text-[#c3c4c7]"
                >
                  <span className="w-4 h-4 shrink-0 inline-block opacity-40 text-center">
                    ·
                  </span>
                  <span>{item.label}</span>
                </div>
              ),
            )}
          </div>
        </aside>

        {/* Área de contenido principal estilo .wrap de WordPress */}
        <main className="flex-1 bg-[#f0f0f1] p-5 sm:p-6 min-w-0">
          <div className="max-w-[960px]">
            <div className="flex flex-col sm:flex-row sm:items-baseline sm:justify-between gap-2 mb-4">
              <div>
                <h1 className="text-[23px] font-semibold text-[#1d2327] leading-tight">
                  OscarPx Backup &amp; Restore
                </h1>
                <p className="text-[13px] text-[#50575e] mt-1">
                  Versión 1.0.0 · Autor: OscarPx · Submenú de{' '}
                  <code className="font-mono text-xs">PX Tools (px-tools)</code>
                </p>
              </div>
              <label className="inline-flex items-center gap-2 text-[12px] text-[#50575e] cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={simulateExistingPxTools}
                  onChange={(e) => setSimulateExistingPxTools(e.target.checked)}
                  className="rounded border-[#8c8f94] text-[#2271b1]"
                />
                <span>Simular otros plugins PX Tools activos</span>
              </label>
            </div>

            {/* Estado de integración PX Tools + directorio protegido */}
            <div className="bg-white border border-[#c3c4c7] px-4 py-2.5 mb-5 space-y-1.5 text-[13px] text-[#1d2327]">
              <div className="flex items-center gap-2.5">
                <ShieldCheck
                  className="w-4 h-4 text-[#16a34a] shrink-0"
                  aria-hidden="true"
                />
                <span>
                  Directorio protegido automáticamente:{' '}
                  <code className="font-mono text-xs bg-[#f6f7f7] px-1.5 py-0.5 rounded border border-[#dcdcde]">
                    wp-content/oscarpx-backups/
                  </code>{' '}
                  (con <code className="font-mono text-xs">.htaccess</code>{' '}
                  <em>Deny from all</em> e{' '}
                  <code className="font-mono text-xs">index.php</code>)
                </span>
              </div>
              <div className="flex items-center gap-2.5 text-[12px] text-[#50575e]">
                <Zap className="w-4 h-4 text-[#2271b1] shrink-0" aria-hidden="true" />
                <span>
                  {simulateExistingPxTools ? (
                    <>
                      Ecosistema <code className="font-mono">px-tools</code> detectado en{' '}
                      <code className="font-mono">$admin_page_hooks</code>: se omite{' '}
                      <code className="font-mono">add_menu_page()</code> y se apila mediante{' '}
                      <code className="font-mono">add_submenu_page(&apos;px-tools&apos;, ...)</code>.
                    </>
                  ) : (
                    <>
                      Primer plugin activo: registra menú maestro{' '}
                      <code className="font-mono">PX Tools</code> (
                      <code className="font-mono">px-tools</code>,{' '}
                      <code className="font-mono">dashicons-superhero</code>) con{' '}
                      <code className="font-mono">add_menu_page()</code> y se enlaza con{' '}
                      <code className="font-mono">add_submenu_page()</code>.
                    </>
                  )}
                </span>
              </div>
            </div>

            {/* Pestañas nativas .nav-tab-wrapper */}
            <div
              role="tablist"
              aria-label="Pestañas de OscarPx Backup"
              className="flex border-b border-[#c3c4c7] gap-1"
            >
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'create'}
                disabled={isRunning || uploadState.active}
                onClick={() => {
                  setActiveTab('create');
                  setConfirmRestoreOpen(false);
                  setPendingManagerRestore(null);
                  if (!isRunning && !uploadState.active) {
                    setCompletedBanner(null);
                    setManagerNotice(null);
                    setLogs([]);
                  }
                }}
                className={`px-4 py-2 text-[14px] font-semibold border border-b-0 transition-colors cursor-pointer whitespace-nowrap shrink-0 disabled:opacity-60 focus-visible:outline-2 focus-visible:outline-[#2271b1] ${
                  activeTab === 'create'
                    ? 'bg-white text-[#1d2327] border-[#c3c4c7] -mb-px pb-[9px]'
                    : 'bg-[#dcdcde] text-[#50575e] border-[#c3c4c7] hover:bg-[#f0f0f1] hover:text-[#1d2327]'
                }`}
              >
                Crear Backup
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'manager'}
                disabled={isRunning || uploadState.active}
                onClick={() => {
                  setActiveTab('manager');
                  setConfirmRestoreOpen(false);
                  if (!isRunning && !uploadState.active) {
                    setCompletedBanner(null);
                    setManagerNotice(null);
                    setLogs([]);
                  }
                }}
                className={`px-4 py-2 text-[14px] font-semibold border border-b-0 transition-colors cursor-pointer whitespace-nowrap shrink-0 disabled:opacity-60 focus-visible:outline-2 focus-visible:outline-[#2271b1] ${
                  activeTab === 'manager'
                    ? 'bg-white text-[#1d2327] border-[#c3c4c7] -mb-px pb-[9px]'
                    : 'bg-[#dcdcde] text-[#50575e] border-[#c3c4c7] hover:bg-[#f0f0f1] hover:text-[#1d2327]'
                }`}
              >
                Gestor de Backups ({backups.length})
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'restore'}
                disabled={isRunning || uploadState.active}
                onClick={() => {
                  setActiveTab('restore');
                  setPendingManagerRestore(null);
                  if (!isRunning && !uploadState.active) {
                    setCompletedBanner(null);
                    setManagerNotice(null);
                    setLogs([]);
                  }
                }}
                className={`px-4 py-2 text-[14px] font-semibold border border-b-0 transition-colors cursor-pointer whitespace-nowrap shrink-0 disabled:opacity-60 focus-visible:outline-2 focus-visible:outline-[#2271b1] ${
                  activeTab === 'restore'
                    ? 'bg-white text-[#1d2327] border-[#c3c4c7] -mb-px pb-[9px]'
                    : 'bg-[#dcdcde] text-[#50575e] border-[#c3c4c7] hover:bg-[#f0f0f1] hover:text-[#1d2327]'
                }`}
              >
                Restaurar Backup ({backups.length})
              </button>
            </div>

            {/* Contenido de Pestaña */}
            {activeTab === 'create' ? (
              <section
                aria-label="Crear Backup"
                className="bg-white border border-t-0 border-[#c3c4c7] p-5 sm:p-6"
              >
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-4 border-b border-[#dcdcde]">
                  <div>
                    <h2 className="text-[16px] font-semibold text-[#1d2327]">
                      Generar Nueva Copia de Seguridad
                    </h2>
                    <p className="text-[13px] text-[#50575e] mt-0.5">
                      Exporta las {SIMULATED_DB_TABLES.length} tablas vía{' '}
                      <code className="font-mono text-xs">$wpdb</code>
                      {backupType === 'completo' ? (
                        <>
                          {' '}y empaqueta <code className="font-mono text-xs">wp-content</code> +{' '}
                          <code className="font-mono text-xs">wp-config.php</code> con{' '}
                          <code className="font-mono text-xs">ZipArchive</code>.
                        </>
                      ) : (
                        <>
                          {' '}y genera un archivo <code className="font-mono text-xs">.zip</code>{' '}
                          exclusivo con <code className="font-mono text-xs">database-backup.sql</code>.
                        </>
                      )}
                    </p>
                  </div>
                  <div className="text-xs font-mono tabular-nums text-[#50575e] whitespace-nowrap shrink-0">
                    {backupType === 'solo-bd'
                      ? 'Solo BD (.sql)'
                      : `${includedFiles.length} incluidos · ${skippedFiles.length} omitidos`}
                  </div>
                </div>

                {/* Nomenclatura Única, Dinámica y Cronológica */}
                <div className="mt-5 grid grid-cols-1 md:grid-cols-[200px_1fr] gap-4 items-center">
                  <label
                    htmlFor="oscarpx-sim-site-name"
                    className="text-[14px] font-semibold text-[#1d2327]"
                  >
                    Nombre del Sitio (<code className="font-mono text-xs">get_bloginfo</code>)
                  </label>
                  <div>
                    <input
                      id="oscarpx-sim-site-name"
                      type="text"
                      value={siteName}
                      onChange={(e) => setSiteName(e.target.value)}
                      disabled={isRunning}
                      className="w-full max-w-md text-[13px] px-3 py-1.5 bg-white border border-[#8c8f94] rounded-[3px] text-[#1d2327] focus:border-[#2271b1] focus:outline-none focus:ring-1 focus:ring-[#2271b1] disabled:bg-[#f6f7f7]"
                    />
                    <p className="mt-1 text-[12px] text-[#50575e]">
                      Sanitizado con <code className="font-mono">sanitize_title()</code>:{' '}
                      <code className="font-mono font-semibold text-[#1d2327]">
                        {sanitizeSiteTitle(siteName)}
                      </code>
                    </p>
                  </div>
                </div>

                <div className="mt-4 grid grid-cols-1 md:grid-cols-[200px_1fr] gap-4 items-center">
                  <label
                    htmlFor="oscarpx-sim-backup-type"
                    className="text-[14px] font-semibold text-[#1d2327]"
                  >
                    Tipo de Backup
                  </label>
                  <div>
                    <select
                      id="oscarpx-sim-backup-type"
                      value={backupType}
                      onChange={(e) => setBackupType(e.target.value as BackupType)}
                      disabled={isRunning}
                      className="w-full max-w-md text-[13px] px-3 py-1.5 bg-white border border-[#8c8f94] rounded-[3px] text-[#1d2327] focus:border-[#2271b1] focus:outline-none focus:ring-1 focus:ring-[#2271b1] disabled:bg-[#f6f7f7]"
                    >
                      <option value="completo">completo — Base de Datos + Archivos</option>
                      <option value="solo-bd">solo-bd — Solo Base de Datos (.sql)</option>
                    </select>
                    <p className="mt-1 text-[12px] text-[#50575e]">
                      Formato generado:{' '}
                      <code className="font-mono text-[#2271b1]">
                        {sanitizeSiteTitle(siteName)}-{backupType}_YYYY-MM-DD_HH-ii-ss.zip
                      </code>
                    </p>
                  </div>
                </div>

                <div className="mt-5 grid grid-cols-1 md:grid-cols-[200px_1fr] gap-4 items-start">
                  <label
                    htmlFor="oscarpx-exclusions"
                    className="text-[14px] font-semibold text-[#1d2327] pt-1"
                  >
                    Carpetas a Excluir
                  </label>
                  <div>
                    <textarea
                      id="oscarpx-exclusions"
                      rows={8}
                      value={exclusionsText}
                      onChange={(e) => setExclusionsText(e.target.value)}
                      disabled={isRunning}
                      className="w-full font-mono text-[13px] leading-relaxed p-3 bg-white border border-[#8c8f94] rounded-[3px] text-[#1d2327] focus:border-[#2271b1] focus:outline-none focus:ring-1 focus:ring-[#2271b1] disabled:bg-[#f6f7f7]"
                      placeholder="wp-content/cache/"
                    />
                    <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[12px] text-[#50575e]">
                      <span>
                        Rutas relativas separadas por saltos de línea. Validación{' '}
                        <code className="font-mono">strpos()</code> previa a{' '}
                        <code className="font-mono">ZipArchive::addFile()</code>.
                      </span>
                      <div className="flex items-center gap-3">
                        <button
                          type="button"
                          onClick={() =>
                            setExclusionsText(DEFAULT_EXCLUDED_PATHS.join('\n'))
                          }
                          disabled={isRunning}
                          className="text-[#2271b1] hover:underline font-medium cursor-pointer disabled:opacity-50"
                        >
                          Restablecer por defecto
                        </button>
                        <button
                          type="button"
                          onClick={() => setShowFilePreview((v) => !v)}
                          className="text-[#2271b1] hover:underline font-medium cursor-pointer"
                        >
                          {showFilePreview
                            ? 'Ocultar vista previa de rutas'
                            : 'Previsualizar exclusiones'}
                        </button>
                      </div>
                    </div>

                    {showFilePreview && (
                      <div className="mt-4 border border-[#dcdcde] bg-[#f6f7f7] p-3 rounded-[3px]">
                        <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-medium text-[#1d2327] mb-2">
                          <span>
                            Evaluación de rutas en tiempo real ({parsedRules.length}{' '}
                            reglas activas)
                          </span>
                          <span className="font-mono tabular-nums text-[#50575e]">
                            Empaquetar: {formatBytes(includedTotalBytes)} · Ahorro:{' '}
                            {formatBytes(skippedTotalBytes)}
                          </span>
                        </div>
                        <div className="max-h-48 overflow-y-auto bg-white border border-[#dcdcde] divide-y divide-[#f0f0f1] text-xs font-mono">
                          {evaluatedFiles.map((file) => (
                            <div
                              key={file.path}
                              className="px-2.5 py-1.5 flex items-center justify-between gap-3"
                            >
                              <span
                                className={`truncate ${
                                  file.excluded
                                    ? 'line-through text-[#8c8f94]'
                                    : 'text-[#1d2327]'
                                }`}
                              >
                                {file.path}
                              </span>
                              <span
                                className={`shrink-0 flex items-center gap-1 font-sans font-medium ${
                                  file.excluded
                                    ? 'text-[#b45309]'
                                    : 'text-[#15803d]'
                                }`}
                              >
                                {file.excluded ? (
                                  <>
                                    <FolderX className="w-3.5 h-3.5" aria-hidden="true" />
                                    <span>Omitido</span>
                                  </>
                                ) : (
                                  <>
                                    <FileArchive className="w-3.5 h-3.5" aria-hidden="true" />
                                    <span>Incluir ({formatBytes(file.sizeBytes)})</span>
                                  </>
                                )}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                <div className="mt-6 pt-4 border-t border-[#dcdcde] flex flex-wrap items-center gap-4">
                  <button
                    type="button"
                    onClick={runSimulatedBackup}
                    disabled={isRunning}
                    className="inline-flex items-center gap-2 px-5 py-2.5 text-[14px] font-semibold text-white bg-[#2271b1] hover:bg-[#135e96] disabled:opacity-60 rounded-[3px] transition-colors cursor-pointer whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#2271b1]"
                  >
                    <HardDrive className="w-4 h-4" aria-hidden="true" />
                    <span>
                      {isRunning
                        ? 'Procesando lotes AJAX...'
                        : backupType === 'solo-bd'
                          ? 'Iniciar Backup Solo BD'
                          : 'Iniciar Backup Completo'}
                    </span>
                  </button>
                  <span className="text-[12px] text-[#50575e] font-mono tabular-nums">
                    Lotes: 250 filas/req · 150 archivos/req · max 15 MB/req
                  </span>
                </div>
              </section>
            ) : activeTab === 'manager' ? (
              <section
                aria-label="Gestor de Backups"
                className="bg-white border border-t-0 border-[#c3c4c7] p-5 sm:p-6"
              >
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-4 border-b border-[#dcdcde]">
                  <div>
                    <h2 className="text-[16px] font-semibold text-[#1d2327]">
                      Gestor de Backups y Subida por Fragmentos
                    </h2>
                    <p className="text-[13px] text-[#50575e] mt-0.5">
                      Escanea{' '}
                      <code className="font-mono text-xs">
                        wp-content/oscarpx-backups/
                      </code>{' '}
                      con <code className="font-mono text-xs">scandir()</code>. Soporta subida
                      externa con <code className="font-mono text-xs">File.slice()</code> (1 MB)
                      y eliminación AJAX blindada contra Directory Traversal.
                    </p>
                  </div>
                  <div className="text-xs font-mono tabular-nums text-[#50575e] whitespace-nowrap shrink-0">
                    {backups.length} archivo(s) .zip
                  </div>
                </div>

                {/* Módulo de Subida (Chunking Upload con File.slice) */}
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    if (!uploadState.active && !isRunning) {
                      setUploadState((prev) => ({ ...prev, isDragOver: true }));
                    }
                  }}
                  onDragLeave={() =>
                    setUploadState((prev) => ({ ...prev, isDragOver: false }))
                  }
                  onDrop={handleDropZoneDrop}
                  className={`mt-5 border-2 border-dashed rounded-[4px] p-5 text-center transition-colors ${
                    uploadState.isDragOver
                      ? 'border-[#2271b1] bg-[#f0f6fc]'
                      : 'border-[#8c8f94] bg-[#f6f7f7]'
                  }`}
                >
                  <UploadCloud
                    className="w-8 h-8 text-[#2271b1] mx-auto mb-2"
                    aria-hidden="true"
                  />
                  <h3 className="text-[14px] font-semibold text-[#1d2327]">
                    Subir Backup Externo (.zip hasta 2 GB+)
                  </h3>
                  <p className="text-[12px] text-[#50575e] mt-1 max-w-xl mx-auto">
                    Arrastra un archivo aquí o selecciónalo. Se divide mediante{' '}
                    <code className="font-mono">File.slice()</code> en fragmentos de 1 MB vía AJAX
                    para sortear límites bajos de{' '}
                    <code className="font-mono">upload_max_filesize</code> (ej. 2M).
                  </p>

                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".zip,application/zip"
                    onChange={handleFileInputChange}
                    aria-label="Seleccionar archivo .zip externo"
                    className="sr-only"
                  />

                  <div className="mt-3.5 flex flex-wrap items-center justify-center gap-3">
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      disabled={isRunning || uploadState.active}
                      className="inline-flex items-center gap-1.5 px-4 py-2 text-[13px] font-semibold bg-white border border-[#2271b1] text-[#2271b1] hover:bg-[#f0f6fc] rounded-[3px] cursor-pointer disabled:opacity-50"
                    >
                      <FolderOpen className="w-4 h-4" aria-hidden="true" />
                      <span>Seleccionar archivo .zip</span>
                    </button>
                    <button
                      type="button"
                      onClick={handleSimulateExternalUpload}
                      disabled={isRunning || uploadState.active}
                      className="inline-flex items-center gap-1.5 px-4 py-2 text-[13px] font-semibold bg-[#2271b1] hover:bg-[#135e96] text-white rounded-[3px] cursor-pointer disabled:opacity-50"
                    >
                      <UploadCloud className="w-4 h-4" aria-hidden="true" />
                      <span>
                        {uploadState.active
                          ? `Subiendo fragmento ${uploadState.chunkIndex}/${uploadState.totalChunks}...`
                          : 'Simular Subida Externa (File.slice 1 MB)'}
                      </span>
                    </button>
                  </div>

                  {uploadState.active && (
                    <div className="mt-4 max-w-lg mx-auto text-left bg-white border border-[#c3c4c7] p-3 rounded-[3px]">
                      <div className="flex items-center justify-between text-xs font-medium text-[#1d2327] mb-1.5">
                        <span className="font-mono truncate">
                          {uploadState.filename} ({uploadState.chunkIndex}/
                          {uploadState.totalChunks} chunks)
                        </span>
                        <span className="font-mono font-semibold text-[#2271b1]">
                          {uploadState.pct}%
                        </span>
                      </div>
                      <div
                        role="progressbar"
                        aria-label="Progreso de subida por fragmentos"
                        aria-valuenow={uploadState.pct}
                        aria-valuemin={0}
                        aria-valuemax={100}
                        className="w-full h-3.5 bg-[#dcdcde] rounded-[2px] overflow-hidden"
                      >
                        <div
                          className="h-full bg-[#2271b1] transition-[width] duration-150"
                          style={{ width: `${uploadState.pct}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>

                {managerNotice && (
                  <div
                    role="status"
                    className={`mt-4 px-4 py-2.5 border text-[13px] text-[#1d2327] ${
                      managerNotice.isError
                        ? 'border-[#b32d2e] bg-[#fcf0f1]'
                        : 'border-[#16a34a] bg-[#f0fdf4]'
                    }`}
                  >
                    {managerNotice.text}
                  </div>
                )}

                {maintenanceActive && (
                  <div
                    role="status"
                    className="mt-4 border border-[#d97706] bg-[#fffbeb] px-4 py-2.5 text-[13px] text-[#1d2327]"
                  >
                    <strong>Modo Mantenimiento activo (.maintenance):</strong> tráfico público y
                    cronjobs detenidos vía <code className="font-mono text-xs">wp_maintenance()</code>{' '}
                    hasta completar Search &amp; Replace.
                  </div>
                )}

                {backups.length === 0 ? (
                  <div className="mt-4 p-4 border border-[#c3c4c7] bg-[#f6f7f7] text-[13px] text-[#1d2327]">
                    No se encontraron archivos <code className="font-mono">.zip</code> en{' '}
                    <code className="font-mono">wp-content/oscarpx-backups/</code>. Crea un
                    backup o sube un <code className="font-mono">.zip</code> externo arriba.
                  </div>
                ) : (
                  <div className="mt-5 overflow-x-auto border border-[#c3c4c7]">
                    <table className="w-full text-left border-collapse text-[13px]">
                      <thead>
                        <tr className="bg-[#f6f7f7] border-b border-[#c3c4c7] text-[#1d2327]">
                          <th className="py-2.5 px-3 font-semibold">
                            Nombre del archivo
                          </th>
                          <th className="py-2.5 px-3 font-semibold whitespace-nowrap">
                            Fecha de creación
                          </th>
                          <th className="py-2.5 px-3 font-semibold whitespace-nowrap">
                            Peso en MB
                          </th>
                          <th className="py-2.5 px-3 font-semibold text-right whitespace-nowrap">
                            Acciones
                          </th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#dcdcde]">
                        {backups.map((item) => {
                          const sizeInMb = (item.sizeBytes / 1048576).toFixed(2);
                          return (
                            <tr key={item.filename} className="hover:bg-[#f6f7f7]">
                              <td className="py-2.5 px-3 font-mono text-xs text-[#1d2327]">
                                {item.filename}
                              </td>
                              <td className="py-2.5 px-3 font-mono tabular-nums text-xs text-[#50575e]">
                                {item.createdAt}
                              </td>
                              <td className="py-2.5 px-3 font-mono tabular-nums text-xs text-[#1d2327] font-medium">
                                {sizeInMb} MB
                              </td>
                              <td className="py-2.5 px-3 text-right">
                                <div className="inline-flex items-center justify-end gap-2">
                                  <button
                                    type="button"
                                    aria-label={`Descargar ${item.filename}`}
                                    disabled={isRunning || uploadState.active}
                                    onClick={() => handleSecureDownload(item.filename)}
                                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium border border-[#2271b1] text-[#2271b1] bg-white hover:bg-[#f0f6fc] rounded-[3px] cursor-pointer disabled:opacity-40"
                                  >
                                    <Download className="w-3.5 h-3.5" aria-hidden="true" />
                                    <span>Descargar</span>
                                  </button>
                                  <button
                                    type="button"
                                    aria-label={`Restaurar ${item.filename}`}
                                    disabled={isRunning || uploadState.active}
                                    onClick={() => {
                                      setSelectedBackup(item.filename);
                                      setPendingManagerRestore(item.filename);
                                      setManagerNotice(null);
                                    }}
                                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-semibold bg-[#2271b1] hover:bg-[#135e96] text-white rounded-[3px] cursor-pointer disabled:opacity-40"
                                  >
                                    <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" />
                                    <span>Restaurar</span>
                                  </button>
                                  <button
                                    type="button"
                                    aria-label={`Eliminar ${item.filename}`}
                                    disabled={isRunning || uploadState.active}
                                    onClick={() => handleSecureAjaxDelete(item.filename)}
                                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium border border-[#b32d2e] text-[#b32d2e] hover:bg-[#fcf0f1] rounded-[3px] cursor-pointer disabled:opacity-40"
                                  >
                                    <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                                    <span>Eliminar</span>
                                  </button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}

                {pendingManagerRestore && (
                  <div
                    data-testid="manager-inline-restore-confirm"
                    className="mt-4 p-4 border border-[#d97706] bg-[#fffbeb] text-[13px] text-[#1d2327] space-y-3"
                  >
                    <div>
                      <strong>Confirmar Restauración Anticaídas:</strong> se activará{' '}
                      <code className="font-mono">.maintenance</code>, se restaurarán{' '}
                      <code className="font-mono">wp-content</code> y las tablas vía{' '}
                      <code className="font-mono">$wpdb</code> desde{' '}
                      <code className="font-mono">{pendingManagerRestore}</code> manteniendo
                      intactos <code className="font-mono">wp-config.php</code> y{' '}
                      <code className="font-mono">.htaccess</code>.
                    </div>
                    <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                      <label
                        htmlFor="oscarpx-manager-target-url"
                        className="text-xs font-semibold text-[#1d2327] shrink-0"
                      >
                        URL de Destino:
                      </label>
                      <input
                        id="oscarpx-manager-target-url"
                        type="url"
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        disabled={isRunning}
                        className="w-full max-w-sm font-mono text-xs px-2.5 py-1.5 bg-white border border-[#8c8f94] rounded-[3px] text-[#1d2327]"
                      />
                      <div className="flex items-center gap-2 sm:ml-auto shrink-0">
                        <button
                          type="button"
                          onClick={() => setPendingManagerRestore(null)}
                          className="px-3 py-1.5 text-xs font-medium border border-[#8c8f94] bg-white text-[#1d2327] rounded-[3px] cursor-pointer"
                        >
                          Cancelar
                        </button>
                        <button
                          type="button"
                          onClick={() => runSimulatedRestore(pendingManagerRestore)}
                          className="px-3 py-1.5 text-xs font-semibold bg-[#b32d2e] hover:bg-[#8a2424] text-white rounded-[3px] cursor-pointer"
                        >
                          Confirmar e Iniciar Restauración Segura
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </section>
            ) : (
              <section
                aria-label="Restaurar Backup"
                className="bg-white border border-t-0 border-[#c3c4c7] p-5 sm:p-6"
              >
                <div className="pb-4 border-b border-[#dcdcde]">
                  <h2 className="text-[16px] font-semibold text-[#1d2327]">
                    Restaurar desde Archivo .zip Existente (Sistema Anticaídas)
                  </h2>
                  <p className="text-[13px] text-[#50575e] mt-0.5">
                    Selecciona un archivo en{' '}
                    <code className="font-mono text-xs">
                      wp-content/oscarpx-backups/
                    </code>
                    . El motor bloquea la sobrescritura de{' '}
                    <code className="font-mono text-xs">wp-config.php</code> y{' '}
                    <code className="font-mono text-xs">.htaccess</code>, activa{' '}
                    <code className="font-mono text-xs">.maintenance</code> hasta finalizar
                    Search &amp; Replace e inyecta SQL por fragmentos vía{' '}
                    <code className="font-mono text-xs">$wpdb</code>.
                  </p>
                </div>

                {/* Resumen de las 3 reglas inquebrantables del Sistema Anticaídas */}
                <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3 text-[12px]">
                  <div className="border border-[#c3c4c7] bg-[#f6f7f7] p-3 rounded-[3px]">
                    <div className="font-semibold text-[#1d2327]">1. Protección del Core</div>
                    <p className="text-[#50575e] mt-1 leading-relaxed">
                      <code className="font-mono">wp-config.php</code> y{' '}
                      <code className="font-mono">.htaccess</code> quedan bloqueados al
                      extraer con <code className="font-mono">ZipArchive</code>.
                    </p>
                  </div>
                  <div className="border border-[#c3c4c7] bg-[#f6f7f7] p-3 rounded-[3px]">
                    <div className="font-semibold text-[#1d2327]">2. Aislamiento (.maintenance)</div>
                    <p className="text-[#50575e] mt-1 leading-relaxed">
                      Activa <code className="font-mono">wp_maintenance()</code> antes del 1er
                      lote y se elimina tras Search &amp; Replace.
                    </p>
                  </div>
                  <div className="border border-[#c3c4c7] bg-[#f6f7f7] p-3 rounded-[3px]">
                    <div className="font-semibold text-[#1d2327]">3. Hot Swap SQL ($wpdb)</div>
                    <p className="text-[#50575e] mt-1 leading-relaxed">
                      Solo <code className="font-mono">DROP TABLE IF EXISTS</code>,{' '}
                      <code className="font-mono">CREATE</code> e{' '}
                      <code className="font-mono">INSERT</code> en fragmentos de baja RAM.
                    </p>
                  </div>
                </div>

                {maintenanceActive && (
                  <div
                    role="status"
                    className="mt-4 border border-[#d97706] bg-[#fffbeb] px-4 py-2.5 text-[13px] text-[#1d2327]"
                  >
                    <strong>Modo Mantenimiento activo (.maintenance):</strong> tráfico público y
                    cronjobs detenidos vía <code className="font-mono text-xs">wp_maintenance()</code>{' '}
                    hasta completar Search &amp; Replace.
                  </div>
                )}

                {backups.length === 0 ? (
                  <div className="mt-4 p-4 border border-[#c3c4c7] bg-[#f6f7f7] text-[13px] text-[#1d2327]">
                    No se encontraron archivos <code className="font-mono">.zip</code> en{' '}
                    <code className="font-mono">wp-content/oscarpx-backups/</code>. Crea un
                    backup en la pestaña anterior.
                  </div>
                ) : (
                  <>
                    <div className="mt-4 overflow-x-auto border border-[#c3c4c7]">
                      <table className="w-full text-left border-collapse text-[13px]">
                        <thead>
                          <tr className="bg-[#f6f7f7] border-b border-[#c3c4c7] text-[#1d2327]">
                            <th className="py-2.5 px-3 w-10">
                              <span className="sr-only">Seleccionar</span>
                            </th>
                            <th className="py-2.5 px-3 font-semibold">
                              Archivo de Respaldo (.zip)
                            </th>
                            <th className="py-2.5 px-3 font-semibold">Tamaño</th>
                            <th className="py-2.5 px-3 font-semibold">Fecha</th>
                            <th className="py-2.5 px-3 font-semibold">Contenido</th>
                            <th className="py-2.5 px-3 font-semibold text-right">
                              Acción
                            </th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[#dcdcde]">
                          {backups.map((item) => {
                            const isChecked = selectedBackup === item.filename;
                            return (
                              <tr
                                key={item.filename}
                                className={
                                  isChecked ? 'bg-[#f0f6fc]' : 'hover:bg-[#f6f7f7]'
                                }
                              >
                                <td className="py-2.5 px-3">
                                  <input
                                    type="radio"
                                    name="oscarpx_selected_backup"
                                    aria-label={`Seleccionar ${item.filename}`}
                                    checked={isChecked}
                                    onChange={() => setSelectedBackup(item.filename)}
                                    disabled={isRunning}
                                  />
                                </td>
                                <td className="py-2.5 px-3 font-mono text-xs text-[#1d2327]">
                                  {item.filename}
                                </td>
                                <td className="py-2.5 px-3 font-mono tabular-nums text-xs text-[#50575e]">
                                  {item.sizeLabel}
                                </td>
                                <td className="py-2.5 px-3 font-mono tabular-nums text-xs text-[#50575e]">
                                  {item.createdAt}
                                </td>
                                <td className="py-2.5 px-3 text-xs text-[#50575e] tabular-nums">
                                  {item.tablesCount} tablas · {item.filesCount} archivos
                                </td>
                                <td className="py-2.5 px-3 text-right">
                                  <div className="inline-flex items-center justify-end gap-3">
                                    <button
                                      type="button"
                                      aria-label={`Descargar ${item.filename}`}
                                      onClick={() => handleSecureDownload(item.filename)}
                                      disabled={isRunning}
                                      className="inline-flex items-center gap-1 text-xs font-medium text-[#2271b1] hover:underline cursor-pointer disabled:opacity-40"
                                    >
                                      <Download className="w-3.5 h-3.5" aria-hidden="true" />
                                      <span>Descargar</span>
                                    </button>
                                    <button
                                      type="button"
                                      aria-label={`Eliminar ${item.filename}`}
                                      onClick={() => onBackupDeleted(item.filename)}
                                      disabled={isRunning}
                                      className="inline-flex items-center gap-1 text-xs font-medium text-[#b32d2e] hover:underline cursor-pointer disabled:opacity-40"
                                    >
                                      <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                                      <span>Eliminar</span>
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>

                    <div className="mt-4 grid grid-cols-1 md:grid-cols-[200px_1fr] gap-3 items-center">
                      <label
                        htmlFor="oscarpx-sim-target-url"
                        className="text-[13px] font-semibold text-[#1d2327]"
                      >
                        URL de Destino (Search &amp; Replace)
                      </label>
                      <div>
                        <input
                          id="oscarpx-sim-target-url"
                          type="url"
                          value={targetUrl}
                          onChange={(e) => setTargetUrl(e.target.value)}
                          disabled={isRunning}
                          className="w-full max-w-md font-mono text-[13px] px-3 py-1.5 bg-white border border-[#8c8f94] rounded-[3px] text-[#1d2327] focus:border-[#2271b1] focus:outline-none focus:ring-1 focus:ring-[#2271b1] disabled:bg-[#f6f7f7]"
                        />
                      </div>
                    </div>

                    {confirmRestoreOpen && (
                      <div className="mt-4 p-4 border border-[#d97706] bg-[#fffbeb] text-[13px] text-[#1d2327] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                        <div>
                          <strong>Confirmar restauración segura:</strong> se activará{' '}
                          <code className="font-mono">.maintenance</code>, se restaurarán{' '}
                          <code className="font-mono">wp-content</code> y las tablas vía{' '}
                          <code className="font-mono">$wpdb</code> desde{' '}
                          <code className="font-mono">{selectedBackup}</code> manteniendo intactos{' '}
                          <code className="font-mono">wp-config.php</code> y{' '}
                          <code className="font-mono">.htaccess</code>.
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            type="button"
                            onClick={() => setConfirmRestoreOpen(false)}
                            className="px-3 py-1.5 text-xs font-medium border border-[#8c8f94] bg-white text-[#1d2327] rounded-[3px] cursor-pointer"
                          >
                            Cancelar
                          </button>
                          <button
                            type="button"
                            onClick={() => runSimulatedRestore()}
                            className="px-3 py-1.5 text-xs font-semibold bg-[#b32d2e] hover:bg-[#8a2424] text-white rounded-[3px] cursor-pointer"
                          >
                            Confirmar y Restaurar
                          </button>
                        </div>
                      </div>
                    )}

                    <div className="mt-5 pt-4 border-t border-[#dcdcde]">
                      <button
                        type="button"
                        onClick={() => setConfirmRestoreOpen(true)}
                        disabled={isRunning || !selectedBackup}
                        className="inline-flex items-center gap-2 px-5 py-2.5 text-[14px] font-semibold text-white bg-[#2271b1] hover:bg-[#135e96] disabled:opacity-60 rounded-[3px] transition-colors cursor-pointer whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#2271b1]"
                      >
                        <RotateCcw className="w-4 h-4" aria-hidden="true" />
                        <span>
                          {isRunning
                            ? 'Restaurando por lotes...'
                            : 'Restaurar Backup Seleccionado'}
                        </span>
                      </button>
                    </div>
                  </>
                )}
              </section>
            )}

            {/* Aviso de éxito */}
            {completedBanner && (
              <div
                role="status"
                className="mt-4 bg-white border border-[#16a34a] px-4 py-3 flex items-center gap-2.5 text-[13px] text-[#1d2327]"
              >
                <CheckCircle2
                  className="w-4 h-4 text-[#16a34a] shrink-0"
                  aria-hidden="true"
                />
                <span>{completedBanner}</span>
              </div>
            )}

            {/* Panel de progreso y log en vivo */}
            {(isRunning || logs.length > 0) && (
              <div
                data-testid="progress-panel"
                className="mt-4 bg-white border border-[#c3c4c7] p-5"
              >
                <div className="flex items-center justify-between gap-4 mb-2">
                  <h3 className="text-[14px] font-semibold text-[#1d2327]">
                    {progressTitle}
                  </h3>
                  <span className="font-mono text-xs font-semibold tabular-nums text-[#2271b1]">
                    {progress}%
                  </span>
                </div>
                <div
                  role="progressbar"
                  aria-valuenow={progress}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  className="w-full h-5 bg-[#dcdcde] rounded-[3px] overflow-hidden mb-3"
                >
                  <div
                    className="h-full bg-[#2271b1] text-white text-[11px] font-semibold leading-5 text-center transition-[width] duration-150"
                    style={{ width: `${progress}%` }}
                  >
                    {progress}%
                  </div>
                </div>
                <pre
                  ref={logBoxRef}
                  className="bg-[#1d2327] text-[#f0f0f1] p-3.5 rounded-[3px] max-h-56 overflow-y-auto text-[12px] leading-relaxed font-mono m-0"
                >
                  {logs.join('\n')}
                </pre>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
