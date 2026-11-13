import { useEffect, useMemo, useRef, useState } from 'react';
import {
  CheckCircle2,
  Database,
  FileArchive,
  FolderX,
  HardDrive,
  RotateCcw,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import {
  DEFAULT_EXCLUDED_PATHS,
  isPathExcluded,
  parseExclusionRules,
  sanitizeBackupFilename,
} from '../lib/exclusionMatcher';
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

type AdminTab = 'create' | 'restore';

export function WpAdminSimulator({
  backups,
  onBackupCreated,
  onBackupDeleted,
}: WpAdminSimulatorProps) {
  const [activeTab, setActiveTab] = useState<AdminTab>('create');
  const [exclusionsText, setExclusionsText] = useState<string>(
    DEFAULT_EXCLUDED_PATHS.join('\n'),
  );
  const [selectedBackup, setSelectedBackup] = useState<string>(
    backups[0]?.filename ?? '',
  );
  const [confirmRestoreOpen, setConfirmRestoreOpen] = useState(false);

  // Estado del proceso asíncrono AJAX por lotes
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressTitle, setProgressTitle] = useState('');
  const [logs, setLogs] = useState<string[]>([]);
  const [completedBanner, setCompletedBanner] = useState<string | null>(null);
  const [showFilePreview, setShowFilePreview] = useState(false);

  const timersRef = useRef<number[]>([]);
  const logBoxRef = useRef<HTMLPreElement | null>(null);

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
    setProgressTitle('Creando Copia de Seguridad Completa (Lotes AJAX)...');
    setLogs([]);

    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
    const rawZipName = `oscarpx-backup-${stamp}.zip`;
    const zipName = sanitizeBackupFilename(rawZipName) ?? 'oscarpx-backup.zip';

    const steps: Array<{ delay: number; fn: () => void }> = [];
    let t = 80;

    steps.push({
      delay: t,
      fn: () => {
        pushLog('POST admin-ajax.php?action=oscarpx_start_backup (nonce verificado + manage_options)');
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
          const pct = 10 + ((idx + 1) / SIMULATED_DB_TABLES.length) * 30;
          setProgress(Math.round(pct));
        },
      });
    });

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

    // Finalización
    t += 200;
    steps.push({
      delay: t,
      fn: () => {
        const dbBytes = SIMULATED_DB_TABLES.reduce((acc, tbl) => acc + tbl.sizeKb * 1024, 0);
        const estimatedZipBytes = Math.round((includedTotalBytes + dbBytes) * 0.58);
        const newBackup: BackupArchiveItem = {
          filename: zipName,
          sizeLabel: formatBytes(estimatedZipBytes),
          sizeBytes: estimatedZipBytes,
          createdAt: `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`,
          tablesCount: SIMULATED_DB_TABLES.length,
          filesCount: includedFiles.length,
          skippedCount: skippedFiles.length,
        };
        onBackupCreated(newBackup);
        setSelectedBackup(zipName);
        setProgress(100);
        pushLog(`Completado: wp-content/oscarpx-backups/${zipName} (${newBackup.sizeLabel}).`);
        setCompletedBanner(
          `Backup ${zipName} creado correctamente (${newBackup.sizeLabel}). Disponible en la pestaña "Restaurar Backup".`,
        );
        setIsRunning(false);
      },
    });

    steps.forEach((step) => {
      const id = window.setTimeout(step.fn, step.delay);
      timersRef.current.push(id);
    });
  }

  function runSimulatedRestore() {
    if (isRunning || !selectedBackup) return;
    const safeName = sanitizeBackupFilename(selectedBackup);
    if (!safeName) return;

    clearScheduledSteps();
    setConfirmRestoreOpen(false);
    setIsRunning(true);
    setCompletedBanner(null);
    setProgress(5);
    setProgressTitle(`Restaurando Backup: ${safeName}`);
    setLogs([]);

    const steps: Array<{ delay: number; fn: () => void }> = [];
    let t = 80;

    steps.push({
      delay: t,
      fn: () => {
        pushLog(`POST admin-ajax.php?action=oscarpx_start_restore -> archivo=${safeName}`);
        pushLog('Validación realpath() correcta dentro de wp-content/oscarpx-backups/.');
        pushLog('Verificado database-backup.sql en la raíz del archivo ZIP.');
        setProgress(15);
      },
    });

    // Extracción por lotes ZipArchive
    for (let batch = 1; batch <= 3; batch++) {
      t += 220;
      steps.push({
        delay: t,
        fn: () => {
          pushLog(
            `[AJAX Extract] ZipArchive lote ${batch}/3: sobrescribiendo wp-content/ y wp-config.php (preservando wp-content/oscarpx-backups/).`,
          );
          setProgress(15 + batch * 12);
        },
      });
    }

    // Restauración SQL por lotes vía $wpdb
    SIMULATED_DB_TABLES.forEach((table, idx) => {
      t += 150;
      steps.push({
        delay: t,
        fn: () => {
          pushLog(
            `[AJAX $wpdb] DROP TABLE IF EXISTS \`${table.name}\`; CREATE TABLE \`${table.name}\`; INSERT ${table.rows} filas.`,
          );
          const pct = 52 + ((idx + 1) / SIMULATED_DB_TABLES.length) * 45;
          setProgress(Math.round(pct));
        },
      });
    });

    t += 180;
    steps.push({
      delay: t,
      fn: () => {
        setProgress(100);
        pushLog('SET FOREIGN_KEY_CHECKS = 1; limpieza de carpeta temporal .tmp-* completada.');
        pushLog('Restauración finalizada sin errores.');
        setCompletedBanner(
          `El sitio y la base de datos han sido restaurados al estado exacto de ${safeName}.`,
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
          className="bg-[#1d2327] text-[#f0f0f1] lg:w-[220px] shrink-0 flex lg:flex-col overflow-x-auto lg:overflow-visible"
        >
          <div className="hidden lg:block px-4 py-3 border-b border-white/10 text-xs font-medium text-[#a7aaad]">
            Escritorio WordPress
          </div>
          <div className="flex lg:flex-col w-full text-[13px]">
            {[
              { label: 'Escritorio', active: false },
              { label: 'Entradas', active: false },
              { label: 'Medios', active: false },
              { label: 'Páginas', active: false },
              { label: 'Plugins', active: false },
              { label: 'OscarPx Backup', active: true },
              { label: 'Ajustes', active: false },
            ].map((item) => (
              <div
                key={item.label}
                className={`px-4 py-2.5 whitespace-nowrap shrink-0 flex items-center gap-2.5 ${
                  item.active
                    ? 'bg-[#2271b1] text-white font-semibold'
                    : 'text-[#c3c4c7]'
                }`}
              >
                {item.active ? (
                  <Database className="w-4 h-4 shrink-0" aria-hidden="true" />
                ) : (
                  <span className="w-4 h-4 shrink-0 inline-block opacity-40 text-center">
                    ·
                  </span>
                )}
                <span>{item.label}</span>
              </div>
            ))}
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
                  Versión 1.0.0 · Autor: OscarPx · Motor AJAX por lotes sin límites de hosting compartido
                </p>
              </div>
            </div>

            {/* Aviso de seguridad de directorio */}
            <div className="bg-white border border-[#c3c4c7] px-4 py-2.5 mb-5 flex items-center gap-2.5 text-[13px] text-[#1d2327]">
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
                disabled={isRunning}
                onClick={() => {
                  setActiveTab('create');
                  setConfirmRestoreOpen(false);
                  if (!isRunning) {
                    setCompletedBanner(null);
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
                aria-selected={activeTab === 'restore'}
                disabled={isRunning}
                onClick={() => {
                  setActiveTab('restore');
                  if (!isRunning) {
                    setCompletedBanner(null);
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
                      Generar Nueva Copia de Seguridad Completa
                    </h2>
                    <p className="text-[13px] text-[#50575e] mt-0.5">
                      Exporta las {SIMULATED_DB_TABLES.length} tablas vía{' '}
                      <code className="font-mono text-xs">$wpdb</code> y empaqueta{' '}
                      <code className="font-mono text-xs">wp-content</code> +{' '}
                      <code className="font-mono text-xs">wp-config.php</code> con{' '}
                      <code className="font-mono text-xs">ZipArchive</code>.
                    </p>
                  </div>
                  <div className="text-xs font-mono tabular-nums text-[#50575e]">
                    {includedFiles.length} incluidos · {skippedFiles.length} omitidos
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
                        : 'Iniciar Backup Completo'}
                    </span>
                  </button>
                  <span className="text-[12px] text-[#50575e] font-mono tabular-nums">
                    Lotes: 250 filas/req · 150 archivos/req · max 15 MB/req
                  </span>
                </div>
              </section>
            ) : (
              <section
                aria-label="Restaurar Backup"
                className="bg-white border border-t-0 border-[#c3c4c7] p-5 sm:p-6"
              >
                <div className="pb-4 border-b border-[#dcdcde]">
                  <h2 className="text-[16px] font-semibold text-[#1d2327]">
                    Restaurar desde Archivo .zip Existente
                  </h2>
                  <p className="text-[13px] text-[#50575e] mt-0.5">
                    Selecciona un archivo almacenado en{' '}
                    <code className="font-mono text-xs">
                      wp-content/oscarpx-backups/
                    </code>
                    . El motor extraerá archivos con{' '}
                    <code className="font-mono text-xs">ZipArchive</code> y ejecutará las
                    sentencias <code className="font-mono text-xs">DROP</code> e{' '}
                    <code className="font-mono text-xs">INSERT</code> mediante{' '}
                    <code className="font-mono text-xs">$wpdb</code>.
                  </p>
                </div>

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
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>

                    {confirmRestoreOpen && (
                      <div className="mt-4 p-4 border border-[#d97706] bg-[#fffbeb] text-[13px] text-[#1d2327] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                        <div>
                          <strong>Confirmar restauración:</strong> se sobrescribirán los
                          archivos en <code className="font-mono">wp-content</code> y las
                          tablas de la base de datos con{' '}
                          <code className="font-mono">{selectedBackup}</code>.
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
                            onClick={runSimulatedRestore}
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
