import { Database, FileArchive, Filter, Lock, RefreshCw, Shield } from 'lucide-react';

export function ArchitectureOverview() {
  const modules = [
    {
      icon: Database,
      title: '01. Motor de Base de Datos ($wpdb)',
      file: 'includes/class-oscarpx-db-engine.php',
      body: 'Itera sobre todas las tablas mediante SHOW TABLES y vuelca estructura (SHOW CREATE TABLE) y filas en lotes de 250 registros con LIMIT/OFFSET. Escapa valores con $wpdb->_real_escape() sin recurrir a exec("mysqldump").',
    },
    {
      icon: FileArchive,
      title: '02. Motor de Archivos (ZipArchive)',
      file: 'includes/class-oscarpx-file-engine.php',
      body: 'Construye un manifiesto ligero en disco y empaqueta wp-content, wp-config.php y database-backup.sql en wp-content/oscarpx-backups/ mediante ZipArchive en lotes de 150 archivos o 15 MB por petición AJAX.',
    },
    {
      icon: Filter,
      title: '03. Omisión Recursiva O(k) sin Regex Pesadas',
      file: 'OscarPx_File_Engine::is_path_excluded()',
      body: 'Normaliza el contenido del textarea "Carpetas a Excluir" una sola vez por lote y evalúa cada ruta mediante comparación directa por prefijo con strpos() === 0, evitando descender en directorios excluidos y revalidando antes de ZipArchive::addFile().',
    },
    {
      icon: RefreshCw,
      title: '04. Sistema Anticaídas (Restauración Segura)',
      file: 'includes/class-oscarpx-restore-engine.php',
      body: 'Cumple 3 reglas inquebrantables: (1) bloquea explícitamente la sobrescritura de wp-config.php y .htaccess al extraer con ZipArchive; (2) activa .maintenance (wp_maintenance()) antes del primer lote AJAX y solo lo elimina tras concluir Search & Replace; (3) inyecta SQL Hot Swap vía $wpdb con DROP TABLE IF EXISTS / CREATE / INSERT en fragmentos de máx. 2 MB.',
    },
    {
      icon: Lock,
      title: '05. Gestor, Nomenclatura y Descarga Stream',
      file: 'includes/class-oscarpx-security.php · OscarPx_Admin',
      body: 'Genera nombres {sitio}-{tipo}_{Y-m-d_H-i-s}.zip (get_bloginfo + sanitize_title), escanea con scandir(), sube chunks File.slice() (1 MB), protege con .htaccess (Deny from all) y transmite descargas vía admin_post_download_oscarpx_backup con fread() + ob_clean()/flush() tras validar Nonce, manage_options, sanitize_file_name() y realpath().',
    },
    {
      icon: Shield,
      title: '06. Ecosistema PX Tools y Metadatos',
      file: 'oscarpx-backup-restore.php · OscarPx_Admin::register_menu_page()',
      body: 'Verifica globalmente si el menú maestro px-tools ya existe ($admin_page_hooks / $menu); si no existe lo registra con add_menu_page("PX Tools", "manage_options", "dashicons-superhero") y apila este plugin mediante add_submenu_page("px-tools", ...). Metadatos oficiales: OscarPx Backup & Restore v1.0.0 (Author: OscarPx).',
    },
  ];

  return (
    <div className="max-w-[1380px] mx-auto px-4 sm:px-6 py-6">
      <div className="bg-white border border-slate-200 rounded p-6 sm:p-8">
        <div className="max-w-2xl pb-6 border-b border-slate-200">
          <h1 className="text-2xl font-bold text-slate-900">
            Arquitectura de OscarPx Backup &amp; Restore
          </h1>
          <p className="text-sm text-slate-600 mt-2 leading-relaxed">
            Diseñado para ejecutarse de forma fiable en hosting compartido con límites estrictos
            de <code className="font-mono text-xs">max_execution_time</code> y memoria PHP,
            evitando errores 504 Gateway Timeout mediante chunking asíncrono por AJAX.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-8 pt-6">
          {modules.map((mod) => {
            const Icon = mod.icon;
            return (
              <article key={mod.title} className="flex flex-col">
                <div className="flex items-center gap-2.5 text-slate-900 font-semibold text-base">
                  <Icon className="w-4 h-4 text-[#2271b1] shrink-0" aria-hidden="true" />
                  <h2>{mod.title}</h2>
                </div>
                <div className="mt-1 font-mono text-xs text-[#2271b1]">{mod.file}</div>
                <p className="mt-2.5 text-sm text-slate-600 leading-relaxed">{mod.body}</p>
              </article>
            );
          })}
        </div>
      </div>
    </div>
  );
}
