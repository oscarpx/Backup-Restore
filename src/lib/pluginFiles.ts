export interface PluginFile {
  path: string;
  language: 'php' | 'javascript' | 'css' | 'text';
  summary: string;
  content: string;
}

export const PLUGIN_FILES: PluginFile[] = [
  {
    path: 'oscarpx-backup-restore.php',
    language: 'php',
    summary: 'Archivo principal del plugin, cabecera de metadatos, hooks de activación y carga de clases.',
    content: `<?php
/**
 * Plugin Name:       OscarPx Backup & Restore
 * Plugin URI:        https://oscarpx.com
 * Description:       Motor ligero y asíncrono de copias de seguridad completas (Archivos + Base de Datos) y restauración por lotes AJAX, con filtro dinámico de exclusión de carpetas.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            OscarPx
 * Author URI:        https://oscarpx.com
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       oscarpx-backup-restore
 */

if ( ! defined( 'ABSPATH' ) ) {
\texit; // Evitar acceso directo al archivo.
}

define( 'OSCARPX_BR_VERSION', '1.0.0' );
define( 'OSCARPX_BR_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'OSCARPX_BR_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'OSCARPX_BR_BACKUP_DIR', trailingslashit( WP_CONTENT_DIR ) . 'oscarpx-backups/' );

require_once OSCARPX_BR_PLUGIN_DIR . 'includes/class-oscarpx-security.php';
require_once OSCARPX_BR_PLUGIN_DIR . 'includes/class-oscarpx-db-engine.php';
require_once OSCARPX_BR_PLUGIN_DIR . 'includes/class-oscarpx-file-engine.php';
require_once OSCARPX_BR_PLUGIN_DIR . 'includes/class-oscarpx-restore-engine.php';
require_once OSCARPX_BR_PLUGIN_DIR . 'includes/class-oscarpx-admin.php';

/**
 * Inicializa la carpeta segura de backups al activar el plugin.
 */
function oscarpx_br_activate() {
\tOscarPx_Security::ensure_backup_directory();
}
register_activation_hook( __FILE__, 'oscarpx_br_activate' );

/**
 * Arranca la instancia principal del plugin en el área de administración.
 */
function oscarpx_br_init() {
\tif ( is_admin() ) {
\t\t$admin = new OscarPx_Admin();
\t\t$admin->init();
\t}
}
add_action( 'plugins_loaded', 'oscarpx_br_init' );
`,
  },
  {
    path: 'includes/class-oscarpx-security.php',
    language: 'php',
    summary: 'Capa de seguridad: validación de nonces, capacidad manage_options, protección .htaccess e index.php y sanitización de rutas.',
    content: `<?php
/**
 * Seguridad, control de acceso y endurecimiento del directorio de backups.
 *
 * @package OscarPx_Backup_Restore
 */

if ( ! defined( 'ABSPATH' ) ) {
\texit;
}

class OscarPx_Security {

\t/**
\t * Valida nonce AJAX y permisos de administrador (manage_options).
\t * Finaliza la ejecución con código HTTP 403 si falla la verificación.
\t */
\tpublic static function verify_ajax_request() {
\t\tcheck_ajax_referer( 'oscarpx_backup_nonce', 'nonce' );

\t\tif ( ! current_user_can( 'manage_options' ) ) {
\t\t\twp_send_json_error(
\t\t\t\tarray(
\t\t\t\t\t'message' => __( 'Acceso denegado: se requieren permisos manage_options.', 'oscarpx-backup-restore' ),
\t\t\t\t),
\t\t\t\t403
\t\t\t);
\t\t}
\t}

\t/**
\t * Crea automáticamente wp-content/oscarpx-backups/ con .htaccess (Deny from all)
\t * e index.php vacío para bloquear descargas públicas directas.
\t *
\t * @return string|WP_Error Ruta absoluta al directorio o error.
\t */
\tpublic static function ensure_backup_directory() {
\t\t$backup_dir = OSCARPX_BR_BACKUP_DIR;

\t\tif ( ! file_exists( $backup_dir ) ) {
\t\t\tif ( ! wp_mkdir_p( $backup_dir ) ) {
\t\t\t\treturn new WP_Error(
\t\t\t\t\t'oscarpx_mkdir_failed',
\t\t\t\t\t__( 'No se pudo crear el directorio wp-content/oscarpx-backups/. Verifique los permisos de escritura.', 'oscarpx-backup-restore' )
\t\t\t\t);
\t\t\t}
\t\t}

\t\t// Regla Apache 2.2 y 2.4+ para impedir descarga directa por HTTP.
\t\t$htaccess_path = $backup_dir . '.htaccess';
\t\tif ( ! file_exists( $htaccess_path ) ) {
\t\t\t$htaccess_rules  = "# Proteccion OscarPx Backup & Restore\\n";
\t\t\t$htaccess_rules .= "Order deny,allow\\n";
\t\t\t$htaccess_rules .= "Deny from all\\n";
\t\t\t$htaccess_rules .= "<IfModule mod_authz_core.c>\\n";
\t\t\t$htaccess_rules .= "    Require all denied\\n";
\t\t\t$htaccess_rules .= "</IfModule>\\n";
\t\t\t@file_put_contents( $htaccess_path, $htaccess_rules );
\t\t}

\t\t// Archivo index.php vacío para evitar listado de directorios.
\t\t$index_path = $backup_dir . 'index.php';
\t\tif ( ! file_exists( $index_path ) ) {
\t\t\t@file_put_contents( $index_path, "<?php\\n// Silence is golden.\\n" );
\t\t}

\t\treturn $backup_dir;
\t}

\t/**
\t * Sanitiza un nombre de archivo .zip y verifica contención estricta dentro del directorio de backups.
\t *
\t * @param string $raw_filename Nombre enviado por el cliente.
\t * @return string|WP_Error Nombre sanitizado o error si es inválido.
\t */
\tpublic static function sanitize_zip_filename( $raw_filename ) {
\t\t$base = basename( wp_unslash( (string) $raw_filename ) );
\t\t$safe = sanitize_file_name( $base );

\t\tif ( empty( $safe ) || ! preg_match( '/^[a-zA-Z0-9._-]+\\.zip$/i', $safe ) ) {
\t\t\treturn new WP_Error(
\t\t\t\t'oscarpx_invalid_filename',
\t\t\t\t__( 'Nombre de archivo ZIP inválido.', 'oscarpx-backup-restore' )
\t\t\t);
\t\t}

\t\treturn $safe;
\t}

\t/**
\t * Resuelve y verifica que un archivo .zip resida físicamente dentro de wp-content/oscarpx-backups/.
\t *
\t * @param string $raw_filename Nombre del archivo.
\t * @return string|WP_Error Ruta absoluta verificada o error.
\t */
\tpublic static function resolve_existing_backup_path( $raw_filename ) {
\t\t$safe_name = self::sanitize_zip_filename( $raw_filename );
\t\tif ( is_wp_error( $safe_name ) ) {
\t\t\treturn $safe_name;
\t\t}

\t\t$base_dir  = realpath( OSCARPX_BR_BACKUP_DIR );
\t\t$full_path = realpath( OSCARPX_BR_BACKUP_DIR . $safe_name );

\t\tif ( false === $base_dir || false === $full_path || 0 !== strpos( $full_path, $base_dir . DIRECTORY_SEPARATOR ) ) {
\t\t\treturn new WP_Error(
\t\t\t\t'oscarpx_backup_not_found',
\t\t\t\t__( 'El archivo de respaldo especificado no existe o está fuera del directorio permitido.', 'oscarpx-backup-restore' )
\t\t\t);
\t\t}

\t\treturn $full_path;
\t}

\t/**
\t * Sanitiza un identificador de tarea (job_id) y devuelve la carpeta temporal segura.
\t *
\t * @param string $job_id Identificador alfanumérico de la operación.
\t * @return string|WP_Error Ruta temporal segura.
\t */
\tpublic static function get_job_temp_dir( $job_id ) {
\t\t$clean_id = preg_replace( '/[^a-zA-Z0-9_-]/', '', (string) $job_id );
\t\tif ( empty( $clean_id ) ) {
\t\t\treturn new WP_Error( 'oscarpx_invalid_job', __( 'Identificador de tarea inválido.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$temp_dir = OSCARPX_BR_BACKUP_DIR . '.tmp-' . $clean_id . '/';
\t\tif ( ! file_exists( $temp_dir ) ) {
\t\t\twp_mkdir_p( $temp_dir );
\t\t\t@file_put_contents( $temp_dir . 'index.php', "<?php\\n// Silence is golden.\\n" );
\t\t}

\t\treturn $temp_dir;
\t}

\t/**
\t * Elimina recursivamente un directorio temporal al finalizar backup o restauración.
\t *
\t * @param string $temp_dir Ruta del directorio temporal.
\t */
\tpublic static function cleanup_temp_dir( $temp_dir ) {
\t\tif ( empty( $temp_dir ) || ! is_dir( $temp_dir ) ) {
\t\t\treturn;
\t\t}

\t\t$base_dir = realpath( OSCARPX_BR_BACKUP_DIR );
\t\t$target   = realpath( $temp_dir );

\t\tif ( false === $base_dir || false === $target || 0 !== strpos( $target, $base_dir . DIRECTORY_SEPARATOR ) ) {
\t\t\treturn;
\t\t}

\t\t$iterator = new RecursiveIteratorIterator(
\t\t\tnew RecursiveDirectoryIterator( $target, RecursiveDirectoryIterator::SKIP_DOTS ),
\t\t\tRecursiveIteratorIterator::CHILD_FIRST
\t\t);

\t\tforeach ( $iterator as $item ) {
\t\t\tif ( $item->isDir() ) {
\t\t\t\t@rmdir( $item->getRealPath() );
\t\t\t} else {
\t\t\t\t@unlink( $item->getRealPath() );
\t\t\t}
\t\t}
\t\t@rmdir( $target );
\t}
}
`,
  },
  {
    path: 'includes/class-oscarpx-db-engine.php',
    language: 'php',
    summary: 'Motor de exportación de base de datos por lotes usando $wpdb (sin exec/mysqldump).',
    content: `<?php
/**
 * Motor de Backup de Base de Datos usando exclusivamente $wpdb y volcado por lotes.
 *
 * @package OscarPx_Backup_Restore
 */

if ( ! defined( 'ABSPATH' ) ) {
\texit;
}

class OscarPx_DB_Engine {

\t/**
\t * Cantidad máxima de filas por petición AJAX para evitar timeouts 504.
\t */
\tconst ROWS_PER_CHUNK = 250;

\t/**
\t * Obtiene la lista ordenada de todas las tablas de la base de datos.
\t *
\t * @return array Lista de nombres de tabla.
\t */
\tpublic function get_all_tables() {
\t\tglobal $wpdb;
\t\t$results = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );
\t\t$tables  = array();

\t\tif ( is_array( $results ) ) {
\t\t\tforeach ( $results as $row ) {
\t\t\t\tif ( isset( $row[0] ) ) {
\t\t\t\t\t$tables[] = $row[0];
\t\t\t\t}
\t\t\t}
\t\t}

\t\treturn $tables;
\t}

\t/**
\t * Inicializa el archivo .sql con la cabecera de compatibilidad y desactivación de FK.
\t *
\t * @param string $sql_file Ruta al archivo .sql temporal.
\t * @return bool|WP_Error
\t */
\tpublic function init_sql_dump( $sql_file ) {
\t\tglobal $wpdb;

\t\t$header  = "-- OscarPx Backup & Restore SQL Dump\\n";
\t\t$header .= '-- Version: ' . OSCARPX_BR_VERSION . "\\n";
\t\t$header .= '-- Fecha UTC: ' . gmdate( 'Y-m-d H:i:s' ) . "\\n";
\t\t$header .= '-- Sitio: ' . home_url() . "\\n";
\t\t$header .= '-- Charset: ' . $wpdb->charset . "\\n\\n";
\t\t$header .= "SET SQL_MODE = \\"NO_AUTO_VALUE_ON_ZERO\\";\\n";
\t\t$header .= "SET FOREIGN_KEY_CHECKS = 0;\\n";
\t\t$header .= "SET NAMES utf8mb4;\\n\\n";

\t\tif ( false === @file_put_contents( $sql_file, $header ) ) {
\t\t\treturn new WP_Error( 'oscarpx_sql_write', __( 'No se pudo inicializar el archivo .sql temporal.', 'oscarpx-backup-restore' ) );
\t\t}

\t\treturn true;
\t}

\t/**
\t * Exporta un lote de filas de la tabla actual hacia el archivo .sql.
\t *
\t * @param string $sql_file    Ruta del archivo .sql.
\t * @param array  $tables      Lista total de tablas.
\t * @param int    $table_index Índice de la tabla en curso.
\t * @param int    $row_offset  Desplazamiento actual dentro de la tabla.
\t * @return array|WP_Error Estado del siguiente lote.
\t */
\tpublic function export_chunk( $sql_file, $tables, $table_index, $row_offset ) {
\t\tglobal $wpdb;

\t\t$total_tables = count( $tables );
\t\tif ( $table_index >= $total_tables ) {
\t\t\t@file_put_contents( $sql_file, "\\nSET FOREIGN_KEY_CHECKS = 1;\\n", FILE_APPEND );
\t\t\treturn array(
\t\t\t\t'done'        => true,
\t\t\t\t'table_index' => $total_tables,
\t\t\t\t'row_offset'  => 0,
\t\t\t\t'total'       => $total_tables,
\t\t\t\t'message'     => __( 'Volcado SQL completado.', 'oscarpx-backup-restore' ),
\t\t\t);
\t\t}

\t\t$table_name = $tables[ $table_index ];
\t\t$safe_table = str_replace( '\`', '\`\`', $table_name );
\t\t$handle     = @fopen( $sql_file, 'ab' );

\t\tif ( ! $handle ) {
\t\t\treturn new WP_Error( 'oscarpx_sql_open', __( 'No se pudo abrir el archivo .sql para escritura.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t// Al iniciar cada tabla (offset 0), escribimos DROP TABLE + CREATE TABLE.
\t\tif ( 0 === (int) $row_offset ) {
\t\t\t$create_row = $wpdb->get_row( "SHOW CREATE TABLE \`{$safe_table}\`", ARRAY_N );
\t\t\t$ddl        = isset( $create_row[1] ) ? $create_row[1] : '';

\t\t\tfwrite( $handle, "\\n-- --------------------------------------------------------\\n" );
\t\t\tfwrite( $handle, "-- Estructura y datos de la tabla \`{$safe_table}\`\\n" );
\t\t\tfwrite( $handle, "-- --------------------------------------------------------\\n\\n" );
\t\t\tfwrite( $handle, "DROP TABLE IF EXISTS \`{$safe_table}\`;\\n" );
\t\t\tif ( ! empty( $ddl ) ) {
\t\t\t\tfwrite( $handle, $ddl . ";\\n\\n" );
\t\t\t}
\t\t}

\t\t$limit = self::ROWS_PER_CHUNK;
\t\t$rows  = $wpdb->get_results(
\t\t\t$wpdb->prepare( "SELECT * FROM \`{$safe_table}\` LIMIT %d OFFSET %d", $limit, (int) $row_offset ),
\t\t\tARRAY_A
\t\t);

\t\t$exported_rows = is_array( $rows ) ? count( $rows ) : 0;

\t\tif ( $exported_rows > 0 ) {
\t\t\t$columns    = array_keys( $rows[0] );
\t\t\t$col_list   = array_map(
\t\t\t\tfunction ( $col ) {
\t\t\t\t\treturn '\`' . str_replace( '\`', '\`\`', $col ) . '\`';
\t\t\t\t},
\t\t\t\t$columns
\t\t\t);
\t\t\t$insert_sql = 'INSERT INTO \`' . $safe_table . '\` (' . implode( ', ', $col_list ) . ') VALUES ';

\t\t\t$value_groups = array();
\t\t\tforeach ( $rows as $row ) {
\t\t\t\t$escaped_vals = array();
\t\t\t\tforeach ( $row as $value ) {
\t\t\t\t\tif ( is_null( $value ) ) {
\t\t\t\t\t\t$escaped_vals[] = 'NULL';
\t\t\t\t\t} else {
\t\t\t\t\t\t$escaped_vals[] = "'" . $wpdb->_real_escape( (string) $value ) . "'";
\t\t\t\t\t}
\t\t\t\t}
\t\t\t\t$value_groups[] = '(' . implode( ', ', $escaped_vals ) . ')';
\t\t\t}

\t\t\t// Escribimos bloques de hasta 50 filas por INSERT para mantener compatibilidad con max_allowed_packet.
\t\t\tforeach ( array_chunk( $value_groups, 50 ) as $chunk_group ) {
\t\t\t\tfwrite( $handle, $insert_sql . implode( ",\\n", $chunk_group ) . ";\\n" );
\t\t\t}
\t\t}

\t\tfclose( $handle );

\t\t// Determinar si continuamos con más filas de la misma tabla o avanzamos a la siguiente.
\t\tif ( $exported_rows === $limit ) {
\t\t\t$next_table_index = $table_index;
\t\t\t$next_offset      = $row_offset + $exported_rows;
\t\t\t$msg              = sprintf( 'Tabla %s: exportadas %d filas (offset %d)...', $table_name, $exported_rows, $next_offset );
\t\t} else {
\t\t\t$next_table_index = $table_index + 1;
\t\t\t$next_offset      = 0;
\t\t\t$msg              = sprintf( 'Tabla %s completada (%d/%d).', $table_name, $table_index + 1, $total_tables );
\t\t}

\t\t$done = ( $next_table_index >= $total_tables );
\t\tif ( $done ) {
\t\t\t@file_put_contents( $sql_file, "\\nSET FOREIGN_KEY_CHECKS = 1;\\n", FILE_APPEND );
\t\t}

\t\treturn array(
\t\t\t'done'        => $done,
\t\t\t'table_index' => $next_table_index,
\t\t\t'row_offset'  => $next_offset,
\t\t\t'total'       => $total_tables,
\t\t\t'message'     => $msg,
\t\t);
\t}
}
`,
  },
  {
    path: 'includes/class-oscarpx-file-engine.php',
    language: 'php',
    summary: 'Motor de archivos ZipArchive por lotes AJAX con filtro de exclusión O(k) sin regex pesadas ni sobrecarga de memoria.',
    content: `<?php
/**
 * Motor de empaquetado de archivos con ZipArchive, chunking AJAX y omisión recursiva eficiente.
 *
 * @package OscarPx_Backup_Restore
 */

if ( ! defined( 'ABSPATH' ) ) {
\texit;
}

class OscarPx_File_Engine {

\t/**
\t * Límite de archivos y volumen por lote AJAX para evitar 504 Gateway Timeout.
\t */
\tconst FILES_PER_CHUNK = 150;
\tconst BYTES_PER_CHUNK = 15728640; // 15 MB por lote.

\t/**
\t * Rutas relativas por defecto mostradas en el textarea "Carpetas a Excluir".
\t *
\t * @return array
\t */
\tpublic static function get_default_exclusions() {
\t\treturn array(
\t\t\t'wp-content/cache/',
\t\t\t'wp-content/updraft/',
\t\t\t'wp-content/oscarpx-backups/',
\t\t\t'wp-content/ai1wm-backups/',
\t\t\t'wp-content/backups-dup-lite/',
\t\t\t'wp-content/et-cache/',
\t\t\t'wp-content/w3tc-config/',
\t\t\t'wp-content/debug.log',
\t\t);
\t}

\t/**
\t * Normaliza las líneas del textarea en prefijos limpios para comparación rápida con strpos().
\t * Se ejecuta una sola vez por petición AJAX.
\t *
\t * @param string $raw_textarea Contenido del campo "Carpetas a Excluir".
\t * @return array Lista de rutas relativas normalizadas (sin barra inicial/final).
\t */
\tpublic function parse_exclusion_rules( $raw_textarea ) {
\t\t$lines = preg_split( '/\\r\\n|\\r|\\n/', (string) $raw_textarea );
\t\t$rules = array();

\t\tif ( ! is_array( $lines ) ) {
\t\t\treturn $rules;
\t\t}

\t\tforeach ( $lines as $line ) {
\t\t\t$clean = trim( str_replace( '\\\\', '/', $line ) );
\t\t\tif ( '' === $clean ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t$clean = ltrim( $clean, './' );
\t\t\t$clean = rtrim( $clean, '/' );

\t\t\t// Bloquear secuencias de path traversal en reglas de usuario.
\t\t\tif ( '' === $clean || false !== strpos( $clean, '..' ) ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t$rules[ $clean ] = $clean;
\t\t}

\t\t// Garantizar siempre que la carpeta propia de backups nunca entre en bucle.
\t\t$rules['wp-content/oscarpx-backups'] = 'wp-content/oscarpx-backups';

\t\treturn array_values( $rules );
\t}

\t/**
\t * Comprueba en tiempo O(k) sin regex ni asignaciones pesadas si una ruta relativa
\t * coincide con alguna carpeta o archivo excluido.
\t *
\t * @param string $relative_path Ruta relativa desde ABSPATH (ej. "wp-content/cache/index.html").
\t * @param array  $rules         Reglas normalizadas desde parse_exclusion_rules().
\t * @return bool True si debe omitirse.
\t */
\tpublic function is_path_excluded( $relative_path, array $rules ) {
\t\t$clean_path = ltrim( str_replace( '\\\\', '/', $relative_path ), './' );

\t\tforeach ( $rules as $rule ) {
\t\t\tif ( $clean_path === $rule ) {
\t\t\t\treturn true;
\t\t\t}
\t\t\t// Comparación directa por prefijo con strpos() === 0 para máxima velocidad.
\t\t\tif ( 0 === strpos( $clean_path, $rule . '/' ) ) {
\t\t\t\treturn true;
\t\t\t}
\t\t}

\t\treturn false;
\t}

\t/**
\t * Escanea wp-content y wp-config.php escribiendo un manifiesto ligero en disco
\t * (una ruta relativa por línea) y podando directorios excluidos durante el recorrido.
\t *
\t * @param string $manifest_file Ruta al archivo manifiesto temporal.
\t * @param array  $rules         Reglas de exclusión normalizadas.
\t * @return array|WP_Error Resumen de archivos indexados y omitidos.
\t */
\tpublic function build_manifest( $manifest_file, array $rules ) {
\t\t$handle = @fopen( $manifest_file, 'wb' );
\t\tif ( ! $handle ) {
\t\t\treturn new WP_Error( 'oscarpx_manifest_err', __( 'No se pudo crear el manifiesto de archivos.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$abs_root    = rtrim( str_replace( '\\\\', '/', ABSPATH ), '/' ) . '/';
\t\t$abs_len     = strlen( $abs_root );
\t\t$wp_content  = str_replace( '\\\\', '/', WP_CONTENT_DIR );
\t\t$total_files = 0;
\t\t$skipped     = 0;

\t\t// 1. Incluir wp-config.php (en ABSPATH o un nivel superior si el sitio lo movió).
\t\t$config_candidates = array(
\t\t\t$abs_root . 'wp-config.php'                => 'wp-config.php',
\t\t\tdirectory_exists_config_path( $abs_root )  => 'wp-config.php',
\t\t);

\t\tforeach ( $config_candidates as $candidate_abs => $rel_entry ) {
\t\t\tif ( $candidate_abs && file_exists( $candidate_abs ) && is_readable( $candidate_abs ) ) {
\t\t\t\tif ( ! $this->is_path_excluded( $rel_entry, $rules ) ) {
\t\t\t\t\tfwrite( $handle, $candidate_abs . '|' . $rel_entry . "\\n" );
\t\t\t\t\t++$total_files;
\t\t\t\t}
\t\t\t\tbreak;
\t\t\t}
\t\t}

\t\t// 2. Recorrer wp-content podando recursivamente las carpetas excluidas.
\t\tif ( is_dir( $wp_content ) ) {
\t\t\t$dir_iter = new RecursiveDirectoryIterator(
\t\t\t\t$wp_content,
\t\t\t\tRecursiveDirectoryIterator::SKIP_DOTS | FilesystemIterator::FOLLOW_SYMLINKS
\t\t\t);

\t\t\t$filter_iter = new RecursiveCallbackFilterIterator(
\t\t\t\t$dir_iter,
\t\t\t\tfunction ( $current ) use ( $abs_root, $abs_len, $rules, &$skipped ) {
\t\t\t\t\t$full_path = str_replace( '\\\\', '/', $current->getPathname() );
\t\t\t\t\t$rel_path  = ( 0 === strpos( $full_path, $abs_root ) )
\t\t\t\t\t\t? substr( $full_path, $abs_len )
\t\t\t\t\t\t: 'wp-content/' . ltrim( str_replace( str_replace( '\\\\', '/', WP_CONTENT_DIR ), '', $full_path ), '/' );

\t\t\t\t\tif ( $this->is_path_excluded( $rel_path, $rules ) ) {
\t\t\t\t\t\t++$skipped;
\t\t\t\t\t\treturn false; // Evita descender dentro de carpetas excluidas.
\t\t\t\t\t}
\t\t\t\t\treturn true;
\t\t\t\t}
\t\t\t);

\t\t\t$iterator = new RecursiveIteratorIterator( $filter_iter, RecursiveIteratorIterator::LEAVES_ONLY );
\t\t\tforeach ( $iterator as $file_info ) {
\t\t\t\tif ( ! $file_info->isFile() || ! $file_info->isReadable() ) {
\t\t\t\t\tcontinue;
\t\t\t\t}

\t\t\t\t$full_path = str_replace( '\\\\', '/', $file_info->getPathname() );
\t\t\t\t$rel_path  = ( 0 === strpos( $full_path, $abs_root ) )
\t\t\t\t\t? substr( $full_path, $abs_len )
\t\t\t\t\t: 'wp-content/' . ltrim( str_replace( str_replace( '\\\\', '/', WP_CONTENT_DIR ), '', $full_path ), '/' );

\t\t\t\tfwrite( $handle, $full_path . '|' . $rel_path . "\\n" );
\t\t\t\t++$total_files;
\t\t\t}
\t\t}

\t\tfclose( $handle );

\t\treturn array(
\t\t\t'total_files' => $total_files,
\t\t\t'skipped'     => $skipped,
\t\t);
\t}

\t/**
\t * Empaqueta un lote de archivos desde el manifiesto hacia el archivo .zip.
\t * Re-verifica la exclusión justo antes de ejecutar ZipArchive::addFile().
\t *
\t * @param string $zip_path      Ruta del archivo .zip final en wp-content/oscarpx-backups/.
\t * @param string $manifest_file Ruta al manifiesto.
\t * @param string $sql_file      Ruta al volcado .sql generado.
\t * @param int    $line_offset   Línea inicial en el manifiesto.
\t * @param int    $total_files   Total de líneas en el manifiesto.
\t * @param array  $rules         Reglas de exclusión normalizadas.
\t * @return array|WP_Error
\t */
\tpublic function pack_chunk( $zip_path, $manifest_file, $sql_file, $line_offset, $total_files, array $rules ) {
\t\tif ( ! class_exists( 'ZipArchive' ) ) {
\t\t\treturn new WP_Error( 'oscarpx_no_zip', __( 'La extensión PHP ZipArchive no está disponible en este servidor.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$zip   = new ZipArchive();
\t\t$flags = ( 0 === (int) $line_offset ) ? ( ZipArchive::CREATE | ZipArchive::OVERWRITE ) : ZipArchive::CREATE;

\t\tif ( true !== $zip->open( $zip_path, $flags ) ) {
\t\t\treturn new WP_Error( 'oscarpx_zip_open', __( 'No se pudo abrir el archivo ZIP para escritura.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t// En el primer lote insertamos el volcado SQL generado por $wpdb.
\t\tif ( 0 === (int) $line_offset && file_exists( $sql_file ) ) {
\t\t\t$zip->addFile( $sql_file, 'database-backup.sql' );
\t\t}

\t\t$file_obj = new SplFileObject( $manifest_file, 'rb' );
\t\t$file_obj->seek( (int) $line_offset );

\t\t$processed     = 0;
\t\t$added_count   = 0;
\t\t$skipped_count = 0;
\t\t$bytes_batch   = 0;

\t\twhile ( ! $file_obj->eof() && $processed < self::FILES_PER_CHUNK && $bytes_batch < self::BYTES_PER_CHUNK ) {
\t\t\t$line = trim( (string) $file_obj->current() );
\t\t\t$file_obj->next();

\t\t\tif ( '' === $line ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t++$processed;
\t\t\t$parts = explode( '|', $line, 2 );
\t\t\tif ( 2 !== count( $parts ) ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\tlist( $abs_file, $rel_entry ) = $parts;

\t\t\t// Validación directa antes de ZipArchive::addFile() para omisión garantizada.
\t\t\tif ( $this->is_path_excluded( $rel_entry, $rules ) ) {
\t\t\t\t++$skipped_count;
\t\t\t\tcontinue;
\t\t\t}

\t\t\tif ( is_file( $abs_file ) && is_readable( $abs_file ) ) {
\t\t\t\t$size = (int) @filesize( $abs_file );
\t\t\t\t$zip->addFile( $abs_file, $rel_entry );
\t\t\t\t$bytes_batch += $size;
\t\t\t\t++$added_count;
\t\t\t}
\t\t}

\t\t$zip->close();

\t\t$next_offset = (int) $line_offset + $processed;
\t\t$done        = ( $file_obj->eof() || $next_offset >= (int) $total_files );

\t\treturn array(
\t\t\t'done'        => $done,
\t\t\t'next_offset' => $next_offset,
\t\t\t'total_files' => (int) $total_files,
\t\t\t'added'       => $added_count,
\t\t\t'skipped'     => $skipped_count,
\t\t\t'bytes'       => $bytes_batch,
\t\t);
\t}
}

if ( ! function_exists( 'directory_exists_config_path' ) ) {
\t/**
\t * Localiza wp-config.php si fue movido un nivel por encima de ABSPATH.
\t *
\t * @param string $abs_root Ruta ABSPATH normalizada.
\t * @return string|null
\t */
\tfunction directory_exists_config_path( $abs_root ) {
\t\t$parent = dirname( rtrim( $abs_root, '/' ) ) . '/wp-config.php';
\t\tif ( file_exists( $parent ) && ! file_exists( dirname( rtrim( $abs_root, '/' ) ) . '/wp-settings.php' ) ) {
\t\t\treturn $parent;
\t\t}
\t\treturn null;
\t}
}
`,
  },
  {
    path: 'includes/class-oscarpx-restore-engine.php',
    language: 'php',
    summary: 'Motor de restauración por lotes: extracción segura con ZipArchive y ejecución de sentencias DROP/INSERT vía $wpdb.',
    content: `<?php
/**
 * Motor de Restauración por lotes AJAX (Extracción ZipArchive + Importación SQL via $wpdb).
 *
 * @package OscarPx_Backup_Restore
 */

if ( ! defined( 'ABSPATH' ) ) {
\texit;
}

class OscarPx_Restore_Engine {

\tconst ENTRIES_PER_CHUNK    = 150;
\tconst STATEMENTS_PER_CHUNK = 80;

\t/**
\t * Inspecciona el archivo .zip antes de iniciar la restauración por lotes.
\t *
\t * @param string $zip_path Ruta física validada del archivo .zip.
\t * @return array|WP_Error
\t */
\tpublic function inspect_archive( $zip_path ) {
\t\tif ( ! class_exists( 'ZipArchive' ) ) {
\t\t\treturn new WP_Error( 'oscarpx_no_zip', __( 'ZipArchive no está habilitado en el servidor.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$zip = new ZipArchive();
\t\tif ( true !== $zip->open( $zip_path ) ) {
\t\t\treturn new WP_Error( 'oscarpx_zip_invalid', __( 'No se pudo abrir el archivo .zip seleccionado.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$num_files = (int) $zip->numFiles;
\t\t$has_sql   = ( false !== $zip->locateName( 'database-backup.sql' ) );
\t\t$zip->close();

\t\tif ( ! $has_sql ) {
\t\t\treturn new WP_Error(
\t\t\t\t'oscarpx_missing_sql',
\t\t\t\t__( 'El archivo ZIP no contiene database-backup.sql generado por OscarPx Backup & Restore.', 'oscarpx-backup-restore' )
\t\t\t);
\t\t}

\t\treturn array(
\t\t\t'total_entries' => $num_files,
\t\t\t'has_sql'       => true,
\t\t);
\t}

\t/**
\t * Extrae un lote de archivos del .zip protegiendo contra Zip Slip y preservando
\t * el directorio wp-content/oscarpx-backups/.
\t *
\t * @param string $zip_path    Ruta del .zip.
\t * @param string $temp_dir    Carpeta temporal para depositar database-backup.sql.
\t * @param int    $entry_index Índice inicial en el archivo ZIP.
\t * @return array|WP_Error
\t */
\tpublic function extract_chunk( $zip_path, $temp_dir, $entry_index ) {
\t\t$zip = new ZipArchive();
\t\tif ( true !== $zip->open( $zip_path ) ) {
\t\t\treturn new WP_Error( 'oscarpx_zip_open', __( 'Error al abrir el respaldo durante la extracción.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$total     = (int) $zip->numFiles;
\t\t$end_index = min( $total, (int) $entry_index + self::ENTRIES_PER_CHUNK );
\t\t$extracted = 0;

\t\tfor ( $i = (int) $entry_index; $i < $end_index; $i++ ) {
\t\t\t$entry_name = str_replace( '\\\\', '/', (string) $zip->getNameIndex( $i ) );
\t\t\t$entry_name = ltrim( $entry_name, '/' );

\t\t\t// Protección Zip Slip contra traversal.
\t\t\tif ( empty( $entry_name ) || false !== strpos( $entry_name, '..' ) ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t// Ignorar entradas de directorio puras.
\t\t\tif ( '/' === substr( $entry_name, -1 ) ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t// Nunca sobrescribir el repositorio activo de backups ni carpetas temporales.
\t\t\tif ( 0 === strpos( $entry_name, 'wp-content/oscarpx-backups/' ) ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t$target_path = ( 'database-backup.sql' === $entry_name )
\t\t\t\t? trailingslashit( $temp_dir ) . 'database-backup.sql'
\t\t\t\t: trailingslashit( ABSPATH ) . $entry_name;

\t\t\t$target_dir = dirname( $target_path );
\t\t\tif ( ! is_dir( $target_dir ) ) {
\t\t\t\twp_mkdir_p( $target_dir );
\t\t\t}

\t\t\t$stream = $zip->getStream( $zip->getNameIndex( $i ) );
\t\t\tif ( $stream ) {
\t\t\t\t$out = @fopen( $target_path, 'wb' );
\t\t\t\tif ( $out ) {
\t\t\t\t\twhile ( ! feof( $stream ) ) {
\t\t\t\t\t\tfwrite( $out, fread( $stream, 65536 ) );
\t\t\t\t\t}
\t\t\t\t\tfclose( $out );
\t\t\t\t\t++$extracted;
\t\t\t\t}
\t\t\t\tfclose( $stream );
\t\t\t}
\t\t}

\t\t$zip->close();

\t\treturn array(
\t\t\t'done'       => ( $end_index >= $total ),
\t\t\t'next_index' => $end_index,
\t\t\t'total'      => $total,
\t\t\t'extracted'  => $extracted,
\t\t);
\t}

\t/**
\t * Lee database-backup.sql por streaming y ejecuta sentencias DROP / CREATE / INSERT
\t * en lotes mediante $wpdb sin cargar el archivo completo en memoria.
\t *
\t * @param string $sql_file    Ruta al archivo .sql extraído.
\t * @param int    $byte_offset Posición de byte actual en el archivo.
\t * @return array|WP_Error
\t */
\tpublic function restore_db_chunk( $sql_file, $byte_offset ) {
\t\tglobal $wpdb;

\t\tif ( ! file_exists( $sql_file ) ) {
\t\t\treturn new WP_Error( 'oscarpx_sql_missing', __( 'No se encontró database-backup.sql para restaurar.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$total_bytes = (int) filesize( $sql_file );
\t\t$handle      = @fopen( $sql_file, 'rb' );
\t\tif ( ! $handle ) {
\t\t\treturn new WP_Error( 'oscarpx_sql_read', __( 'No se pudo leer el volcado SQL.', 'oscarpx-backup-restore' ) );
\t\t}

\t\tfseek( $handle, (int) $byte_offset );
\t\t$wpdb->query( 'SET FOREIGN_KEY_CHECKS = 0;' );

\t\t$executed       = 0;
\t\t$buffer         = '';
\t\t$in_string      = false;
\t\t$escape_next    = false;
\t\t$last_safe_pos  = (int) $byte_offset;

\t\twhile ( ! feof( $handle ) && $executed < self::STATEMENTS_PER_CHUNK ) {
\t\t\t$line = fgets( $handle );
\t\t\tif ( false === $line ) {
\t\t\t\tbreak;
\t\t\t}

\t\t\t$trimmed = ltrim( $line );
\t\t\tif ( ! $in_string && ( '' === $trimmed || 0 === strpos( $trimmed, '--' ) || 0 === strpos( $trimmed, '/*' ) ) ) {
\t\t\t\t$last_safe_pos = ftell( $handle );
\t\t\t\tcontinue;
\t\t\t}

\t\t\t$len = strlen( $line );
\t\t\tfor ( $i = 0; $i < $len; $i++ ) {
\t\t\t\t$ch = $line[ $i ];

\t\t\t\tif ( $escape_next ) {
\t\t\t\t\t$buffer     .= $ch;
\t\t\t\t\t$escape_next = false;
\t\t\t\t\tcontinue;
\t\t\t\t}

\t\t\t\tif ( '\\\\' === $ch && $in_string ) {
\t\t\t\t\t$buffer     .= $ch;
\t\t\t\t\t$escape_next = true;
\t\t\t\t\tcontinue;
\t\t\t\t}

\t\t\t\tif ( "'" === $ch ) {
\t\t\t\t\t$in_string = ! $in_string;
\t\t\t\t\t$buffer   .= $ch;
\t\t\t\t\tcontinue;
\t\t\t\t}

\t\t\t\tif ( ';' === $ch && ! $in_string ) {
\t\t\t\t\t$statement = trim( $buffer );
\t\t\t\t\t$buffer    = '';

\t\t\t\t\tif ( '' !== $statement ) {
\t\t\t\t\t\t$result = $wpdb->query( $statement );
\t\t\t\t\t\tif ( false === $result && ! empty( $wpdb->last_error ) ) {
\t\t\t\t\t\t\tfclose( $handle );
\t\t\t\t\t\t\treturn new WP_Error( 'oscarpx_sql_exec', $wpdb->last_error );
\t\t\t\t\t\t}
\t\t\t\t\t\t++$executed;
\t\t\t\t\t}
\t\t\t\t} else {
\t\t\t\t\t$buffer .= $ch;
\t\t\t\t}
\t\t\t}

\t\t\tif ( ! $in_string && '' === trim( $buffer ) ) {
\t\t\t\t$last_safe_pos = ftell( $handle );
\t\t\t}

\t\t\tif ( $executed >= self::STATEMENTS_PER_CHUNK && '' === trim( $buffer ) ) {
\t\t\t\tbreak;
\t\t\t}
\t\t}

\t\t$eof = feof( $handle );
\t\tfclose( $handle );

\t\tif ( $eof && '' !== trim( $buffer ) ) {
\t\t\t$wpdb->query( trim( $buffer ) );
\t\t\t++$executed;
\t\t}

\t\t$wpdb->query( 'SET FOREIGN_KEY_CHECKS = 1;' );

\t\treturn array(
\t\t\t'done'        => $eof,
\t\t\t'next_offset' => $eof ? $total_bytes : $last_safe_pos,
\t\t\t'total_bytes' => $total_bytes,
\t\t\t'executed'    => $executed,
\t\t);
\t}
}
`,
  },
  {
    path: 'includes/class-oscarpx-admin.php',
    language: 'php',
    summary: 'Controlador de interfaz WP-Admin (admin_menu, pestañas nativas, textarea Carpetas a Excluir) y endpoints AJAX.',
    content: `<?php
/**
 * Interfaz de Administración nativa de WordPress y endpoints AJAX.
 *
 * @package OscarPx_Backup_Restore
 */

if ( ! defined( 'ABSPATH' ) ) {
\texit;
}

class OscarPx_Admin {

\tconst MENU_SLUG = 'oscarpx-backup-restore';

\t/**
\t * Registra hooks de menú, assets y acciones AJAX protegidas.
\t */
\tpublic function init() {
\t\tadd_action( 'admin_menu', array( $this, 'register_menu_page' ) );
\t\tadd_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );

\t\t// Endpoints AJAX para Backup por lotes.
\t\tadd_action( 'wp_ajax_oscarpx_start_backup', array( $this, 'ajax_start_backup' ) );
\t\tadd_action( 'wp_ajax_oscarpx_process_db_chunk', array( $this, 'ajax_process_db_chunk' ) );
\t\tadd_action( 'wp_ajax_oscarpx_scan_files', array( $this, 'ajax_scan_files' ) );
\t\tadd_action( 'wp_ajax_oscarpx_process_zip_chunk', array( $this, 'ajax_process_zip_chunk' ) );

\t\t// Endpoints AJAX para Restauración y gestión de archivos.
\t\tadd_action( 'wp_ajax_oscarpx_start_restore', array( $this, 'ajax_start_restore' ) );
\t\tadd_action( 'wp_ajax_oscarpx_process_extract_chunk', array( $this, 'ajax_process_extract_chunk' ) );
\t\tadd_action( 'wp_ajax_oscarpx_process_sql_chunk', array( $this, 'ajax_process_sql_chunk' ) );
\t\tadd_action( 'wp_ajax_oscarpx_delete_backup', array( $this, 'ajax_delete_backup' ) );
\t}

\t/**
\t * Añade la página de opciones en el menú de administración de WordPress.
\t */
\tpublic function register_menu_page() {
\t\tadd_menu_page(
\t\t\t__( 'OscarPx Backup & Restore', 'oscarpx-backup-restore' ),
\t\t\t__( 'OscarPx Backup', 'oscarpx-backup-restore' ),
\t\t\t'manage_options',
\t\t\tself::MENU_SLUG,
\t\t\tarray( $this, 'render_admin_page' ),
\t\t\t'dashicons-database-export',
\t\t\t80
\t\t);
\t}

\t/**
\t * Carga scripts y estilos solo dentro de la página del plugin.
\t *
\t * @param string $hook_suffix Sufijo del screen actual.
\t */
\tpublic function enqueue_assets( $hook_suffix ) {
\t\tif ( 'toplevel_page_' . self::MENU_SLUG !== $hook_suffix ) {
\t\t\treturn;
\t\t}

\t\twp_enqueue_style(
\t\t\t'oscarpx-admin-css',
\t\t\tOSCARPX_BR_PLUGIN_URL . 'assets/css/oscarpx-admin.css',
\t\t\tarray(),
\t\t\tOSCARPX_BR_VERSION
\t\t);

\t\twp_enqueue_script(
\t\t\t'oscarpx-admin-js',
\t\t\tOSCARPX_BR_PLUGIN_URL . 'assets/js/oscarpx-admin.js',
\t\t\tarray(),
\t\t\tOSCARPX_BR_VERSION,
\t\t\ttrue
\t\t);

\t\twp_localize_script(
\t\t\t'oscarpx-admin-js',
\t\t\t'oscarpxBackupConfig',
\t\t\tarray(
\t\t\t\t'ajaxUrl' => admin_url( 'admin-ajax.php' ),
\t\t\t\t'nonce'   => wp_create_nonce( 'oscarpx_backup_nonce' ),
\t\t\t)
\t\t);
\t}

\t/**
\t * Renderiza la interfaz con estilos nativos de WordPress y pestañas "Crear Backup" / "Restaurar Backup".
\t */
\tpublic function render_admin_page() {
\t\tif ( ! current_user_can( 'manage_options' ) ) {
\t\t\twp_die( esc_html__( 'No tienes permisos suficientes.', 'oscarpx-backup-restore' ) );
\t\t}

\t\tOscarPx_Security::ensure_backup_directory();

\t\t$active_tab         = isset( $_GET['tab'] ) && 'restore' === $_GET['tab'] ? 'restore' : 'create';
\t\t$default_exclusions = implode( "\\n", OscarPx_File_Engine::get_default_exclusions() );
\t\t$backups            = $this->list_available_backups();
\t\t?>
\t\t<div class="wrap oscarpx-wrap">
\t\t\t<h1><?php esc_html_e( 'OscarPx Backup & Restore', 'oscarpx-backup-restore' ); ?></h1>
\t\t\t<p class="description">
\t\t\t\t<?php esc_html_e( 'Copias de seguridad completas (Base de Datos + Archivos) y restauración directa por lotes AJAX. Almacenamiento seguro en wp-content/oscarpx-backups/.', 'oscarpx-backup-restore' ); ?>
\t\t\t</p>

\t\t\t<nav class="nav-tab-wrapper" aria-label="<?php esc_attr_e( 'Pestañas de OscarPx Backup', 'oscarpx-backup-restore' ); ?>">
\t\t\t\t<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::MENU_SLUG . '&tab=create' ) ); ?>"
\t\t\t\t   class="nav-tab <?php echo 'create' === $active_tab ? 'nav-tab-active' : ''; ?>">
\t\t\t\t\t<?php esc_html_e( 'Crear Backup', 'oscarpx-backup-restore' ); ?>
\t\t\t\t</a>
\t\t\t\t<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::MENU_SLUG . '&tab=restore' ) ); ?>"
\t\t\t\t   class="nav-tab <?php echo 'restore' === $active_tab ? 'nav-tab-active' : ''; ?>">
\t\t\t\t\t<?php esc_html_e( 'Restaurar Backup', 'oscarpx-backup-restore' ); ?>
\t\t\t\t</a>
\t\t\t</nav>

\t\t\t<?php if ( 'create' === $active_tab ) : ?>
\t\t\t\t<div class="card oscarpx-card">
\t\t\t\t\t<h2><?php esc_html_e( 'Generar Nueva Copia de Seguridad Completa', 'oscarpx-backup-restore' ); ?></h2>
\t\t\t\t\t<table class="form-table" role="presentation">
\t\t\t\t\t\t<tbody>
\t\t\t\t\t\t\t<tr>
\t\t\t\t\t\t\t\t<th scope="row">
\t\t\t\t\t\t\t\t\t<label for="oscarpx-exclusions"><?php esc_html_e( 'Carpetas a Excluir', 'oscarpx-backup-restore' ); ?></label>
\t\t\t\t\t\t\t\t</th>
\t\t\t\t\t\t\t\t<td>
\t\t\t\t\t\t\t\t\t<textarea id="oscarpx-exclusions" rows="9" cols="60" class="large-text code"><?php echo esc_textarea( $default_exclusions ); ?></textarea>
\t\t\t\t\t\t\t\t\t<p class="description">
\t\t\t\t\t\t\t\t\t\t<?php esc_html_e( 'Rutas relativas desde la raíz de WordPress separadas por saltos de línea. Se omitirán de forma recursiva antes de ejecutar ZipArchive::addFile().', 'oscarpx-backup-restore' ); ?>
\t\t\t\t\t\t\t\t\t</p>
\t\t\t\t\t\t\t\t</td>
\t\t\t\t\t\t\t</tr>
\t\t\t\t\t\t</tbody>
\t\t\t\t\t</table>

\t\t\t\t\t<p class="submit">
\t\t\t\t\t\t<button type="button" id="oscarpx-start-backup-btn" class="button button-primary button-hero">
\t\t\t\t\t\t\t<?php esc_html_e( 'Iniciar Backup Completo', 'oscarpx-backup-restore' ); ?>
\t\t\t\t\t\t</button>
\t\t\t\t\t</p>
\t\t\t\t</div>
\t\t\t<?php else : ?>
\t\t\t\t<div class="card oscarpx-card">
\t\t\t\t\t<h2><?php esc_html_e( 'Restaurar desde Archivo .zip Existente', 'oscarpx-backup-restore' ); ?></h2>
\t\t\t\t\t<?php if ( empty( $backups ) ) : ?>
\t\t\t\t\t\t<div class="notice notice-info inline">
\t\t\t\t\t\t\t<p><?php esc_html_e( 'No se encontraron archivos .zip en wp-content/oscarpx-backups/. Crea un backup primero.', 'oscarpx-backup-restore' ); ?></p>
\t\t\t\t\t\t</div>
\t\t\t\t\t<?php else : ?>
\t\t\t\t\t\t<table class="wp-list-table widefat fixed striped">
\t\t\t\t\t\t\t<thead>
\t\t\t\t\t\t\t\t<tr>
\t\t\t\t\t\t\t\t\t<th scope="col" class="check-column"></th>
\t\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Archivo de Respaldo (.zip)', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Tamaño', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Fecha de Creación', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Acciones', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t\t</tr>
\t\t\t\t\t\t\t</thead>
\t\t\t\t\t\t\t<tbody>
\t\t\t\t\t\t\t\t<?php foreach ( $backups as $idx => $item ) : ?>
\t\t\t\t\t\t\t\t\t<tr>
\t\t\t\t\t\t\t\t\t\t<th scope="row" class="check-column">
\t\t\t\t\t\t\t\t\t\t\t<input type="radio" name="oscarpx_selected_backup" value="<?php echo esc_attr( $item['name'] ); ?>" <?php checked( 0, $idx ); ?> />
\t\t\t\t\t\t\t\t\t\t</th>
\t\t\t\t\t\t\t\t\t\t<td><code><?php echo esc_html( $item['name'] ); ?></code></td>
\t\t\t\t\t\t\t\t\t\t<td><?php echo esc_html( size_format( $item['size'], 2 ) ); ?></td>
\t\t\t\t\t\t\t\t\t\t<td><?php echo esc_html( wp_date( 'Y-m-d H:i:s', $item['mtime'] ) ); ?></td>
\t\t\t\t\t\t\t\t\t\t<td>
\t\t\t\t\t\t\t\t\t\t\t<button type="button" class="button button-link-delete oscarpx-delete-btn" data-file="<?php echo esc_attr( $item['name'] ); ?>">
\t\t\t\t\t\t\t\t\t\t\t\t<?php esc_html_e( 'Eliminar', 'oscarpx-backup-restore' ); ?>
\t\t\t\t\t\t\t\t\t\t\t</button>
\t\t\t\t\t\t\t\t\t\t</td>
\t\t\t\t\t\t\t\t\t</tr>
\t\t\t\t\t\t\t\t<?php endforeach; ?>
\t\t\t\t\t\t\t</tbody>
\t\t\t\t\t\t</table>
\t\t\t\t\t\t<p class="submit">
\t\t\t\t\t\t\t<button type="button" id="oscarpx-start-restore-btn" class="button button-primary button-hero">
\t\t\t\t\t\t\t\t<?php esc_html_e( 'Restaurar Backup Seleccionado', 'oscarpx-backup-restore' ); ?>
\t\t\t\t\t\t\t</button>
\t\t\t\t\t\t</p>
\t\t\t\t\t<?php endif; ?>
\t\t\t\t</div>
\t\t\t<?php endif; ?>

\t\t\t<div id="oscarpx-progress-panel" class="card oscarpx-card" style="display:none;">
\t\t\t\t<h3 id="oscarpx-progress-title"><?php esc_html_e( 'Progreso de Operación', 'oscarpx-backup-restore' ); ?></h3>
\t\t\t\t<div class="oscarpx-progress-track">
\t\t\t\t\t<div id="oscarpx-progress-bar" class="oscarpx-progress-fill" style="width:0%;">0%</div>
\t\t\t\t</div>
\t\t\t\t<pre id="oscarpx-progress-log" class="oscarpx-log"></pre>
\t\t\t</div>
\t\t</div>
\t\t<?php
\t}

\t/**
\t * Lista los archivos .zip válidos dentro de wp-content/oscarpx-backups/.
\t *
\t * @return array
\t */
\tprivate function list_available_backups() {
\t\t$files = @glob( OSCARPX_BR_BACKUP_DIR . '*.zip' );
\t\t$list  = array();

\t\tif ( is_array( $files ) ) {
\t\t\tforeach ( $files as $filepath ) {
\t\t\t\t$name = basename( $filepath );
\t\t\t\tif ( ! is_wp_error( OscarPx_Security::sanitize_zip_filename( $name ) ) ) {
\t\t\t\t\t$list[] = array(
\t\t\t\t\t\t'name'  => $name,
\t\t\t\t\t\t'size'  => (int) @filesize( $filepath ),
\t\t\t\t\t\t'mtime' => (int) @filemtime( $filepath ),
\t\t\t\t\t);
\t\t\t\t}
\t\t\t}
\t\t}

\t\tusort(
\t\t\t$list,
\t\t\tfunction ( $a, $b ) {
\t\t\t\treturn $b['mtime'] - $a['mtime'];
\t\t\t}
\t\t);

\t\treturn $list;
\t}

\t/* -------------------------------------------------------------------------
\t * ENDPOINTS AJAX - BACKUP
\t * ---------------------------------------------------------------------- */

\tpublic function ajax_start_backup() {
\t\tOscarPx_Security::verify_ajax_request();
\t\t$dir = OscarPx_Security::ensure_backup_directory();
\t\tif ( is_wp_error( $dir ) ) {
\t\t\twp_send_json_error( array( 'message' => $dir->get_error_message() ) );
\t\t}

\t\t$job_id   = gmdate( 'Ymd-His' ) . '-' . wp_generate_password( 6, false, false );
\t\t$temp_dir = OscarPx_Security::get_job_temp_dir( $job_id );
\t\tif ( is_wp_error( $temp_dir ) ) {
\t\t\twp_send_json_error( array( 'message' => $temp_dir->get_error_message() ) );
\t\t}

\t\t$db_engine = new OscarPx_DB_Engine();
\t\t$tables    = $db_engine->get_all_tables();
\t\t$sql_file  = $temp_dir . 'database-backup.sql';
\t\t$init      = $db_engine->init_sql_dump( $sql_file );

\t\tif ( is_wp_error( $init ) ) {
\t\t\twp_send_json_error( array( 'message' => $init->get_error_message() ) );
\t\t}

\t\t$zip_name = OscarPx_Security::sanitize_zip_filename( 'oscarpx-backup-' . $job_id . '.zip' );
\t\tif ( is_wp_error( $zip_name ) ) {
\t\t\twp_send_json_error( array( 'message' => $zip_name->get_error_message() ) );
\t\t}

\t\t$raw_exclusions = isset( $_POST['exclusions'] ) ? wp_unslash( $_POST['exclusions'] ) : '';
\t\tset_transient(
\t\t\t'oscarpx_job_' . $job_id,
\t\t\tarray(
\t\t\t\t'tables'     => $tables,
\t\t\t\t'zip_name'   => $zip_name,
\t\t\t\t'exclusions' => $raw_exclusions,
\t\t\t),
\t\t\tHOUR_IN_SECONDS
\t\t);

\t\twp_send_json_success(
\t\t\tarray(
\t\t\t\t'job_id'       => $job_id,
\t\t\t\t'zip_name'     => $zip_name,
\t\t\t\t'total_tables' => count( $tables ),
\t\t\t)
\t\t);
\t}

\tpublic function ajax_process_db_chunk() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id      = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$table_index = isset( $_POST['table_index'] ) ? absint( $_POST['table_index'] ) : 0;
\t\t$row_offset  = isset( $_POST['row_offset'] ) ? absint( $_POST['row_offset'] ) : 0;
\t\t$job         = get_transient( 'oscarpx_job_' . $job_id );
\t\t$temp_dir    = OscarPx_Security::get_job_temp_dir( $job_id );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\twp_send_json_error( array( 'message' => __( 'Sesión de backup expirada o inválida.', 'oscarpx-backup-restore' ) ) );
\t\t}

\t\t$db_engine = new OscarPx_DB_Engine();
\t\t$res       = $db_engine->export_chunk( $temp_dir . 'database-backup.sql', $job['tables'], $table_index, $row_offset );

\t\tif ( is_wp_error( $res ) ) {
\t\t\twp_send_json_error( array( 'message' => $res->get_error_message() ) );
\t\t}

\t\twp_send_json_success( $res );
\t}

\tpublic function ajax_scan_files() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id   = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$job      = get_transient( 'oscarpx_job_' . $job_id );
\t\t$temp_dir = OscarPx_Security::get_job_temp_dir( $job_id );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\twp_send_json_error( array( 'message' => __( 'Sesión de backup inválida.', 'oscarpx-backup-restore' ) ) );
\t\t}

\t\t$file_engine = new OscarPx_File_Engine();
\t\t$rules       = $file_engine->parse_exclusion_rules( $job['exclusions'] );
\t\t$scan        = $file_engine->build_manifest( $temp_dir . 'manifest.txt', $rules );

\t\tif ( is_wp_error( $scan ) ) {
\t\t\twp_send_json_error( array( 'message' => $scan->get_error_message() ) );
\t\t}

\t\t$job['total_files'] = $scan['total_files'];
\t\tset_transient( 'oscarpx_job_' . $job_id, $job, HOUR_IN_SECONDS );

\t\twp_send_json_success( $scan );
\t}

\tpublic function ajax_process_zip_chunk() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id      = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$line_offset = isset( $_POST['line_offset'] ) ? absint( $_POST['line_offset'] ) : 0;
\t\t$job         = get_transient( 'oscarpx_job_' . $job_id );
\t\t$temp_dir    = OscarPx_Security::get_job_temp_dir( $job_id );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\twp_send_json_error( array( 'message' => __( 'Sesión de empaquetado inválida.', 'oscarpx-backup-restore' ) ) );
\t\t}

\t\t$file_engine = new OscarPx_File_Engine();
\t\t$rules       = $file_engine->parse_exclusion_rules( $job['exclusions'] );
\t\t$zip_path    = OSCARPX_BR_BACKUP_DIR . $job['zip_name'];

\t\t$res = $file_engine->pack_chunk(
\t\t\t$zip_path,
\t\t\t$temp_dir . 'manifest.txt',
\t\t\t$temp_dir . 'database-backup.sql',
\t\t\t$line_offset,
\t\t\tisset( $job['total_files'] ) ? (int) $job['total_files'] : 0,
\t\t\t$rules
\t\t);

\t\tif ( is_wp_error( $res ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\twp_send_json_error( array( 'message' => $res->get_error_message() ) );
\t\t}

\t\tif ( ! empty( $res['done'] ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\tdelete_transient( 'oscarpx_job_' . $job_id );
\t\t\t$res['zip_name'] = $job['zip_name'];
\t\t\t$res['zip_size'] = size_format( (int) @filesize( $zip_path ), 2 );
\t\t}

\t\twp_send_json_success( $res );
\t}

\t/* -------------------------------------------------------------------------
\t * ENDPOINTS AJAX - RESTAURACIÓN
\t * ---------------------------------------------------------------------- */

\tpublic function ajax_start_restore() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$raw_file = isset( $_POST['filename'] ) ? $_POST['filename'] : '';
\t\t$zip_path = OscarPx_Security::resolve_existing_backup_path( $raw_file );
\t\tif ( is_wp_error( $zip_path ) ) {
\t\t\twp_send_json_error( array( 'message' => $zip_path->get_error_message() ) );
\t\t}

\t\t$restore = new OscarPx_Restore_Engine();
\t\t$info    = $restore->inspect_archive( $zip_path );
\t\tif ( is_wp_error( $info ) ) {
\t\t\twp_send_json_error( array( 'message' => $info->get_error_message() ) );
\t\t}

\t\t$job_id = 'restore-' . gmdate( 'YmdHis' ) . '-' . wp_generate_password( 6, false, false );
\t\tOscarPx_Security::get_job_temp_dir( $job_id );

\t\tset_transient(
\t\t\t'oscarpx_restore_' . $job_id,
\t\t\tarray(
\t\t\t\t'zip_name' => basename( $zip_path ),
\t\t\t),
\t\t\tHOUR_IN_SECONDS
\t\t);

\t\twp_send_json_success(
\t\t\tarray(
\t\t\t\t'job_id'        => $job_id,
\t\t\t\t'total_entries' => $info['total_entries'],
\t\t\t)
\t\t);
\t}

\tpublic function ajax_process_extract_chunk() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id      = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$entry_index = isset( $_POST['entry_index'] ) ? absint( $_POST['entry_index'] ) : 0;
\t\t$job         = get_transient( 'oscarpx_restore_' . $job_id );
\t\t$temp_dir    = OscarPx_Security::get_job_temp_dir( $job_id );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\twp_send_json_error( array( 'message' => __( 'Sesión de restauración inválida.', 'oscarpx-backup-restore' ) ) );
\t\t}

\t\t$zip_path = OscarPx_Security::resolve_existing_backup_path( $job['zip_name'] );
\t\tif ( is_wp_error( $zip_path ) ) {
\t\t\twp_send_json_error( array( 'message' => $zip_path->get_error_message() ) );
\t\t}

\t\t$restore = new OscarPx_Restore_Engine();
\t\t$res     = $restore->extract_chunk( $zip_path, $temp_dir, $entry_index );

\t\tif ( is_wp_error( $res ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\twp_send_json_error( array( 'message' => $res->get_error_message() ) );
\t\t}

\t\twp_send_json_success( $res );
\t}

\tpublic function ajax_process_sql_chunk() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id      = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$byte_offset = isset( $_POST['byte_offset'] ) ? absint( $_POST['byte_offset'] ) : 0;
\t\t$job         = get_transient( 'oscarpx_restore_' . $job_id );
\t\t$temp_dir    = OscarPx_Security::get_job_temp_dir( $job_id );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\twp_send_json_error( array( 'message' => __( 'Sesión SQL inválida.', 'oscarpx-backup-restore' ) ) );
\t\t}

\t\t$restore = new OscarPx_Restore_Engine();
\t\t$res     = $restore->restore_db_chunk( $temp_dir . 'database-backup.sql', $byte_offset );

\t\tif ( is_wp_error( $res ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\twp_send_json_error( array( 'message' => $res->get_error_message() ) );
\t\t}

\t\tif ( ! empty( $res['done'] ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\tdelete_transient( 'oscarpx_restore_' . $job_id );
\t\t}

\t\twp_send_json_success( $res );
\t}

\tpublic function ajax_delete_backup() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$raw_file = isset( $_POST['filename'] ) ? $_POST['filename'] : '';
\t\t$zip_path = OscarPx_Security::resolve_existing_backup_path( $raw_file );

\t\tif ( is_wp_error( $zip_path ) ) {
\t\t\twp_send_json_error( array( 'message' => $zip_path->get_error_message() ) );
\t\t}

\t\tif ( ! @unlink( $zip_path ) ) {
\t\t\twp_send_json_error( array( 'message' => __( 'No se pudo eliminar el archivo de respaldo.', 'oscarpx-backup-restore' ) ) );
\t\t}

\t\twp_send_json_success( array( 'deleted' => basename( $zip_path ) ) );
\t}
}
`,
  },
  {
    path: 'assets/js/oscarpx-admin.js',
    language: 'javascript',
    summary: 'Orquestador AJAX por lotes en el cliente con barra de progreso y registro en tiempo real.',
    content: `(function () {
  'use strict';

  var cfg = window.oscarpxBackupConfig || {};
  var panel = document.getElementById('oscarpx-progress-panel');
  var titleEl = document.getElementById('oscarpx-progress-title');
  var barEl = document.getElementById('oscarpx-progress-bar');
  var logEl = document.getElementById('oscarpx-progress-log');

  function showProgress(title) {
    if (!panel) return;
    panel.style.display = 'block';
    titleEl.textContent = title;
    logEl.textContent = '';
    setProgress(0);
  }

  function setProgress(pct) {
    var safePct = Math.max(0, Math.min(100, Math.round(pct)));
    barEl.style.width = safePct + '%';
    barEl.textContent = safePct + '%';
  }

  function appendLog(msg) {
    var now = new Date().toTimeString().slice(0, 8);
    logEl.textContent += '[' + now + '] ' + msg + '\\n';
    logEl.scrollTop = logEl.scrollHeight;
  }

  function postAjax(action, params) {
    var body = new FormData();
    body.append('action', action);
    body.append('nonce', cfg.nonce || '');
    Object.keys(params || {}).forEach(function (key) {
      body.append(key, params[key]);
    });

    return fetch(cfg.ajaxUrl, {
      method: 'POST',
      credentials: 'same-origin',
      body: body,
    })
      .then(function (res) {
        return res.json();
      })
      .then(function (json) {
        if (!json || !json.success) {
          var errMsg = (json && json.data && json.data.message) ? json.data.message : 'Error inesperado en AJAX.';
          throw new Error(errMsg);
        }
        return json.data;
      });
  }

  /* ---- FLUJO DE CREACIÓN DE BACKUP POR LOTES ---- */
  var startBackupBtn = document.getElementById('oscarpx-start-backup-btn');
  if (startBackupBtn) {
    startBackupBtn.addEventListener('click', function () {
      var exclusionsEl = document.getElementById('oscarpx-exclusions');
      var exclusions = exclusionsEl ? exclusionsEl.value : '';

      startBackupBtn.disabled = true;
      showProgress('Creando Copia de Seguridad Completa...');
      appendLog('Inicializando directorio seguro wp-content/oscarpx-backups/...');

      postAjax('oscarpx_start_backup', { exclusions: exclusions })
        .then(function (startData) {
          appendLog('Base de datos detectada: ' + startData.total_tables + ' tablas.');
          return runDbChunk(startData.job_id, 0, 0, startData.total_tables);
        })
        .then(function (jobId) {
          appendLog('Escaneando wp-content y wp-config.php aplicando exclusiones...');
          setProgress(35);
          return postAjax('oscarpx_scan_files', { job_id: jobId }).then(function (scan) {
            appendLog('Manifiesto listo: ' + scan.total_files + ' archivos a empaquetar (' + scan.skipped + ' nodos omitidos).');
            return runZipChunk(jobId, 0, scan.total_files);
          });
        })
        .then(function (finalData) {
          setProgress(100);
          appendLog('Backup completado: ' + finalData.zip_name + ' (' + finalData.zip_size + ').');
          startBackupBtn.disabled = false;
        })
        .catch(function (err) {
          appendLog('ERROR: ' + err.message);
          startBackupBtn.disabled = false;
        });
    });
  }

  function runDbChunk(jobId, tableIndex, rowOffset, totalTables) {
    return postAjax('oscarpx_process_db_chunk', {
      job_id: jobId,
      table_index: tableIndex,
      row_offset: rowOffset,
    }).then(function (res) {
      appendLog(res.message);
      var pct = totalTables > 0 ? (res.table_index / totalTables) * 30 : 30;
      setProgress(pct);
      if (res.done) {
        return jobId;
      }
      return runDbChunk(jobId, res.table_index, res.row_offset, totalTables);
    });
  }

  function runZipChunk(jobId, lineOffset, totalFiles) {
    return postAjax('oscarpx_process_zip_chunk', {
      job_id: jobId,
      line_offset: lineOffset,
    }).then(function (res) {
      appendLog('Lote ZIP: +' + res.added + ' archivos empaquetados, ' + res.skipped + ' omitidos.');
      var pct = totalFiles > 0 ? 35 + (res.next_offset / totalFiles) * 65 : 100;
      setProgress(pct);
      if (res.done) {
        return res;
      }
      return runZipChunk(jobId, res.next_offset, totalFiles);
    });
  }

  /* ---- FLUJO DE RESTAURACIÓN POR LOTES ---- */
  var startRestoreBtn = document.getElementById('oscarpx-start-restore-btn');
  if (startRestoreBtn) {
    startRestoreBtn.addEventListener('click', function () {
      var selected = document.querySelector('input[name="oscarpx_selected_backup"]:checked');
      if (!selected) return;

      var filename = selected.value;
      startRestoreBtn.disabled = true;
      showProgress('Restaurando Backup: ' + filename);
      appendLog('Verificando integridad de ' + filename + '...');

      postAjax('oscarpx_start_restore', { filename: filename })
        .then(function (data) {
          appendLog('Archivo verificado (' + data.total_entries + ' entradas). Iniciando extracción...');
          return runExtractChunk(data.job_id, 0, data.total_entries);
        })
        .then(function (jobId) {
          appendLog('Extracción de archivos completada. Ejecutando volcado SQL via $wpdb...');
          setProgress(55);
          return runSqlChunk(jobId, 0);
        })
        .then(function () {
          setProgress(100);
          appendLog('Restauración completada con éxito. Base de datos y archivos restaurados.');
          startRestoreBtn.disabled = false;
        })
        .catch(function (err) {
          appendLog('ERROR: ' + err.message);
          startRestoreBtn.disabled = false;
        });
    });
  }

  function runExtractChunk(jobId, entryIndex, totalEntries) {
    return postAjax('oscarpx_process_extract_chunk', {
      job_id: jobId,
      entry_index: entryIndex,
    }).then(function (res) {
      appendLog('Extraídos ' + res.extracted + ' archivos (' + res.next_index + '/' + totalEntries + ').');
      var pct = totalEntries > 0 ? (res.next_index / totalEntries) * 50 : 50;
      setProgress(pct);
      if (res.done) return jobId;
      return runExtractChunk(jobId, res.next_index, totalEntries);
    });
  }

  function runSqlChunk(jobId, byteOffset) {
    return postAjax('oscarpx_process_sql_chunk', {
      job_id: jobId,
      byte_offset: byteOffset,
    }).then(function (res) {
      appendLog('SQL $wpdb: ' + res.executed + ' sentencias ejecutadas.');
      var pct = res.total_bytes > 0 ? 55 + (res.next_offset / res.total_bytes) * 45 : 100;
      setProgress(pct);
      if (res.done) return res;
      return runSqlChunk(jobId, res.next_offset);
    });
  }

  document.querySelectorAll('.oscarpx-delete-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var file = btn.getAttribute('data-file');
      postAjax('oscarpx_delete_backup', { filename: file }).then(function () {
        window.location.reload();
      });
    });
  });
})();
`,
  },
  {
    path: 'assets/css/oscarpx-admin.css',
    language: 'css',
    summary: 'Estilos ligeros integrados con la estética nativa de WordPress Admin.',
    content: `.oscarpx-wrap .oscarpx-card {
  max-width: 960px;
  margin-top: 16px;
  padding: 20px;
}

.oscarpx-progress-track {
  width: 100%;
  height: 24px;
  background: #dcdcde;
  border-radius: 3px;
  overflow: hidden;
  margin: 12px 0;
}

.oscarpx-progress-fill {
  height: 100%;
  background: #2271b1;
  color: #ffffff;
  font-size: 12px;
  font-weight: 600;
  line-height: 24px;
  text-align: center;
  transition: width 0.2s ease;
}

.oscarpx-log {
  background: #1d2327;
  color: #f0f0f1;
  padding: 12px 14px;
  border-radius: 3px;
  max-height: 240px;
  overflow-y: auto;
  font-size: 12px;
  line-height: 1.5;
  margin: 0;
}
`,
  },
];
