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
\t * Prepara la petición AJAX evitando timeouts y capturando cualquier salida accidental.
\t */
\tpublic static function begin_json_response() {
\t\tif ( function_exists( 'set_time_limit' ) ) {
\t\t\t@set_time_limit( 0 );
\t\t}
\t\t@ignore_user_abort( true );
\t\tif ( ! ob_get_level() ) {
\t\t\t@ob_start();
\t\t}
\t}

\t/**
\t * Limpia buffers previos y envía respuesta JSON de éxito garantizada.
\t *
\t * @param mixed $data Datos de respuesta.
\t */
\tpublic static function send_json_success( $data = null ) {
\t\twhile ( ob_get_level() > 0 ) {
\t\t\t@ob_end_clean();
\t\t}
\t\twp_send_json_success( $data );
\t}

\t/**
\t * Limpia buffers previos y envía respuesta JSON de error garantizada.
\t *
\t * @param string $message Mensaje legible.
\t * @param int    $status  Código HTTP.
\t */
\tpublic static function send_json_error( $message, $status = 200 ) {
\t\twhile ( ob_get_level() > 0 ) {
\t\t\t@ob_end_clean();
\t\t}
\t\twp_send_json_error( array( 'message' => (string) $message ), $status );
\t}

\t/**
\t * Valida nonce AJAX y permisos de administrador (manage_options).
\t * Finaliza la ejecución con código HTTP 403 si falla la verificación.
\t */
\tpublic static function verify_ajax_request() {
\t\tself::begin_json_response();

\t\tif ( ! check_ajax_referer( 'oscarpx_backup_nonce', 'nonce', false ) ) {
\t\t\tself::send_json_error(
\t\t\t\t__( 'Token de seguridad (nonce) inválido o expirado. Recarga la página e inténtalo de nuevo.', 'oscarpx-backup-restore' ),
\t\t\t\t403
\t\t\t);
\t\t}

\t\tif ( ! current_user_can( 'manage_options' ) ) {
\t\t\tself::send_json_error(
\t\t\t\t__( 'Acceso denegado: se requieren permisos manage_options.', 'oscarpx-backup-restore' ),
\t\t\t\t403
\t\t\t);
\t\t}
\t}

\t/**
\t * Guarda el estado de la tarea en disco (inmune a restauraciones de wp_options).
\t *
\t * @param string $temp_dir Carpeta temporal del job.
\t * @param array  $state    Datos del job.
\t * @return bool
\t */
\tpublic static function write_job_state( $temp_dir, array $state ) {
\t\treturn false !== @file_put_contents( trailingslashit( $temp_dir ) . 'job.json', wp_json_encode( $state ) );
\t}

\t/**
\t * Lee el estado de la tarea desde disco.
\t *
\t * @param string $temp_dir Carpeta temporal del job.
\t * @return array|null
\t */
\tpublic static function read_job_state( $temp_dir ) {
\t\t$file = trailingslashit( $temp_dir ) . 'job.json';
\t\tif ( ! file_exists( $file ) ) {
\t\t\treturn null;
\t\t}
\t\t$decoded = json_decode( (string) @file_get_contents( $file ), true );
\t\treturn is_array( $decoded ) ? $decoded : null;
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
\t * Construye el nombre único, dinámico y cronológico del archivo ZIP:
\t * {nombre-sitio-sanitizado}-{tipo-backup}_{Y-m-d_H-i-s}.zip
\t *
\t * @param string $backup_type Tipo seleccionado en UI ('completo' o 'solo-bd').
\t * @return string|WP_Error
\t */
\tpublic static function build_backup_filename( $backup_type = 'completo' ) {
\t\t$site_name = (string) get_bloginfo( 'name' );
\t\t$site_slug = sanitize_title( $site_name );
\t\tif ( '' === $site_slug ) {
\t\t\t$site_slug = 'sitio-wp';
\t\t}

\t\t$allowed_types = array( 'completo', 'solo-bd' );
\t\t$clean_type    = in_array( $backup_type, $allowed_types, true ) ? $backup_type : 'completo';
\t\t$timestamp     = date( 'Y-m-d_H-i-s' );
\t\t$raw_filename  = sprintf( '%s-%s_%s.zip', $site_slug, $clean_type, $timestamp );

\t\treturn self::sanitize_zip_filename( $raw_filename );
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

\t/**
\t * Devuelve la ruta absoluta del archivo .maintenance en la raíz de WordPress.
\t *
\t * @return string
\t */
\tpublic static function get_maintenance_file_path() {
\t\treturn trailingslashit( ABSPATH ) . '.maintenance';
\t}

\t/**
\t * Activa el archivo .maintenance en la raíz para que wp_maintenance() detenga tráfico y cronjobs,
\t * permitiendo únicamente las peticiones AJAX autenticadas de este job mediante $maint_key.
\t *
\t * @param string $maint_key Clave aleatoria de un solo uso para la restauración en curso.
\t * @return bool|WP_Error
\t */
\tpublic static function enable_maintenance_mode( $maint_key ) {
\t\t$maint_file = self::get_maintenance_file_path();
\t\t$clean_key  = preg_replace( '/[^a-zA-Z0-9]/', '', (string) $maint_key );

\t\tif ( empty( $clean_key ) ) {
\t\t\treturn new WP_Error( 'oscarpx_maint_key', __( 'Clave de mantenimiento inválida.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t// Formato estándar leído por wp_maintenance() en wp-includes/load.php.
\t\t$payload  = "<?php\\n";
\t\t$payload .= "// Archivo generado temporalmente por OscarPx Backup & Restore (wp_maintenance).\\n";
\t\t$payload .= '$upgrading = ' . time() . ";\\n";
\t\t$payload .= "if ( defined( 'DOING_AJAX' ) && DOING_AJAX && isset( \\$_POST['action'], \\$_POST['oscarpx_maint_key'] ) && 0 === strpos( (string) \\$_POST['action'], 'oscarpx_' ) && hash_equals( '" . $clean_key . "', (string) \\$_POST['oscarpx_maint_key'] ) ) {\\n";
\t\t$payload .= "\t\\$upgrading = 0;\\n";
\t\t$payload .= "}\\n";

\t\tif ( false === @file_put_contents( $maint_file, $payload ) ) {
\t\t\treturn new WP_Error(
\t\t\t\t'oscarpx_maint_write',
\t\t\t\t__( 'No se pudo crear el archivo .maintenance en la raíz de WordPress.', 'oscarpx-backup-restore' )
\t\t\t);
\t\t}

\t\treturn true;
\t}

\t/**
\t * Elimina el archivo .maintenance de la raíz al finalizar con éxito el último paso (Search & Replace).
\t *
\t * @return bool
\t */
\tpublic static function disable_maintenance_mode() {
\t\t$maint_file = self::get_maintenance_file_path();
\t\tif ( file_exists( $maint_file ) ) {
\t\t\treturn @unlink( $maint_file );
\t\t}
\t\treturn true;
\t}

\t/**
\t * Comprueba si existe .maintenance en la raíz.
\t *
\t * @return bool
\t */
\tpublic static function is_maintenance_active() {
\t\treturn file_exists( self::get_maintenance_file_path() );
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

\t\t// Modo solo-bd: sin archivos wp-content que empaquetar.
\t\tif ( 0 === (int) $total_files ) {
\t\t\t$zip->close();
\t\t\treturn array(
\t\t\t\t'done'        => true,
\t\t\t\t'next_offset' => 0,
\t\t\t\t'total_files' => 0,
\t\t\t\t'added'       => 1,
\t\t\t\t'skipped'     => 0,
\t\t\t\t'bytes'       => file_exists( $sql_file ) ? (int) @filesize( $sql_file ) : 0,
\t\t\t);
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

\tconst ENTRIES_PER_CHUNK         = 300;
\tconst STATEMENTS_PER_CHUNK      = 100;
\tconst MAX_SQL_BYTES_PER_CHUNK   = 2097152; // 2 MB por lote para no colapsar RAM.
\tconst APPLY_FILES_PER_CHUNK     = 400;
\tconst SEARCH_REPLACE_ROWS_CHUNK = 200;

\t/**
\t * Regla 1 (Protección del core): bloquea explícitamente wp-config.php y .htaccess
\t * para preservar intactas las credenciales de conexión y reglas del servidor destino.
\t *
\t * @param string $relative_path Ruta normalizada dentro del ZIP o staging.
\t * @return bool True si el archivo está protegido y debe omitirse.
\t */
\tpublic function is_protected_core_file( $relative_path ) {
\t\t$clean = ltrim( str_replace( '\\\\', '/', (string) $relative_path ), './' );
\t\t$lower = strtolower( $clean );
\t\t$base  = strtolower( basename( $clean ) );

\t\tif ( '' === $lower ) {
\t\t\treturn true;
\t\t}

\t\tif ( 'wp-config.php' === $lower || 'wp-config.php' === $base || '.htaccess' === $lower || '.htaccess' === $base ) {
\t\t\treturn true;
\t\t}

\t\tif ( 'wp-maintenance' === $lower || '.maintenance' === $lower || '.maintenance' === $base ) {
\t\t\treturn true;
\t\t}

\t\tif ( 0 === strpos( $lower, 'wp-content/oscarpx-backups/' ) ) {
\t\t\treturn true;
\t\t}

\t\treturn false;
\t}

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
\t * Extrae un lote de archivos del .zip hacia una carpeta staging aislada (.tmp-{job_id}/stage/)
\t * omitiendo y bloqueando explícitamente wp-config.php y .htaccess (Regla 1).
\t *
\t * @param string $zip_path    Ruta del .zip.
\t * @param string $temp_dir    Carpeta temporal segura del job.
\t * @param int    $entry_index Índice inicial en el archivo ZIP.
\t * @return array|WP_Error
\t */
\tpublic function extract_chunk( $zip_path, $temp_dir, $entry_index ) {
\t\t$zip = new ZipArchive();
\t\tif ( true !== $zip->open( $zip_path ) ) {
\t\t\treturn new WP_Error( 'oscarpx_zip_open', __( 'Error al abrir el respaldo durante la extracción.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$stage_dir = trailingslashit( $temp_dir ) . 'stage/';
\t\tif ( ! is_dir( $stage_dir ) ) {
\t\t\twp_mkdir_p( $stage_dir );
\t\t}

\t\t$total          = (int) $zip->numFiles;
\t\t$end_index      = min( $total, (int) $entry_index + self::ENTRIES_PER_CHUNK );
\t\t$safe_entries   = array();
\t\t$raw_name_map   = array();
\t\t$blocked_core   = array();

\t\tfor ( $i = (int) $entry_index; $i < $end_index; $i++ ) {
\t\t\t$raw_name   = (string) $zip->getNameIndex( $i );
\t\t\t$entry_name = ltrim( str_replace( '\\\\', '/', $raw_name ), './' );

\t\t\t// Protección Zip Slip contra traversal.
\t\t\tif ( empty( $entry_name ) || false !== strpos( $entry_name, '..' ) ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t// Ignorar entradas de directorio puras.
\t\t\tif ( '/' === substr( $entry_name, -1 ) ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t// Regla 1 (Protección del core): bloquear explícitamente wp-config.php, .htaccess y carpeta de backups.
\t\t\tif ( $this->is_protected_core_file( $entry_name ) ) {
\t\t\t\t$blocked_core[] = $entry_name;
\t\t\t\tcontinue;
\t\t\t}

\t\t\t$safe_entries[]            = $raw_name;
\t\t\t$raw_name_map[ $raw_name ] = $entry_name;
\t\t}

\t\t$extracted = 0;

\t\tif ( ! empty( $safe_entries ) ) {
\t\t\t// Intento rápido en C mediante libzip hacia staging.
\t\t\tif ( @$zip->extractTo( $stage_dir, $safe_entries ) ) {
\t\t\t\t$extracted = count( $safe_entries );
\t\t\t} else {
\t\t\t\t// Respaldo por stream individual si algún servidor restringe extractTo().
\t\t\t\t$created_dirs = array();
\t\t\t\tforeach ( $safe_entries as $raw_name ) {
\t\t\t\t\t$rel_path    = $raw_name_map[ $raw_name ];
\t\t\t\t\t$target_path = $stage_dir . $rel_path;
\t\t\t\t\t$target_dir  = dirname( $target_path );

\t\t\t\t\tif ( ! isset( $created_dirs[ $target_dir ] ) ) {
\t\t\t\t\t\tif ( ! is_dir( $target_dir ) ) {
\t\t\t\t\t\t\twp_mkdir_p( $target_dir );
\t\t\t\t\t\t}
\t\t\t\t\t\t$created_dirs[ $target_dir ] = true;
\t\t\t\t\t}

\t\t\t\t\t$stream = $zip->getStream( $raw_name );
\t\t\t\t\tif ( $stream ) {
\t\t\t\t\t\t$out = @fopen( $target_path, 'wb' );
\t\t\t\t\t\tif ( $out ) {
\t\t\t\t\t\t\twhile ( ! feof( $stream ) ) {
\t\t\t\t\t\t\t\tfwrite( $out, fread( $stream, 65536 ) );
\t\t\t\t\t\t\t}
\t\t\t\t\t\t\tfclose( $out );
\t\t\t\t\t\t\t++$extracted;
\t\t\t\t\t\t}
\t\t\t\t\t\tfclose( $stream );
\t\t\t\t\t}
\t\t\t\t}
\t\t\t}
\t\t}

\t\t$zip->close();

\t\treturn array(
\t\t\t'done'         => ( $end_index >= $total ),
\t\t\t'next_index'   => $end_index,
\t\t\t'total'        => $total,
\t\t\t'extracted'    => $extracted,
\t\t\t'blocked_core' => array_values( array_unique( $blocked_core ) ),
\t\t);
\t}

\t/**
\t * Regla 3 (Inyección SQL Segura - Hot Swap): verifica que ninguna sentencia intente destruir
\t * o recrear la base de datos a nivel de servidor, limitándose a tablas (DROP TABLE IF EXISTS / CREATE / INSERT).
\t *
\t * @param string $statement Sentencia SQL individual.
\t * @return bool
\t */
\tpublic function is_allowed_restore_sql( $statement ) {
\t\t$upper = strtoupper( ltrim( (string) $statement ) );

\t\t// Bloquear explícitamente destrucción o creación de base de datos a nivel de servidor.
\t\t$forbidden_prefixes = array(
\t\t\t'DROP DATABASE',
\t\t\t'DROP SCHEMA',
\t\t\t'CREATE DATABASE',
\t\t\t'CREATE SCHEMA',
\t\t\t'USE ',
\t\t\t'GRANT ',
\t\t\t'REVOKE ',
\t\t\t'CREATE USER',
\t\t\t'DROP USER',
\t\t\t'LOCK TABLES',
\t\t\t'UNLOCK TABLES',
\t\t);

\t\tforeach ( $forbidden_prefixes as $prefix ) {
\t\t\tif ( 0 === strpos( $upper, $prefix ) ) {
\t\t\t\treturn false;
\t\t\t}
\t\t}

\t\treturn true;
\t}

\t/**
\t * Lee la URL origen registrada en la cabecera de database-backup.sql si existe.
\t *
\t * @param string $sql_file Ruta al .sql.
\t * @return string
\t */
\tpublic function detect_source_url_from_dump( $sql_file ) {
\t\tif ( ! file_exists( $sql_file ) ) {
\t\t\treturn '';
\t\t}

\t\t$handle = @fopen( $sql_file, 'rb' );
\t\tif ( ! $handle ) {
\t\t\treturn '';
\t\t}

\t\t$source_url = '';
\t\t$lines_read = 0;
\t\twhile ( ! feof( $handle ) && $lines_read < 30 ) {
\t\t\t$line = fgets( $handle, 4096 );
\t\t\t++$lines_read;
\t\t\tif ( false !== $line && 0 === strpos( $line, '-- Sitio:' ) ) {
\t\t\t\t$source_url = untrailingslashit( trim( substr( $line, strlen( '-- Sitio:' ) ) ) );
\t\t\t\tbreak;
\t\t\t}
\t\t}

\t\tfclose( $handle );
\t\treturn $source_url;
\t}

\t/**
\t * Lee database-backup.sql por fragmentos de memoria acotada usando las credenciales activas en $wpdb,
\t * ejecutando DROP TABLE IF EXISTS, CREATE TABLE e INSERT sin destruir/recrear la base de datos.
\t *
\t * @param string $sql_file         Ruta al archivo .sql extraído en staging.
\t * @param int    $byte_offset      Posición de byte actual.
\t * @param array  $session_snapshot Datos de sesión del administrador actual.
\t * @return array|WP_Error
\t */
\tpublic function restore_db_chunk( $sql_file, $byte_offset, array $session_snapshot = array() ) {
\t\tglobal $wpdb;

\t\tif ( ! file_exists( $sql_file ) ) {
\t\t\treturn new WP_Error( 'oscarpx_sql_missing', __( 'No se encontró database-backup.sql para restaurar.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$total_bytes = (int) filesize( $sql_file );
\t\t$handle      = @fopen( $sql_file, 'rb' );
\t\tif ( ! $handle ) {
\t\t\treturn new WP_Error( 'oscarpx_sql_read', __( 'No se pudo leer el volcado SQL.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$prev_suppress = $wpdb->suppress_errors( true );
\t\t$prev_show     = $wpdb->show_errors( false );

\t\tfseek( $handle, (int) $byte_offset );
\t\t$wpdb->query( 'SET FOREIGN_KEY_CHECKS = 0;' );

\t\t$executed         = 0;
\t\t$skipped_ddl      = 0;
\t\t$bytes_read       = 0;
\t\t$buffer           = '';
\t\t$in_string        = false;
\t\t$escape_next      = false;
\t\t$last_safe_pos    = (int) $byte_offset;
\t\t$touched_usermeta = false;

\t\twhile ( ! feof( $handle ) && $executed < self::STATEMENTS_PER_CHUNK && $bytes_read < self::MAX_SQL_BYTES_PER_CHUNK ) {
\t\t\t$line = fgets( $handle );
\t\t\tif ( false === $line ) {
\t\t\t\tbreak;
\t\t\t}
\t\t\t$bytes_read += strlen( $line );

\t\t\t$trimmed = ltrim( $line );
\t\t\tif ( ! $in_string && ( '' === $trimmed || 0 === strpos( $trimmed, '--' ) || 0 === strpos( $trimmed, '#' ) || 0 === strpos( $trimmed, '/*' ) ) ) {
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
\t\t\t\t\t\tif ( ! $this->is_allowed_restore_sql( $statement ) ) {
\t\t\t\t\t\t\t++$skipped_ddl;
\t\t\t\t\t\t\tcontinue;
\t\t\t\t\t\t}
\t\t\t\t\t\t$result = $wpdb->query( $statement );
\t\t\t\t\t\tif ( false === $result && ! empty( $wpdb->last_error ) ) {
\t\t\t\t\t\t\t$err = $wpdb->last_error;
\t\t\t\t\t\t\tfclose( $handle );
\t\t\t\t\t\t\t$wpdb->show_errors( $prev_show );
\t\t\t\t\t\t\t$wpdb->suppress_errors( $prev_suppress );
\t\t\t\t\t\t\treturn new WP_Error( 'oscarpx_sql_exec', $err );
\t\t\t\t\t\t}
\t\t\t\t\t\tif ( false !== stripos( $statement, 'usermeta' ) ) {
\t\t\t\t\t\t\t$touched_usermeta = true;
\t\t\t\t\t\t}
\t\t\t\t\t\t++$executed;
\t\t\t\t\t\t// Liberar caché interna de resultados de $wpdb para mantener RAM constante.
\t\t\t\t\t\t$wpdb->flush();
\t\t\t\t\t\tif ( defined( 'SAVEQUERIES' ) && SAVEQUERIES ) {
\t\t\t\t\t\t\t$wpdb->queries = array();
\t\t\t\t\t\t}
\t\t\t\t\t}
\t\t\t\t} else {
\t\t\t\t\t$buffer .= $ch;
\t\t\t\t}
\t\t\t}

\t\t\tif ( ! $in_string && '' === trim( $buffer ) ) {
\t\t\t\t$last_safe_pos = ftell( $handle );
\t\t\t}

\t\t\tif ( ( $executed >= self::STATEMENTS_PER_CHUNK || $bytes_read >= self::MAX_SQL_BYTES_PER_CHUNK ) && '' === trim( $buffer ) ) {
\t\t\t\tbreak;
\t\t\t}
\t\t}

\t\t$eof = feof( $handle );
\t\tfclose( $handle );

\t\tif ( $eof && '' !== trim( $buffer ) && $this->is_allowed_restore_sql( trim( $buffer ) ) ) {
\t\t\t$wpdb->query( trim( $buffer ) );
\t\t\t$wpdb->flush();
\t\t\t++$executed;
\t\t}

\t\t// Mantener el token de sesión del administrador activo para no romper los nonces de los lotes restantes.
\t\tif ( $touched_usermeta && ! empty( $session_snapshot['user_id'] ) && ! empty( $session_snapshot['session_tokens'] ) ) {
\t\t\t$uid   = (int) $session_snapshot['user_id'];
\t\t\t$token = (string) $session_snapshot['session_tokens'];
\t\t\t$exists = $wpdb->get_var(
\t\t\t\t$wpdb->prepare(
\t\t\t\t\t"SELECT umeta_id FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = 'session_tokens' LIMIT 1",
\t\t\t\t\t$uid
\t\t\t\t)
\t\t\t);
\t\t\tif ( $exists ) {
\t\t\t\t$wpdb->update(
\t\t\t\t\t$wpdb->usermeta,
\t\t\t\t\tarray( 'meta_value' => $token ),
\t\t\t\t\tarray( 'umeta_id' => (int) $exists ),
\t\t\t\t\tarray( '%s' ),
\t\t\t\t\tarray( '%d' )
\t\t\t\t);
\t\t\t} else {
\t\t\t\t$wpdb->insert(
\t\t\t\t\t$wpdb->usermeta,
\t\t\t\t\tarray(
\t\t\t\t\t\t'user_id'    => $uid,
\t\t\t\t\t\t'meta_key'   => 'session_tokens',
\t\t\t\t\t\t'meta_value' => $token,
\t\t\t\t\t),
\t\t\t\t\tarray( '%d', '%s', '%s' )
\t\t\t\t);
\t\t\t}
\t\t}

\t\t$wpdb->query( 'SET FOREIGN_KEY_CHECKS = 1;' );
\t\t$wpdb->show_errors( $prev_show );
\t\t$wpdb->suppress_errors( $prev_suppress );

\t\treturn array(
\t\t\t'done'        => $eof,
\t\t\t'next_offset' => $eof ? $total_bytes : $last_safe_pos,
\t\t\t'total_bytes' => $total_bytes,
\t\t\t'executed'    => $executed,
\t\t\t'skipped_ddl' => $skipped_ddl,
\t\t);
\t}

\t/**
\t * Genera el manifiesto de archivos extraídos en staging para aplicarlos sobre ABSPATH.
\t * Regla 1: omite y bloquea explícitamente wp-config.php y .htaccess para no alterar credenciales ni reglas del servidor destino.
\t *
\t * @param string $temp_dir Carpeta temporal del job.
\t * @return array|WP_Error
\t */
\tpublic function build_apply_manifest( $temp_dir ) {
\t\t$stage_dir     = trailingslashit( $temp_dir ) . 'stage/';
\t\t$manifest_file = trailingslashit( $temp_dir ) . 'apply-manifest.txt';

\t\tif ( ! is_dir( $stage_dir ) ) {
\t\t\treturn new WP_Error( 'oscarpx_stage_missing', __( 'No se encontró el directorio staging.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$handle = @fopen( $manifest_file, 'wb' );
\t\tif ( ! $handle ) {
\t\t\treturn new WP_Error( 'oscarpx_apply_manifest', __( 'No se pudo crear el manifiesto de aplicación.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$stage_norm  = rtrim( str_replace( '\\\\', '/', $stage_dir ), '/' ) . '/';
\t\t$stage_len   = strlen( $stage_norm );
\t\t$total_files = 0;

\t\t$iterator = new RecursiveIteratorIterator(
\t\t\tnew RecursiveDirectoryIterator( $stage_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
\t\t\tRecursiveIteratorIterator::LEAVES_ONLY
\t\t);

\t\tforeach ( $iterator as $item ) {
\t\t\tif ( ! $item->isFile() ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t$full = str_replace( '\\\\', '/', $item->getPathname() );
\t\t\t$rel  = ltrim( substr( $full, $stage_len ), '/' );

\t\t\tif ( '' === $rel || 'database-backup.sql' === $rel || $this->is_protected_core_file( $rel ) ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\tfwrite( $handle, $rel . "\\n" );
\t\t\t++$total_files;
\t\t}

\t\tfclose( $handle );

\t\treturn array(
\t\t\t'total_files' => $total_files,
\t\t);
\t}

\t/**
\t * Aplica un lote de archivos desde staging hacia ABSPATH mediante rename() (O(1)) o copy().
\t * Nunca sobrescribe wp-config.php ni .htaccess del servidor de destino.
\t *
\t * @param string $temp_dir    Carpeta temporal del job.
\t * @param int    $line_offset Línea inicial en apply-manifest.txt.
\t * @param int    $total_files Total de archivos a aplicar.
\t * @return array|WP_Error
\t */
\tpublic function apply_stage_chunk( $temp_dir, $line_offset, $total_files ) {
\t\t$stage_dir     = trailingslashit( $temp_dir ) . 'stage/';
\t\t$manifest_file = trailingslashit( $temp_dir ) . 'apply-manifest.txt';

\t\tif ( ! file_exists( $manifest_file ) ) {
\t\t\treturn new WP_Error( 'oscarpx_apply_missing', __( 'Falta el manifiesto de aplicación.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$file_obj = new SplFileObject( $manifest_file, 'rb' );
\t\t$file_obj->seek( (int) $line_offset );

\t\t$processed    = 0;
\t\t$applied      = 0;
\t\t$created_dirs = array();
\t\t$abs_root     = trailingslashit( ABSPATH );

\t\twhile ( ! $file_obj->eof() && $processed < self::APPLY_FILES_PER_CHUNK ) {
\t\t\t$rel = trim( (string) $file_obj->current() );
\t\t\t$file_obj->next();

\t\t\tif ( '' === $rel ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t++$processed;

\t\t\t// Doble barrera de protección: jamás sobrescribir wp-config.php ni .htaccess.
\t\t\tif ( $this->is_protected_core_file( $rel ) ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t$src = $stage_dir . $rel;
\t\t\tif ( ! is_file( $src ) ) {
\t\t\t\tcontinue;
\t\t\t}

\t\t\t$dst     = $abs_root . $rel;
\t\t\t$dst_dir = dirname( $dst );
\t\t\tif ( ! isset( $created_dirs[ $dst_dir ] ) ) {
\t\t\t\tif ( ! is_dir( $dst_dir ) ) {
\t\t\t\t\twp_mkdir_p( $dst_dir );
\t\t\t\t}
\t\t\t\t$created_dirs[ $dst_dir ] = true;
\t\t\t}

\t\t\tif ( @rename( $src, $dst ) || ( @copy( $src, $dst ) && @unlink( $src ) ) ) {
\t\t\t\t++$applied;
\t\t\t}
\t\t}

\t\t$next_offset = (int) $line_offset + $processed;
\t\t$done        = ( $file_obj->eof() || $next_offset >= (int) $total_files );

\t\treturn array(
\t\t\t'done'        => $done,
\t\t\t'next_offset' => $next_offset,
\t\t\t'total_files' => (int) $total_files,
\t\t\t'applied'     => $applied,
\t\t);
\t}

\t/**
\t * Ejecuta Search & Replace seguro para cadenas serializadas PHP por lotes de tablas y filas.
\t * Si source_url === target_url, finaliza validando opciones de caché y permalinks.
\t *
\t * @param string $source_url  URL de origen del respaldo.
\t * @param string $target_url  URL de destino actual.
\t * @param int    $table_index Índice de tabla actual.
\t * @param int    $row_offset  Offset de fila actual.
\t * @return array
\t */
\tpublic function search_replace_chunk( $source_url, $target_url, $table_index, $row_offset ) {
\t\tglobal $wpdb;

\t\t$search  = untrailingslashit( trim( (string) $source_url ) );
\t\t$replace = untrailingslashit( trim( (string) $target_url ) );

\t\tif ( '' === $search || '' === $replace || $search === $replace ) {
\t\t\twp_cache_flush();
\t\t\treturn array(
\t\t\t\t'done'        => true,
\t\t\t\t'table_index' => 1,
\t\t\t\t'row_offset'  => 0,
\t\t\t\t'total'       => 1,
\t\t\t\t'updated'     => 0,
\t\t\t\t'message'     => __( 'Search & Replace: dominio de origen y destino coinciden; caché vaciada.', 'oscarpx-backup-restore' ),
\t\t\t);
\t\t}

\t\t$tables_raw = $wpdb->get_results( 'SHOW TABLES', ARRAY_N );
\t\t$tables     = array();
\t\tif ( is_array( $tables_raw ) ) {
\t\t\tforeach ( $tables_raw as $row ) {
\t\t\t\tif ( isset( $row[0] ) ) {
\t\t\t\t\t$tables[] = $row[0];
\t\t\t\t}
\t\t\t}
\t\t}

\t\t$total_tables = count( $tables );
\t\tif ( $table_index >= $total_tables ) {
\t\t\twp_cache_flush();
\t\t\treturn array(
\t\t\t\t'done'        => true,
\t\t\t\t'table_index' => $total_tables,
\t\t\t\t'row_offset'  => 0,
\t\t\t\t'total'       => $total_tables,
\t\t\t\t'updated'     => 0,
\t\t\t\t'message'     => __( 'Search & Replace completado en todas las tablas.', 'oscarpx-backup-restore' ),
\t\t\t);
\t\t}

\t\t$table      = $tables[ $table_index ];
\t\t$safe_table = str_replace( '\`', '\`\`', $table );
\t\t$columns    = $wpdb->get_results( "SHOW COLUMNS FROM \`{$safe_table}\`", ARRAY_A );
\t\t$pk_col     = '';
\t\t$text_cols  = array();

\t\tif ( is_array( $columns ) ) {
\t\t\tforeach ( $columns as $col ) {
\t\t\t\tif ( empty( $pk_col ) && isset( $col['Key'] ) && 'PRI' === $col['Key'] ) {
\t\t\t\t\t$pk_col = $col['Field'];
\t\t\t\t}
\t\t\t\tif ( isset( $col['Type'] ) && preg_match( '/char|text|blob/i', $col['Type'] ) ) {
\t\t\t\t\t$text_cols[] = $col['Field'];
\t\t\t\t}
\t\t\t}
\t\t}

\t\t$updated_rows = 0;
\t\t$limit        = self::SEARCH_REPLACE_ROWS_CHUNK;
\t\t$fetched      = 0;

\t\tif ( ! empty( $pk_col ) && ! empty( $text_cols ) ) {
\t\t\t$rows    = $wpdb->get_results(
\t\t\t\t$wpdb->prepare( "SELECT * FROM \`{$safe_table}\` LIMIT %d OFFSET %d", $limit, (int) $row_offset ),
\t\t\t\tARRAY_A
\t\t\t);
\t\t\t$fetched = is_array( $rows ) ? count( $rows ) : 0;

\t\t\tif ( $fetched > 0 ) {
\t\t\t\tforeach ( $rows as $row ) {
\t\t\t\t\t// Preservar tokens de sesión de usuario intactos.
\t\t\t\t\tif ( isset( $row['meta_key'] ) && 'session_tokens' === $row['meta_key'] ) {
\t\t\t\t\t\tcontinue;
\t\t\t\t\t}

\t\t\t\t\t$changes = array();
\t\t\t\t\tforeach ( $text_cols as $col_name ) {
\t\t\t\t\t\tif ( 'guid' === $col_name ) {
\t\t\t\t\t\t\tcontinue;
\t\t\t\t\t\t}
\t\t\t\t\t\tif ( ! isset( $row[ $col_name ] ) || ! is_string( $row[ $col_name ] ) || false === strpos( $row[ $col_name ], $search ) ) {
\t\t\t\t\t\t\tcontinue;
\t\t\t\t\t\t}
\t\t\t\t\t\t$new_val = $this->recursive_search_replace( $search, $replace, $row[ $col_name ] );
\t\t\t\t\t\tif ( $new_val !== $row[ $col_name ] ) {
\t\t\t\t\t\t\t$changes[ $col_name ] = $new_val;
\t\t\t\t\t\t}
\t\t\t\t\t}

\t\t\t\t\tif ( ! empty( $changes ) ) {
\t\t\t\t\t\t$wpdb->update( $table, $changes, array( $pk_col => $row[ $pk_col ] ) );
\t\t\t\t\t\t++$updated_rows;
\t\t\t\t\t}
\t\t\t\t}
\t\t\t}
\t\t}

\t\t$wpdb->flush();

\t\tif ( $fetched === $limit ) {
\t\t\t$next_table = $table_index;
\t\t\t$next_off   = $row_offset + $fetched;
\t\t} else {
\t\t\t$next_table = $table_index + 1;
\t\t\t$next_off   = 0;
\t\t}

\t\t$done = ( $next_table >= $total_tables );
\t\tif ( $done ) {
\t\t\twp_cache_flush();
\t\t}

\t\treturn array(
\t\t\t'done'        => $done,
\t\t\t'table_index' => $next_table,
\t\t\t'row_offset'  => $next_off,
\t\t\t'total'       => $total_tables,
\t\t\t'updated'     => $updated_rows,
\t\t\t'message'     => sprintf( 'Search & Replace en %s (%d actualizaciones)...', $table, $updated_rows ),
\t\t);
\t}

\t/**
\t * Reemplaza cadenas respetando estructuras serializadas PHP.
\t *
\t * @param string $search  Cadena a buscar.
\t * @param string $replace Cadena de reemplazo.
\t * @param mixed  $data    Valor original.
\t * @return mixed
\t */
\tprivate function recursive_search_replace( $search, $replace, $data ) {
\t\tif ( is_string( $data ) ) {
\t\t\tif ( is_serialized( $data ) ) {
\t\t\t\t$unserialized = @unserialize( $data, array( 'allowed_classes' => false ) );
\t\t\t\tif ( false !== $unserialized || 'b:0;' === $data ) {
\t\t\t\t\t$replaced = $this->recursive_search_replace( $search, $replace, $unserialized );
\t\t\t\t\treturn serialize( $replaced );
\t\t\t\t}
\t\t\t}
\t\t\treturn str_replace( $search, $replace, $data );
\t\t}

\t\tif ( is_array( $data ) ) {
\t\t\tforeach ( $data as $key => $val ) {
\t\t\t\t$data[ $key ] = $this->recursive_search_replace( $search, $replace, $val );
\t\t\t}
\t\t\treturn $data;
\t\t}

\t\treturn $data;
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

\tconst PARENT_MENU_SLUG = 'px-tools';
\tconst MENU_SLUG        = 'oscarpx-backup-restore';

\t/**
\t * Sufijos de pantalla devueltos por add_submenu_page() para cargar assets solo en este plugin.
\t *
\t * @var array
\t */
\tprivate $page_hooks = array();

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

\t\t// Endpoints AJAX para Restauración Segura (Sistema Anticaídas) y Gestor de Backups.
\t\tadd_action( 'wp_ajax_oscarpx_start_restore', array( $this, 'ajax_start_restore' ) );
\t\tadd_action( 'wp_ajax_oscarpx_process_extract_chunk', array( $this, 'ajax_process_extract_chunk' ) );
\t\tadd_action( 'wp_ajax_oscarpx_process_sql_chunk', array( $this, 'ajax_process_sql_chunk' ) );
\t\tadd_action( 'wp_ajax_oscarpx_build_apply_manifest', array( $this, 'ajax_build_apply_manifest' ) );
\t\tadd_action( 'wp_ajax_oscarpx_process_apply_chunk', array( $this, 'ajax_process_apply_chunk' ) );
\t\tadd_action( 'wp_ajax_oscarpx_process_search_replace_chunk', array( $this, 'ajax_process_search_replace_chunk' ) );
\t\tadd_action( 'wp_ajax_oscarpx_upload_backup_chunk', array( $this, 'ajax_upload_backup_chunk' ) );
\t\tadd_action( 'wp_ajax_oscarpx_delete_backup', array( $this, 'ajax_delete_backup' ) );

\t\t// Puente PHP seguro (Streaming) para descargar archivos protegidos por .htaccess.
\t\tadd_action( 'admin_post_download_oscarpx_backup', array( $this, 'handle_download_backup' ) );
\t}

\t/**
\t * Agrupa este plugin bajo el menú maestro del ecosistema "PX Tools" (slug: px-tools).
\t * Verifica globalmente si otro plugin de la marca ya registró px-tools antes de crearlo.
\t */
\tpublic function register_menu_page() {
\t\tglobal $menu, $admin_page_hooks;

\t\t$px_tools_exists = isset( $admin_page_hooks[ self::PARENT_MENU_SLUG ] );
\t\tif ( ! $px_tools_exists && is_array( $menu ) ) {
\t\t\tforeach ( $menu as $menu_item ) {
\t\t\t\tif ( isset( $menu_item[2] ) && self::PARENT_MENU_SLUG === $menu_item[2] ) {
\t\t\t\t\t$px_tools_exists = true;
\t\t\t\t\tbreak;
\t\t\t\t}
\t\t\t}
\t\t}

\t\t// Si ningún otro plugin de la suite ha creado el menú maestro, lo registramos aquí.
\t\tif ( ! $px_tools_exists ) {
\t\t\t$parent_hook = add_menu_page(
\t\t\t\t__( 'PX Tools', 'oscarpx-backup-restore' ),
\t\t\t\t__( 'PX Tools', 'oscarpx-backup-restore' ),
\t\t\t\t'manage_options',
\t\t\t\tself::PARENT_MENU_SLUG,
\t\t\t\tarray( $this, 'render_px_tools_redirect' ),
\t\t\t\t'dashicons-superhero',
\t\t\t\t80
\t\t\t);

\t\t\tif ( $parent_hook ) {
\t\t\t\tadd_action( 'load-' . $parent_hook, array( $this, 'redirect_parent_to_first_submenu' ) );
\t\t\t}
\t\t}

\t\t// Registramos el panel del plugin como submenú ordenado bajo el bloque maestro px-tools.
\t\t$main_hook = add_submenu_page(
\t\t\tself::PARENT_MENU_SLUG,
\t\t\t__( 'OscarPx Backup & Restore', 'oscarpx-backup-restore' ),
\t\t\t__( 'Backup & Restore', 'oscarpx-backup-restore' ),
\t\t\t'manage_options',
\t\t\tself::MENU_SLUG,
\t\t\tarray( $this, 'render_admin_page' )
\t\t);

\t\tif ( $main_hook ) {
\t\t\t$this->page_hooks[] = $main_hook;
\t\t}

\t\t// Evita el submenú duplicado "PX Tools" cuando este plugin crea el nodo padre.
\t\tif ( ! $px_tools_exists ) {
\t\t\tremove_submenu_page( self::PARENT_MENU_SLUG, self::PARENT_MENU_SLUG );
\t\t}
\t}

\t/**
\t * Redirige automáticamente al primer submenú activo si se accede directamente a ?page=px-tools.
\t */
\tpublic function redirect_parent_to_first_submenu() {
\t\tif ( ! current_user_can( 'manage_options' ) ) {
\t\t\treturn;
\t\t}

\t\t$first_slug = $this->get_first_px_tools_submenu_slug();
\t\tif ( $first_slug && self::PARENT_MENU_SLUG !== $first_slug ) {
\t\t\twp_safe_redirect( admin_url( 'admin.php?page=' . $first_slug ) );
\t\t\texit;
\t\t}
\t}

\t/**
\t * Callback de respaldo para el menú maestro px-tools.
\t */
\tpublic function render_px_tools_redirect() {
\t\t$this->render_admin_page();
\t}

\t/**
\t * Devuelve el slug del primer submenú registrado bajo px-tools.
\t *
\t * @return string
\t */
\tprivate function get_first_px_tools_submenu_slug() {
\t\tglobal $submenu;

\t\tif ( ! empty( $submenu[ self::PARENT_MENU_SLUG ] ) && is_array( $submenu[ self::PARENT_MENU_SLUG ] ) ) {
\t\t\tforeach ( $submenu[ self::PARENT_MENU_SLUG ] as $item ) {
\t\t\t\tif ( ! empty( $item[2] ) && self::PARENT_MENU_SLUG !== $item[2] ) {
\t\t\t\t\treturn (string) $item[2];
\t\t\t\t}
\t\t\t}
\t\t}

\t\treturn self::MENU_SLUG;
\t}

\t/**
\t * Carga scripts y estilos solo dentro de las páginas registradas por este plugin.
\t *
\t * @param string $hook_suffix Sufijo del screen actual.
\t */
\tpublic function enqueue_assets( $hook_suffix ) {
\t\t$fallback_hook = 'px-tools_page_' . self::MENU_SLUG;
\t\tif ( ! in_array( $hook_suffix, $this->page_hooks, true ) && $fallback_hook !== $hook_suffix ) {
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
\t * Renderiza la interfaz con estilos nativos de WordPress y 3 pestañas:
\t * "Crear Backup", "Gestor de Backups" (central) y "Restaurar Backup".
\t */
\tpublic function render_admin_page() {
\t\tif ( ! current_user_can( 'manage_options' ) ) {
\t\t\twp_die( esc_html__( 'No tienes permisos suficientes.', 'oscarpx-backup-restore' ) );
\t\t}

\t\tOscarPx_Security::ensure_backup_directory();

\t\t$raw_tab            = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'create';
\t\t$active_tab         = in_array( $raw_tab, array( 'create', 'manager', 'restore' ), true ) ? $raw_tab : 'create';
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
\t\t\t\t<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::MENU_SLUG . '&tab=manager' ) ); ?>"
\t\t\t\t   class="nav-tab <?php echo 'manager' === $active_tab ? 'nav-tab-active' : ''; ?>">
\t\t\t\t\t<?php
\t\t\t\t\t/* translators: %d: cantidad de archivos zip */
\t\t\t\t\tprintf( esc_html__( 'Gestor de Backups (%d)', 'oscarpx-backup-restore' ), count( $backups ) );
\t\t\t\t\t?>
\t\t\t\t</a>
\t\t\t\t<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . self::MENU_SLUG . '&tab=restore' ) ); ?>"
\t\t\t\t   class="nav-tab <?php echo 'restore' === $active_tab ? 'nav-tab-active' : ''; ?>">
\t\t\t\t\t<?php esc_html_e( 'Restaurar Backup', 'oscarpx-backup-restore' ); ?>
\t\t\t\t</a>
\t\t\t</nav>

\t\t\t<?php if ( 'create' === $active_tab ) : ?>
\t\t\t\t<div class="card oscarpx-card">
\t\t\t\t\t<h2><?php esc_html_e( 'Generar Nueva Copia de Seguridad', 'oscarpx-backup-restore' ); ?></h2>
\t\t\t\t\t<table class="form-table" role="presentation">
\t\t\t\t\t\t<tbody>
\t\t\t\t\t\t\t<tr>
\t\t\t\t\t\t\t\t<th scope="row">
\t\t\t\t\t\t\t\t\t<label for="oscarpx-backup-type"><?php esc_html_e( 'Tipo de Backup', 'oscarpx-backup-restore' ); ?></label>
\t\t\t\t\t\t\t\t</th>
\t\t\t\t\t\t\t\t<td>
\t\t\t\t\t\t\t\t\t<select id="oscarpx-backup-type" class="regular-text">
\t\t\t\t\t\t\t\t\t\t<option value="completo"><?php esc_html_e( 'Completo (Base de Datos + Archivos)', 'oscarpx-backup-restore' ); ?></option>
\t\t\t\t\t\t\t\t\t\t<option value="solo-bd"><?php esc_html_e( 'Solo Base de Datos (.sql)', 'oscarpx-backup-restore' ); ?></option>
\t\t\t\t\t\t\t\t\t</select>
\t\t\t\t\t\t\t\t\t<p class="description">
\t\t\t\t\t\t\t\t\t\t<?php
\t\t\t\t\t\t\t\t\t\tprintf(
\t\t\t\t\t\t\t\t\t\t\tesc_html__( 'Nomenclatura automática: %s-{tipo}_{Y-m-d_H-i-s}.zip', 'oscarpx-backup-restore' ),
\t\t\t\t\t\t\t\t\t\t\tesc_html( sanitize_title( (string) get_bloginfo( 'name' ) ) ? sanitize_title( (string) get_bloginfo( 'name' ) ) : 'sitio-wp' )
\t\t\t\t\t\t\t\t\t\t);
\t\t\t\t\t\t\t\t\t\t?>
\t\t\t\t\t\t\t\t\t</p>
\t\t\t\t\t\t\t\t</td>
\t\t\t\t\t\t\t</tr>
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
\t\t\t<?php elseif ( 'manager' === $active_tab ) : ?>
\t\t\t\t<div class="card oscarpx-card">
\t\t\t\t\t<h2><?php esc_html_e( 'Subir Backup Externo (Chunking Upload)', 'oscarpx-backup-restore' ); ?></h2>
\t\t\t\t\t<p class="description">
\t\t\t\t\t\t<?php esc_html_e( 'Sube archivos .zip de hasta 2 GB+ en fragmentos de 1 MB mediante File.slice() para superar límites bajos de upload_max_filesize (ej. 2M).', 'oscarpx-backup-restore' ); ?>
\t\t\t\t\t</p>
\t\t\t\t\t<div id="oscarpx-dropzone" class="oscarpx-dropzone" tabindex="0">
\t\t\t\t\t\t<p><strong><?php esc_html_e( 'Arrastra aquí un archivo .zip o selecciónalo manualmente', 'oscarpx-backup-restore' ); ?></strong></p>
\t\t\t\t\t\t<input type="file" id="oscarpx-upload-input" accept=".zip,application/zip" />
\t\t\t\t\t\t<p class="description" id="oscarpx-upload-status"></p>
\t\t\t\t\t</div>
\t\t\t\t\t<div id="oscarpx-upload-track" class="oscarpx-progress-track" style="display:none;">
\t\t\t\t\t\t<div id="oscarpx-upload-bar" class="oscarpx-progress-fill" style="width:0%;">0%</div>
\t\t\t\t\t</div>

\t\t\t\t\t<hr />

\t\t\t\t\t<h2><?php esc_html_e( 'Backups Almacenados en wp-content/oscarpx-backups/', 'oscarpx-backup-restore' ); ?></h2>
\t\t\t\t\t<div id="oscarpx-manager-notice" class="notice inline" style="display:none;"><p></p></div>

\t\t\t\t\t<div id="oscarpx-inline-restore-confirm" class="notice notice-warning inline" style="display:none;">
\t\t\t\t\t\t<p>
\t\t\t\t\t\t\t<strong><?php esc_html_e( 'Confirmar Restauración Anticaídas:', 'oscarpx-backup-restore' ); ?></strong>
\t\t\t\t\t\t\t<span id="oscarpx-confirm-filename"></span>
\t\t\t\t\t\t</p>
\t\t\t\t\t\t<p>
\t\t\t\t\t\t\t<label for="oscarpx-manager-target-url"><?php esc_html_e( 'URL de Destino (Search & Replace):', 'oscarpx-backup-restore' ); ?></label>
\t\t\t\t\t\t\t<input type="url" id="oscarpx-manager-target-url" class="regular-text code" value="<?php echo esc_attr( untrailingslashit( home_url() ) ); ?>" />
\t\t\t\t\t\t</p>
\t\t\t\t\t\t<p>
\t\t\t\t\t\t\t<button type="button" id="oscarpx-confirm-restore-btn" class="button button-primary"><?php esc_html_e( 'Confirmar e Iniciar Restauración Segura', 'oscarpx-backup-restore' ); ?></button>
\t\t\t\t\t\t\t<button type="button" id="oscarpx-cancel-restore-btn" class="button"><?php esc_html_e( 'Cancelar', 'oscarpx-backup-restore' ); ?></button>
\t\t\t\t\t\t</p>
\t\t\t\t\t</div>

\t\t\t\t\t<table id="oscarpx-backups-table" class="wp-list-table widefat fixed striped">
\t\t\t\t\t\t<thead>
\t\t\t\t\t\t\t<tr>
\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Nombre del archivo', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Fecha de creación', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Peso en MB', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Acciones', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t</tr>
\t\t\t\t\t\t</thead>
\t\t\t\t\t\t<tbody>
\t\t\t\t\t\t\t<?php if ( empty( $backups ) ) : ?>
\t\t\t\t\t\t\t\t<tr class="oscarpx-empty-row">
\t\t\t\t\t\t\t\t\t<td colspan="4"><?php esc_html_e( 'No se encontraron archivos .zip en wp-content/oscarpx-backups/.', 'oscarpx-backup-restore' ); ?></td>
\t\t\t\t\t\t\t\t</tr>
\t\t\t\t\t\t\t<?php else : ?>
\t\t\t\t\t\t\t\t<?php foreach ( $backups as $item ) : ?>
\t\t\t\t\t\t\t\t\t<tr data-file="<?php echo esc_attr( $item['name'] ); ?>">
\t\t\t\t\t\t\t\t\t\t<td><code><?php echo esc_html( $item['name'] ); ?></code></td>
\t\t\t\t\t\t\t\t\t\t<td><?php echo esc_html( wp_date( 'Y-m-d H:i:s', $item['mtime'] ) ); ?></td>
\t\t\t\t\t\t\t\t\t\t<td><?php echo esc_html( number_format_i18n( $item['size'] / 1048576, 2 ) . ' MB' ); ?></td>
\t\t\t\t\t\t\t\t\t\t<td>
\t\t\t\t\t\t\t\t\t\t\t<a href="<?php echo esc_url( $this->get_secure_download_url( $item['name'] ) ); ?>" class="button button-secondary oscarpx-download-btn">
\t\t\t\t\t\t\t\t\t\t\t\t<?php esc_html_e( 'Descargar', 'oscarpx-backup-restore' ); ?>
\t\t\t\t\t\t\t\t\t\t\t</a>
\t\t\t\t\t\t\t\t\t\t\t<button type="button" class="button button-primary oscarpx-restore-row-btn" data-file="<?php echo esc_attr( $item['name'] ); ?>">
\t\t\t\t\t\t\t\t\t\t\t\t<?php esc_html_e( 'Restaurar', 'oscarpx-backup-restore' ); ?>
\t\t\t\t\t\t\t\t\t\t\t</button>
\t\t\t\t\t\t\t\t\t\t\t<button type="button" class="button button-link-delete oscarpx-delete-btn" data-file="<?php echo esc_attr( $item['name'] ); ?>">
\t\t\t\t\t\t\t\t\t\t\t\t<?php esc_html_e( 'Eliminar', 'oscarpx-backup-restore' ); ?>
\t\t\t\t\t\t\t\t\t\t\t</button>
\t\t\t\t\t\t\t\t\t\t</td>
\t\t\t\t\t\t\t\t\t</tr>
\t\t\t\t\t\t\t\t<?php endforeach; ?>
\t\t\t\t\t\t\t<?php endif; ?>
\t\t\t\t\t\t</tbody>
\t\t\t\t\t</table>
\t\t\t\t</div>
\t\t\t<?php else : ?>
\t\t\t\t<div class="card oscarpx-card">
\t\t\t\t\t<h2><?php esc_html_e( 'Restaurar desde Archivo .zip Existente', 'oscarpx-backup-restore' ); ?></h2>
\t\t\t\t\t<div class="notice notice-info inline">
\t\t\t\t\t\t<p>
\t\t\t\t\t\t\t<strong><?php esc_html_e( 'Sistema Anticaídas Activo:', 'oscarpx-backup-restore' ); ?></strong>
\t\t\t\t\t\t\t<?php esc_html_e( 'Se bloquea la sobrescritura de wp-config.php y .htaccess, se activa .maintenance (wp_maintenance()) hasta concluir Search & Replace, y el SQL se inyecta mediante $wpdb por fragmentos de baja RAM.', 'oscarpx-backup-restore' ); ?>
\t\t\t\t\t\t</p>
\t\t\t\t\t</div>
\t\t\t\t\t<?php if ( empty( $backups ) ) : ?>
\t\t\t\t\t\t<div class="notice notice-warning inline">
\t\t\t\t\t\t\t<p><?php esc_html_e( 'No se encontraron archivos .zip en wp-content/oscarpx-backups/. Crea o sube un backup primero.', 'oscarpx-backup-restore' ); ?></p>
\t\t\t\t\t\t</div>
\t\t\t\t\t<?php else : ?>
\t\t\t\t\t\t<table class="wp-list-table widefat fixed striped">
\t\t\t\t\t\t\t<thead>
\t\t\t\t\t\t\t\t<tr>
\t\t\t\t\t\t\t\t\t<th scope="col" class="check-column"></th>
\t\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Archivo de Respaldo (.zip)', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Peso en MB', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Fecha de Creación', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t\t\t<th scope="col"><?php esc_html_e( 'Acciones', 'oscarpx-backup-restore' ); ?></th>
\t\t\t\t\t\t\t\t</tr>
\t\t\t\t\t\t\t</thead>
\t\t\t\t\t\t\t<tbody>
\t\t\t\t\t\t\t\t<?php foreach ( $backups as $idx => $item ) : ?>
\t\t\t\t\t\t\t\t\t<tr data-file="<?php echo esc_attr( $item['name'] ); ?>">
\t\t\t\t\t\t\t\t\t\t<th scope="row" class="check-column">
\t\t\t\t\t\t\t\t\t\t\t<input type="radio" name="oscarpx_selected_backup" value="<?php echo esc_attr( $item['name'] ); ?>" <?php checked( 0, $idx ); ?> />
\t\t\t\t\t\t\t\t\t\t</th>
\t\t\t\t\t\t\t\t\t\t<td><code><?php echo esc_html( $item['name'] ); ?></code></td>
\t\t\t\t\t\t\t\t\t\t<td><?php echo esc_html( number_format_i18n( $item['size'] / 1048576, 2 ) . ' MB' ); ?></td>
\t\t\t\t\t\t\t\t\t\t<td><?php echo esc_html( wp_date( 'Y-m-d H:i:s', $item['mtime'] ) ); ?></td>
\t\t\t\t\t\t\t\t\t\t<td>
\t\t\t\t\t\t\t\t\t\t\t<a href="<?php echo esc_url( $this->get_secure_download_url( $item['name'] ) ); ?>" class="button button-secondary oscarpx-download-btn">
\t\t\t\t\t\t\t\t\t\t\t\t<?php esc_html_e( 'Descargar', 'oscarpx-backup-restore' ); ?>
\t\t\t\t\t\t\t\t\t\t\t</a>
\t\t\t\t\t\t\t\t\t\t\t<button type="button" class="button button-link-delete oscarpx-delete-btn" data-file="<?php echo esc_attr( $item['name'] ); ?>">
\t\t\t\t\t\t\t\t\t\t\t\t<?php esc_html_e( 'Eliminar', 'oscarpx-backup-restore' ); ?>
\t\t\t\t\t\t\t\t\t\t\t</button>
\t\t\t\t\t\t\t\t\t\t</td>
\t\t\t\t\t\t\t\t\t</tr>
\t\t\t\t\t\t\t\t<?php endforeach; ?>
\t\t\t\t\t\t\t</tbody>
\t\t\t\t\t\t</table>
\t\t\t\t\t\t<table class="form-table" role="presentation">
\t\t\t\t\t\t\t<tbody>
\t\t\t\t\t\t\t\t<tr>
\t\t\t\t\t\t\t\t\t<th scope="row">
\t\t\t\t\t\t\t\t\t\t<label for="oscarpx-target-url"><?php esc_html_e( 'URL de Destino (Search & Replace)', 'oscarpx-backup-restore' ); ?></label>
\t\t\t\t\t\t\t\t\t</th>
\t\t\t\t\t\t\t\t\t<td>
\t\t\t\t\t\t\t\t\t\t<input type="url" id="oscarpx-target-url" class="regular-text code" value="<?php echo esc_attr( untrailingslashit( home_url() ) ); ?>" />
\t\t\t\t\t\t\t\t\t\t<p class="description"><?php esc_html_e( 'El modo .maintenance permanecerá activo hasta completar el Search & Replace final con esta URL.', 'oscarpx-backup-restore' ); ?></p>
\t\t\t\t\t\t\t\t\t</td>
\t\t\t\t\t\t\t\t</tr>
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
\t * Escanea el directorio wp-content/oscarpx-backups/ con scandir() nativo y devuelve los .zip válidos.
\t *
\t * @return array
\t */
\tprivate function list_available_backups() {
\t\t$list = array();
\t\tif ( ! is_dir( OSCARPX_BR_BACKUP_DIR ) ) {
\t\t\treturn $list;
\t\t}

\t\t$entries = @scandir( OSCARPX_BR_BACKUP_DIR );
\t\tif ( is_array( $entries ) ) {
\t\t\tforeach ( $entries as $entry ) {
\t\t\t\tif ( '.' === $entry || '..' === $entry ) {
\t\t\t\t\tcontinue;
\t\t\t\t}
\t\t\t\t$filepath = OSCARPX_BR_BACKUP_DIR . $entry;
\t\t\t\tif ( is_file( $filepath ) && ! is_wp_error( OscarPx_Security::sanitize_zip_filename( $entry ) ) ) {
\t\t\t\t\t$list[] = array(
\t\t\t\t\t\t'name'  => $entry,
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

\t/**
\t * Construye la URL firmada con Nonce hacia admin-post.php?action=download_oscarpx_backup.
\t *
\t * @param string $filename Nombre del archivo .zip.
\t * @return string
\t */
\tprivate function get_secure_download_url( $filename ) {
\t\t$base_url = add_query_arg(
\t\t\tarray(
\t\t\t\t'action' => 'download_oscarpx_backup',
\t\t\t\t'file'   => rawurlencode( (string) $filename ),
\t\t\t),
\t\t\tadmin_url( 'admin-post.php' )
\t\t);

\t\treturn wp_nonce_url( $base_url, 'oscarpx_download_backup_nonce' );
\t}

\t/* -------------------------------------------------------------------------
\t * ENDPOINTS AJAX - BACKUP
\t * ---------------------------------------------------------------------- */

\tpublic function ajax_start_backup() {
\t\tOscarPx_Security::verify_ajax_request();
\t\t$dir = OscarPx_Security::ensure_backup_directory();
\t\tif ( is_wp_error( $dir ) ) {
\t\t\tOscarPx_Security::send_json_error( $dir->get_error_message() );
\t\t}

\t\t$raw_type    = isset( $_POST['backup_type'] ) ? sanitize_key( wp_unslash( $_POST['backup_type'] ) ) : 'completo';
\t\t$backup_type = ( 'solo-bd' === $raw_type ) ? 'solo-bd' : 'completo';
\t\t$job_id      = gmdate( 'Ymd-His' ) . '-' . wp_generate_password( 6, false, false );
\t\t$temp_dir    = OscarPx_Security::get_job_temp_dir( $job_id );
\t\tif ( is_wp_error( $temp_dir ) ) {
\t\t\tOscarPx_Security::send_json_error( $temp_dir->get_error_message() );
\t\t}

\t\t$db_engine = new OscarPx_DB_Engine();
\t\t$tables    = $db_engine->get_all_tables();
\t\t$sql_file  = $temp_dir . 'database-backup.sql';
\t\t$init      = $db_engine->init_sql_dump( $sql_file );

\t\tif ( is_wp_error( $init ) ) {
\t\t\tOscarPx_Security::send_json_error( $init->get_error_message() );
\t\t}

\t\t// Nomenclatura Única, Dinámica y Cronológica: {nombre-sitio-sanitizado}-{tipo-backup}_{Y-m-d_H-i-s}.zip
\t\t$zip_name = OscarPx_Security::build_backup_filename( $backup_type );
\t\tif ( is_wp_error( $zip_name ) ) {
\t\t\tOscarPx_Security::send_json_error( $zip_name->get_error_message() );
\t\t}

\t\t$raw_exclusions = isset( $_POST['exclusions'] ) ? wp_unslash( $_POST['exclusions'] ) : '';
\t\tOscarPx_Security::write_job_state(
\t\t\t$temp_dir,
\t\t\tarray(
\t\t\t\t'tables'      => $tables,
\t\t\t\t'zip_name'    => $zip_name,
\t\t\t\t'backup_type' => $backup_type,
\t\t\t\t'exclusions'  => $raw_exclusions,
\t\t\t)
\t\t);

\t\tOscarPx_Security::send_json_success(
\t\t\tarray(
\t\t\t\t'job_id'       => $job_id,
\t\t\t\t'zip_name'     => $zip_name,
\t\t\t\t'backup_type'  => $backup_type,
\t\t\t\t'total_tables' => count( $tables ),
\t\t\t)
\t\t);
\t}

\tpublic function ajax_process_db_chunk() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id      = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$table_index = isset( $_POST['table_index'] ) ? absint( $_POST['table_index'] ) : 0;
\t\t$row_offset  = isset( $_POST['row_offset'] ) ? absint( $_POST['row_offset'] ) : 0;
\t\t$temp_dir    = OscarPx_Security::get_job_temp_dir( $job_id );
\t\t$job         = is_wp_error( $temp_dir ) ? null : OscarPx_Security::read_job_state( $temp_dir );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Sesión de backup expirada o inválida.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$db_engine = new OscarPx_DB_Engine();
\t\t$res       = $db_engine->export_chunk( $temp_dir . 'database-backup.sql', $job['tables'], $table_index, $row_offset );

\t\tif ( is_wp_error( $res ) ) {
\t\t\tOscarPx_Security::send_json_error( $res->get_error_message() );
\t\t}

\t\tOscarPx_Security::send_json_success( $res );
\t}

\tpublic function ajax_scan_files() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id   = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$temp_dir = OscarPx_Security::get_job_temp_dir( $job_id );
\t\t$job      = is_wp_error( $temp_dir ) ? null : OscarPx_Security::read_job_state( $temp_dir );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Sesión de backup inválida.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$backup_type = isset( $job['backup_type'] ) ? $job['backup_type'] : 'completo';
\t\tif ( 'solo-bd' === $backup_type ) {
\t\t\t@file_put_contents( $temp_dir . 'manifest.txt', '' );
\t\t\t$scan = array(
\t\t\t\t'total_files' => 0,
\t\t\t\t'skipped'     => 0,
\t\t\t);
\t\t} else {
\t\t\t$file_engine = new OscarPx_File_Engine();
\t\t\t$rules       = $file_engine->parse_exclusion_rules( $job['exclusions'] );
\t\t\t$scan        = $file_engine->build_manifest( $temp_dir . 'manifest.txt', $rules );
\t\t}

\t\tif ( is_wp_error( $scan ) ) {
\t\t\tOscarPx_Security::send_json_error( $scan->get_error_message() );
\t\t}

\t\t$job['total_files'] = $scan['total_files'];
\t\tOscarPx_Security::write_job_state( $temp_dir, $job );

\t\tOscarPx_Security::send_json_success( $scan );
\t}

\tpublic function ajax_process_zip_chunk() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id      = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$line_offset = isset( $_POST['line_offset'] ) ? absint( $_POST['line_offset'] ) : 0;
\t\t$temp_dir    = OscarPx_Security::get_job_temp_dir( $job_id );
\t\t$job         = is_wp_error( $temp_dir ) ? null : OscarPx_Security::read_job_state( $temp_dir );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Sesión de empaquetado inválida.', 'oscarpx-backup-restore' ) );
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
\t\t\tOscarPx_Security::send_json_error( $res->get_error_message() );
\t\t}

\t\tif ( ! empty( $res['done'] ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\t$res['zip_name'] = $job['zip_name'];
\t\t\t$res['zip_size'] = size_format( (int) @filesize( $zip_path ), 2 );
\t\t}

\t\tOscarPx_Security::send_json_success( $res );
\t}

\t/* -------------------------------------------------------------------------
\t * ENDPOINTS AJAX - RESTAURACIÓN SEGURA (SISTEMA ANTICAÍDAS)
\t * ---------------------------------------------------------------------- */

\tpublic function ajax_start_restore() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$raw_file   = isset( $_POST['filename'] ) ? $_POST['filename'] : '';
\t\t$target_url = isset( $_POST['target_url'] ) ? esc_url_raw( wp_unslash( $_POST['target_url'] ) ) : untrailingslashit( home_url() );
\t\t$zip_path   = OscarPx_Security::resolve_existing_backup_path( $raw_file );
\t\tif ( is_wp_error( $zip_path ) ) {
\t\t\tOscarPx_Security::send_json_error( $zip_path->get_error_message() );
\t\t}

\t\t$restore = new OscarPx_Restore_Engine();
\t\t$info    = $restore->inspect_archive( $zip_path );
\t\tif ( is_wp_error( $info ) ) {
\t\t\tOscarPx_Security::send_json_error( $info->get_error_message() );
\t\t}

\t\t$job_id   = 'restore-' . gmdate( 'YmdHis' ) . '-' . wp_generate_password( 6, false, false );
\t\t$temp_dir = OscarPx_Security::get_job_temp_dir( $job_id );
\t\tif ( is_wp_error( $temp_dir ) ) {
\t\t\tOscarPx_Security::send_json_error( $temp_dir->get_error_message() );
\t\t}

\t\t// Regla 2 (Aislamiento): crear .maintenance en raíz (compatible con wp_maintenance()) ANTES del primer lote AJAX.
\t\t$maint_key = wp_generate_password( 24, false, false );
\t\t$maint_res = OscarPx_Security::enable_maintenance_mode( $maint_key );
\t\tif ( is_wp_error( $maint_res ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\tOscarPx_Security::send_json_error( $maint_res->get_error_message() );
\t\t}

\t\t$current_uid    = get_current_user_id();
\t\t$session_tokens = '';
\t\tif ( $current_uid ) {
\t\t\tglobal $wpdb;
\t\t\t$raw_tokens = $wpdb->get_var(
\t\t\t\t$wpdb->prepare(
\t\t\t\t\t"SELECT meta_value FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key = 'session_tokens' LIMIT 1",
\t\t\t\t\t$current_uid
\t\t\t\t)
\t\t\t);
\t\t\tif ( is_string( $raw_tokens ) ) {
\t\t\t\t$session_tokens = $raw_tokens;
\t\t\t}
\t\t}

\t\tOscarPx_Security::write_job_state(
\t\t\t$temp_dir,
\t\t\tarray(
\t\t\t\t'zip_name'       => basename( $zip_path ),
\t\t\t\t'total_entries'  => $info['total_entries'],
\t\t\t\t'user_id'        => $current_uid,
\t\t\t\t'session_tokens' => $session_tokens,
\t\t\t\t'target_url'     => untrailingslashit( $target_url ? $target_url : home_url() ),
\t\t\t\t'maint_key'      => $maint_key,
\t\t\t)
\t\t);

\t\tOscarPx_Security::send_json_success(
\t\t\tarray(
\t\t\t\t'job_id'        => $job_id,
\t\t\t\t'total_entries' => $info['total_entries'],
\t\t\t\t'maint_key'     => $maint_key,
\t\t\t\t'maintenance'   => true,
\t\t\t)
\t\t);
\t}

\tpublic function ajax_process_extract_chunk() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id      = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$entry_index = isset( $_POST['entry_index'] ) ? absint( $_POST['entry_index'] ) : 0;
\t\t$temp_dir    = OscarPx_Security::get_job_temp_dir( $job_id );
\t\t$job         = is_wp_error( $temp_dir ) ? null : OscarPx_Security::read_job_state( $temp_dir );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Sesión de restauración inválida o expirada.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$zip_path = OscarPx_Security::resolve_existing_backup_path( $job['zip_name'] );
\t\tif ( is_wp_error( $zip_path ) ) {
\t\t\tOscarPx_Security::send_json_error( $zip_path->get_error_message() );
\t\t}

\t\t$restore = new OscarPx_Restore_Engine();
\t\t$res     = $restore->extract_chunk( $zip_path, $temp_dir, $entry_index );

\t\tif ( is_wp_error( $res ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\tOscarPx_Security::send_json_error( $res->get_error_message() );
\t\t}

\t\tOscarPx_Security::send_json_success( $res );
\t}

\tpublic function ajax_process_sql_chunk() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id      = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$byte_offset = isset( $_POST['byte_offset'] ) ? absint( $_POST['byte_offset'] ) : 0;
\t\t$temp_dir    = OscarPx_Security::get_job_temp_dir( $job_id );
\t\t$job         = is_wp_error( $temp_dir ) ? null : OscarPx_Security::read_job_state( $temp_dir );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Sesión SQL inválida.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$sql_file = trailingslashit( $temp_dir ) . 'stage/database-backup.sql';
\t\t$restore  = new OscarPx_Restore_Engine();

\t\tif ( 0 === $byte_offset && empty( $job['source_url'] ) ) {
\t\t\t$job['source_url'] = $restore->detect_source_url_from_dump( $sql_file );
\t\t\tOscarPx_Security::write_job_state( $temp_dir, $job );
\t\t}

\t\t$res = $restore->restore_db_chunk(
\t\t\t$sql_file,
\t\t\t$byte_offset,
\t\t\tarray(
\t\t\t\t'user_id'        => isset( $job['user_id'] ) ? (int) $job['user_id'] : 0,
\t\t\t\t'session_tokens' => isset( $job['session_tokens'] ) ? (string) $job['session_tokens'] : '',
\t\t\t)
\t\t);

\t\tif ( is_wp_error( $res ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\tOscarPx_Security::send_json_error( $res->get_error_message() );
\t\t}

\t\tOscarPx_Security::send_json_success( $res );
\t}

\tpublic function ajax_build_apply_manifest() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id   = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$temp_dir = OscarPx_Security::get_job_temp_dir( $job_id );
\t\t$job      = is_wp_error( $temp_dir ) ? null : OscarPx_Security::read_job_state( $temp_dir );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Sesión de aplicación inválida.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$restore = new OscarPx_Restore_Engine();
\t\t$info    = $restore->build_apply_manifest( $temp_dir );
\t\tif ( is_wp_error( $info ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\tOscarPx_Security::send_json_error( $info->get_error_message() );
\t\t}

\t\t$job['apply_total_files'] = $info['total_files'];
\t\tOscarPx_Security::write_job_state( $temp_dir, $job );

\t\tOscarPx_Security::send_json_success( $info );
\t}

\tpublic function ajax_process_apply_chunk() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id      = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$line_offset = isset( $_POST['line_offset'] ) ? absint( $_POST['line_offset'] ) : 0;
\t\t$temp_dir    = OscarPx_Security::get_job_temp_dir( $job_id );
\t\t$job         = is_wp_error( $temp_dir ) ? null : OscarPx_Security::read_job_state( $temp_dir );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Sesión de aplicación inválida.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$restore     = new OscarPx_Restore_Engine();
\t\t$total_files = isset( $job['apply_total_files'] ) ? (int) $job['apply_total_files'] : 0;
\t\t$res         = $restore->apply_stage_chunk( $temp_dir, $line_offset, $total_files );

\t\tif ( is_wp_error( $res ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\tOscarPx_Security::send_json_error( $res->get_error_message() );
\t\t}

\t\tOscarPx_Security::send_json_success( $res );
\t}

\tpublic function ajax_process_search_replace_chunk() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$job_id      = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
\t\t$table_index = isset( $_POST['table_index'] ) ? absint( $_POST['table_index'] ) : 0;
\t\t$row_offset  = isset( $_POST['row_offset'] ) ? absint( $_POST['row_offset'] ) : 0;
\t\t$temp_dir    = OscarPx_Security::get_job_temp_dir( $job_id );
\t\t$job         = is_wp_error( $temp_dir ) ? null : OscarPx_Security::read_job_state( $temp_dir );

\t\tif ( ! is_array( $job ) || is_wp_error( $temp_dir ) ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Sesión de Search & Replace inválida.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$source_url = isset( $job['source_url'] ) ? (string) $job['source_url'] : '';
\t\t$target_url = isset( $job['target_url'] ) ? (string) $job['target_url'] : untrailingslashit( home_url() );

\t\t$restore = new OscarPx_Restore_Engine();
\t\t$res     = $restore->search_replace_chunk( $source_url, $target_url, $table_index, $row_offset );

\t\t// Regla 2: eliminar .maintenance automáticamente SOLO cuando el último paso (Search & Replace) finaliza con éxito.
\t\tif ( ! empty( $res['done'] ) ) {
\t\t\tOscarPx_Security::disable_maintenance_mode();
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\t$res['maintenance_disabled'] = true;
\t\t}

\t\tOscarPx_Security::send_json_success( $res );
\t}

\t/**
\t * Recibe fragmentos (chunks) enviados mediante File.slice() y los ensambla en wp-content/oscarpx-backups/.
\t */
\tpublic function ajax_upload_backup_chunk() {
\t\tOscarPx_Security::verify_ajax_request();

\t\t$dir = OscarPx_Security::ensure_backup_directory();
\t\tif ( is_wp_error( $dir ) ) {
\t\t\tOscarPx_Security::send_json_error( $dir->get_error_message() );
\t\t}

\t\t$upload_id    = isset( $_POST['upload_id'] ) ? preg_replace( '/[^a-zA-Z0-9_-]/', '', wp_unslash( $_POST['upload_id'] ) ) : '';
\t\t$raw_filename = isset( $_POST['filename'] ) ? wp_unslash( $_POST['filename'] ) : '';
\t\t$chunk_index  = isset( $_POST['chunk_index'] ) ? absint( $_POST['chunk_index'] ) : 0;
\t\t$total_chunks = isset( $_POST['total_chunks'] ) ? absint( $_POST['total_chunks'] ) : 1;

\t\tif ( empty( $upload_id ) || $total_chunks < 1 || $chunk_index >= $total_chunks ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Parámetros de fragmento inválidos.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$safe_name = OscarPx_Security::sanitize_zip_filename( $raw_filename );
\t\tif ( is_wp_error( $safe_name ) ) {
\t\t\tOscarPx_Security::send_json_error( $safe_name->get_error_message() );
\t\t}

\t\tif ( empty( $_FILES['chunk'] ) || ! isset( $_FILES['chunk']['tmp_name'] ) || UPLOAD_ERR_OK !== (int) $_FILES['chunk']['error'] ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Error al recibir el fragmento ZIP.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$tmp_chunk = $_FILES['chunk']['tmp_name'];
\t\tif ( ! is_uploaded_file( $tmp_chunk ) ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Origen de subida inválido.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t$temp_dir = OscarPx_Security::get_job_temp_dir( 'upload-' . $upload_id );
\t\tif ( is_wp_error( $temp_dir ) ) {
\t\t\tOscarPx_Security::send_json_error( $temp_dir->get_error_message() );
\t\t}

\t\t$part_path = trailingslashit( $temp_dir ) . $safe_name . '.part';
\t\t$in_handle = @fopen( $tmp_chunk, 'rb' );
\t\tif ( ! $in_handle ) {
\t\t\tOscarPx_Security::send_json_error( __( 'No se pudo leer el fragmento temporal.', 'oscarpx-backup-restore' ) );
\t\t}

\t\t// En el primer fragmento verificamos firma mágica PKZIP (0x50 0x4B).
\t\tif ( 0 === $chunk_index ) {
\t\t\t$magic = fread( $in_handle, 2 );
\t\t\tif ( 'PK' !== $magic ) {
\t\t\t\tfclose( $in_handle );
\t\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\t\tOscarPx_Security::send_json_error( __( 'El archivo seleccionado no es un ZIP válido.', 'oscarpx-backup-restore' ) );
\t\t\t}
\t\t\trewind( $in_handle );
\t\t}

\t\t$out_mode   = ( 0 === $chunk_index ) ? 'wb' : 'ab';
\t\t$out_handle = @fopen( $part_path, $out_mode );
\t\tif ( ! $out_handle ) {
\t\t\tfclose( $in_handle );
\t\t\tOscarPx_Security::send_json_error( __( 'No se pudo escribir el fragmento en el servidor.', 'oscarpx-backup-restore' ) );
\t\t}

\t\twhile ( ! feof( $in_handle ) ) {
\t\t\t$buffer = fread( $in_handle, 65536 );
\t\t\tif ( false !== $buffer && '' !== $buffer ) {
\t\t\t\tfwrite( $out_handle, $buffer );
\t\t\t}
\t\t}

\t\tfclose( $in_handle );
\t\tfclose( $out_handle );

\t\t$is_last = ( $chunk_index + 1 >= $total_chunks );
\t\tif ( ! $is_last ) {
\t\t\tOscarPx_Security::send_json_success(
\t\t\t\tarray(
\t\t\t\t\t'done'         => false,
\t\t\t\t\t'chunk_index'  => $chunk_index,
\t\t\t\t\t'total_chunks' => $total_chunks,
\t\t\t\t)
\t\t\t);
\t\t}

\t\t// Verificar integridad ZIP al ensamblar el último fragmento.
\t\tif ( class_exists( 'ZipArchive' ) ) {
\t\t\t$zip = new ZipArchive();
\t\t\tif ( true !== $zip->open( $part_path ) ) {
\t\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\t\tOscarPx_Security::send_json_error( __( 'El archivo ensamblado no es un ZIP íntegro o está corrupto.', 'oscarpx-backup-restore' ) );
\t\t\t}
\t\t\t$zip->close();
\t\t}

\t\t$final_name = $safe_name;
\t\t$final_path = OSCARPX_BR_BACKUP_DIR . $final_name;
\t\tif ( file_exists( $final_path ) ) {
\t\t\t$stem       = pathinfo( $safe_name, PATHINFO_FILENAME );
\t\t\t$final_name = OscarPx_Security::sanitize_zip_filename( $stem . '-' . gmdate( 'His' ) . '.zip' );
\t\t\t$final_path = OSCARPX_BR_BACKUP_DIR . $final_name;
\t\t}

\t\tif ( ! @rename( $part_path, $final_path ) && ! ( @copy( $part_path, $final_path ) && @unlink( $part_path ) ) ) {
\t\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );
\t\t\tOscarPx_Security::send_json_error( __( 'No se pudo mover el respaldo ensamblado a wp-content/oscarpx-backups/.', 'oscarpx-backup-restore' ) );
\t\t}

\t\tOscarPx_Security::cleanup_temp_dir( $temp_dir );

\t\t$size_bytes = (int) @filesize( $final_path );
\t\t$mtime      = (int) @filemtime( $final_path );

\t\tOscarPx_Security::send_json_success(
\t\t\tarray(
\t\t\t\t'done' => true,
\t\t\t\t'file' => array(
\t\t\t\t\t'name'         => $final_name,
\t\t\t\t\t'size_mb'      => number_format_i18n( $size_bytes / 1048576, 2 ) . ' MB',
\t\t\t\t\t'created_at'   => wp_date( 'Y-m-d H:i:s', $mtime ? $mtime : time() ),
\t\t\t\t\t'download_url' => $this->get_secure_download_url( $final_name ),
\t\t\t\t),
\t\t\t)
\t\t);
\t}

\t/**
\t * Eliminación Segura (AJAX): valida Nonce, permisos manage_options, sanitize_file_name()
\t * y verifica estrictamente con realpath() que el objetivo reside dentro de oscarpx-backups/.
\t */
\tpublic function ajax_delete_backup() {
\t\tOscarPx_Security::verify_ajax_request();

\t\tif ( ! current_user_can( 'manage_options' ) ) {
\t\t\tOscarPx_Security::send_json_error( __( 'Permisos insuficientes.', 'oscarpx-backup-restore' ), 403 );
\t\t}

\t\t$raw_file      = isset( $_POST['filename'] ) ? wp_unslash( (string) $_POST['filename'] ) : '';
\t\t$sanitized     = sanitize_file_name( $raw_file );
\t\t$real_base_dir = realpath( OSCARPX_BR_BACKUP_DIR );
\t\t$real_target   = ( '' !== $sanitized ) ? realpath( OSCARPX_BR_BACKUP_DIR . $sanitized ) : false;

\t\t// Bloqueo estricto contra Directory Traversal (ej. ../../../wp-config.php).
\t\tif (
\t\t\tfalse === $real_base_dir ||
\t\t\tfalse === $real_target ||
\t\t\t0 !== strpos( $real_target, $real_base_dir . DIRECTORY_SEPARATOR ) ||
\t\t\t! is_file( $real_target ) ||
\t\t\t! preg_match( '/\\.zip$/i', $real_target )
\t\t) {
\t\t\tOscarPx_Security::send_json_error(
\t\t\t\t__( 'Ruta bloqueada o archivo fuera de wp-content/oscarpx-backups/.', 'oscarpx-backup-restore' ),
\t\t\t\t403
\t\t\t);
\t\t}

\t\tif ( ! @unlink( $real_target ) ) {
\t\t\tOscarPx_Security::send_json_error( __( 'No se pudo eliminar el archivo de respaldo.', 'oscarpx-backup-restore' ) );
\t\t}

\t\tOscarPx_Security::send_json_success( array( 'deleted' => basename( $real_target ) ) );
\t}

\t/**
\t * Puente de Descarga Segura (admin_post_download_oscarpx_backup):
\t * Transmite archivos .zip protegidos por .htaccess mediante streaming PHP (fread) sin agotar memory_limit.
\t */
\tpublic function handle_download_backup() {
\t\t$nonce = isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '';
\t\tif ( ! wp_verify_nonce( $nonce, 'oscarpx_download_backup_nonce' ) ) {
\t\t\twp_die(
\t\t\t\tesc_html__( 'Token de seguridad (Nonce) inválido o expirado.', 'oscarpx-backup-restore' ),
\t\t\t\tesc_html__( 'Acceso denegado', 'oscarpx-backup-restore' ),
\t\t\t\tarray( 'response' => 403 )
\t\t\t);
\t\t}

\t\tif ( ! current_user_can( 'manage_options' ) ) {
\t\t\twp_die(
\t\t\t\tesc_html__( 'No tienes permisos suficientes (manage_options).', 'oscarpx-backup-restore' ),
\t\t\t\tesc_html__( 'Acceso denegado', 'oscarpx-backup-restore' ),
\t\t\t\tarray( 'response' => 403 )
\t\t\t);
\t\t}

\t\t$raw_file      = isset( $_GET['file'] ) ? wp_unslash( rawurldecode( (string) $_GET['file'] ) ) : '';
\t\t$sanitized     = sanitize_file_name( $raw_file );
\t\t$real_base_dir = realpath( OSCARPX_BR_BACKUP_DIR );
\t\t$real_target   = ( '' !== $sanitized ) ? realpath( OSCARPX_BR_BACKUP_DIR . $sanitized ) : false;

\t\tif (
\t\t\tfalse === $real_base_dir ||
\t\t\tfalse === $real_target ||
\t\t\t0 !== strpos( $real_target, $real_base_dir . DIRECTORY_SEPARATOR ) ||
\t\t\t! is_file( $real_target ) ||
\t\t\t! is_readable( $real_target ) ||
\t\t\t! preg_match( '/\\.zip$/i', $real_target )
\t\t) {
\t\t\twp_die(
\t\t\t\tesc_html__( 'Archivo no encontrado o acceso bloqueado por Path Traversal.', 'oscarpx-backup-restore' ),
\t\t\t\tesc_html__( 'Archivo inválido', 'oscarpx-backup-restore' ),
\t\t\t\tarray( 'response' => 403 )
\t\t\t);
\t\t}

\t\t$filename  = basename( $real_target );
\t\t$file_size = filesize( $real_target );

\t\tif ( function_exists( 'set_time_limit' ) ) {
\t\t\t@set_time_limit( 0 );
\t\t}
\t\tif ( function_exists( 'apache_setenv' ) ) {
\t\t\t@apache_setenv( 'no-gzip', '1' );
\t\t}
\t\t@ini_set( 'zlib.output_compression', 'Off' );

\t\t// Limpiar búferes de salida antes de enviar cabeceras y stream binario.
\t\tif ( ob_get_level() > 0 ) {
\t\t\t@ob_clean();
\t\t}
\t\twhile ( ob_get_level() > 0 ) {
\t\t\t@ob_end_clean();
\t\t}
\t\tflush();

\t\tnocache_headers();
\t\theader( 'Content-Description: File Transfer' );
\t\theader( 'Content-Type: application/zip' );
\t\theader( 'Content-Disposition: attachment; filename="' . str_replace( '"', '', $filename ) . '"' );
\t\theader( 'Content-Transfer-Encoding: binary' );
\t\tif ( false !== $file_size ) {
\t\t\theader( 'Content-Length: ' . $file_size );
\t\t}

\t\t// Lectura por fragmentos de 1 MB (fread) para evitar agotar memory_limit con archivos pesados.
\t\t$handle = @fopen( $real_target, 'rb' );
\t\tif ( ! $handle ) {
\t\t\twp_die(
\t\t\t\tesc_html__( 'No se pudo abrir el archivo de respaldo para streaming.', 'oscarpx-backup-restore' ),
\t\t\t\tesc_html__( 'Error de lectura', 'oscarpx-backup-restore' ),
\t\t\t\tarray( 'response' => 500 )
\t\t\t);
\t\t}

\t\twhile ( ! feof( $handle ) ) {
\t\t\t$chunk = fread( $handle, 1048576 );
\t\t\tif ( false === $chunk ) {
\t\t\t\tbreak;
\t\t\t}
\t\t\techo $chunk; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
\t\t\tflush();
\t\t}

\t\tfclose( $handle );
\t\texit;
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

  function postAjax(action, params, attempt) {
    var retry = typeof attempt === 'number' ? attempt : 0;
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
        return res.text().then(function (rawText) {
          var parsed = null;
          try {
            parsed = JSON.parse(rawText);
          } catch (e) {
            // Reintentar ante respuestas HTML transitorias (502/503/504 o bloqueo momentáneo del servidor).
            if (retry < 2 && (res.status >= 500 || rawText.indexOf('<') !== -1)) {
              return new Promise(function (resolve) {
                setTimeout(function () {
                  resolve(postAjax(action, params, retry + 1));
                }, 1200);
              });
            }
            var plain = rawText.replace(/<[^>]+>/g, ' ').replace(/\\s+/g, ' ').trim().slice(0, 220);
            throw new Error('HTTP ' + res.status + ' (respuesta no JSON en ' + action + '): ' + (plain || 'Sin detalle'));
          }

          if (!parsed || !parsed.success) {
            var errMsg = (parsed && parsed.data && parsed.data.message)
              ? parsed.data.message
              : ('Error inesperado en AJAX (' + action + ').');
            throw new Error(errMsg);
          }
          return parsed.data;
        });
      });
  }

  /* ---- FLUJO DE CREACIÓN DE BACKUP POR LOTES ---- */
  var startBackupBtn = document.getElementById('oscarpx-start-backup-btn');
  if (startBackupBtn) {
    startBackupBtn.addEventListener('click', function () {
      var exclusionsEl = document.getElementById('oscarpx-exclusions');
      var typeEl = document.getElementById('oscarpx-backup-type');
      var exclusions = exclusionsEl ? exclusionsEl.value : '';
      var backupType = typeEl ? typeEl.value : 'completo';

      startBackupBtn.disabled = true;
      showProgress('Creando Copia de Seguridad (' + backupType + ')...');
      appendLog('Inicializando directorio seguro wp-content/oscarpx-backups/...');

      postAjax('oscarpx_start_backup', { exclusions: exclusions, backup_type: backupType })
        .then(function (startData) {
          appendLog('Archivo asignado: ' + startData.zip_name + ' | Tablas: ' + startData.total_tables);
          return runDbChunk(startData.job_id, 0, 0, startData.total_tables);
        })
        .then(function (jobId) {
          if (backupType === 'solo-bd') {
            appendLog('Modo Solo Base de Datos: omitiendo escaneo de wp-content y empaquetando .sql...');
          } else {
            appendLog('Escaneando wp-content y wp-config.php aplicando exclusiones...');
          }
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

  /* ---- FLUJO DE RESTAURACIÓN SEGURA (SISTEMA ANTICAÍDAS) ---- */
  function startRestoreFlow(filename, targetUrl) {
    if (!filename) return;
    var startRestoreBtn = document.getElementById('oscarpx-start-restore-btn');
    if (startRestoreBtn) startRestoreBtn.disabled = true;

    showProgress('Restaurando Backup (Sistema Anticaídas): ' + filename);
    appendLog('Verificando integridad de ' + filename + '...');

    postAjax('oscarpx_start_restore', { filename: filename, target_url: targetUrl || '' })
      .then(function (data) {
        var maintKey = data.maint_key || '';
        appendLog('Modo mantenimiento activado (.maintenance / wp_maintenance()) para bloquear tráfico y cronjobs.');
        appendLog('Archivo verificado (' + data.total_entries + ' entradas). Extrayendo a staging (bloqueando wp-config.php y .htaccess)...');
        return runExtractChunk(data.job_id, maintKey, 0, data.total_entries).then(function () {
          return { jobId: data.job_id, maintKey: maintKey };
        });
      })
      .then(function (ctx) {
        appendLog('Extracción en staging completa. Inyectando SQL Hot Swap en fragmentos vía $wpdb...');
        setProgress(38);
        return runSqlChunk(ctx.jobId, ctx.maintKey, 0).then(function () {
          return ctx;
        });
      })
      .then(function (ctx) {
        appendLog('Base de datos restaurada. Indexando archivos staging (wp-config.php y .htaccess protegidos)...');
        setProgress(68);
        return postAjax('oscarpx_build_apply_manifest', {
          job_id: ctx.jobId,
          oscarpx_maint_key: ctx.maintKey,
        }).then(function (info) {
          appendLog('Aplicando ' + info.total_files + ' archivos al sitio...');
          return runApplyChunk(ctx.jobId, ctx.maintKey, 0, info.total_files).then(function () {
            return ctx;
          });
        });
      })
      .then(function (ctx) {
        appendLog('Ejecutando Search & Replace final en $wpdb...');
        setProgress(88);
        return runSearchReplaceChunk(ctx.jobId, ctx.maintKey, 0, 0);
      })
      .then(function () {
        setProgress(100);
        appendLog('Search & Replace finalizado. Archivo .maintenance eliminado automáticamente.');
        appendLog('Restauración segura completada con éxito.');
        if (startRestoreBtn) startRestoreBtn.disabled = false;
      })
      .catch(function (err) {
        appendLog('ERROR: ' + err.message);
        if (startRestoreBtn) startRestoreBtn.disabled = false;
      });
  }

  var startRestoreBtn = document.getElementById('oscarpx-start-restore-btn');
  if (startRestoreBtn) {
    startRestoreBtn.addEventListener('click', function () {
      var selected = document.querySelector('input[name="oscarpx_selected_backup"]:checked');
      if (!selected) return;

      var filename = selected.value;
      var targetUrlEl = document.getElementById('oscarpx-target-url');
      var targetUrl = targetUrlEl ? targetUrlEl.value : '';
      startRestoreFlow(filename, targetUrl);
    });
  }

  function runExtractChunk(jobId, maintKey, entryIndex, totalEntries) {
    return postAjax('oscarpx_process_extract_chunk', {
      job_id: jobId,
      oscarpx_maint_key: maintKey,
      entry_index: entryIndex,
    }).then(function (res) {
      var blockedNote = (res.blocked_core && res.blocked_core.length > 0)
        ? ' [Protección core: bloqueados ' + res.blocked_core.join(', ') + ']'
        : '';
      appendLog('Staging: extraídos ' + res.extracted + ' archivos (' + res.next_index + '/' + totalEntries + ').' + blockedNote);
      var pct = totalEntries > 0 ? (res.next_index / totalEntries) * 36 : 36;
      setProgress(pct);
      if (res.done) return jobId;
      return runExtractChunk(jobId, maintKey, res.next_index, totalEntries);
    });
  }

  function runSqlChunk(jobId, maintKey, byteOffset) {
    return postAjax('oscarpx_process_sql_chunk', {
      job_id: jobId,
      oscarpx_maint_key: maintKey,
      byte_offset: byteOffset,
    }).then(function (res) {
      appendLog('Hot Swap $wpdb: ' + res.executed + ' sentencias ejecutadas.');
      var pct = res.total_bytes > 0 ? 38 + (res.next_offset / res.total_bytes) * 28 : 66;
      setProgress(pct);
      if (res.done) return jobId;
      return runSqlChunk(jobId, maintKey, res.next_offset);
    });
  }

  function runApplyChunk(jobId, maintKey, lineOffset, totalFiles) {
    return postAjax('oscarpx_process_apply_chunk', {
      job_id: jobId,
      oscarpx_maint_key: maintKey,
      line_offset: lineOffset,
    }).then(function (res) {
      appendLog('Aplicados ' + res.applied + ' archivos (' + res.next_offset + '/' + totalFiles + ').');
      var pct = totalFiles > 0 ? 68 + (res.next_offset / totalFiles) * 20 : 88;
      setProgress(pct);
      if (res.done) return res;
      return runApplyChunk(jobId, maintKey, res.next_offset, totalFiles);
    });
  }

  function runSearchReplaceChunk(jobId, maintKey, tableIndex, rowOffset) {
    return postAjax('oscarpx_process_search_replace_chunk', {
      job_id: jobId,
      oscarpx_maint_key: maintKey,
      table_index: tableIndex,
      row_offset: rowOffset,
    }).then(function (res) {
      appendLog(res.message);
      var pct = res.total > 0 ? 88 + (res.table_index / res.total) * 12 : 100;
      setProgress(pct);
      if (res.done) return res;
      return runSearchReplaceChunk(jobId, maintKey, res.table_index, res.row_offset);
    });
  }

  /* ---- GESTOR DE BACKUPS: SUBIDA POR FRAGMENTOS (File.slice), ELIMINACIÓN AJAX Y RESTAURACIÓN ---- */
  function showManagerNotice(message, isError) {
    var box = document.getElementById('oscarpx-manager-notice');
    if (!box) return;
    box.className = 'notice inline ' + (isError ? 'notice-error' : 'notice-success');
    box.style.display = 'block';
    box.querySelector('p').textContent = message;
  }

  function createBackupRow(fileObj) {
    var tr = document.createElement('tr');
    tr.setAttribute('data-file', fileObj.name);

    var tdName = document.createElement('td');
    var code = document.createElement('code');
    code.textContent = fileObj.name;
    tdName.appendChild(code);

    var tdDate = document.createElement('td');
    tdDate.textContent = fileObj.created_at;

    var tdSize = document.createElement('td');
    tdSize.textContent = fileObj.size_mb;

    var tdActions = document.createElement('td');
    if (fileObj.download_url) {
      var downloadLink = document.createElement('a');
      downloadLink.href = fileObj.download_url;
      downloadLink.className = 'button button-secondary oscarpx-download-btn';
      downloadLink.textContent = 'Descargar';
      tdActions.appendChild(downloadLink);
      tdActions.appendChild(document.createTextNode(' '));
    }

    var restoreBtn = document.createElement('button');
    restoreBtn.type = 'button';
    restoreBtn.className = 'button button-primary oscarpx-restore-row-btn';
    restoreBtn.setAttribute('data-file', fileObj.name);
    restoreBtn.textContent = 'Restaurar';

    var deleteBtn = document.createElement('button');
    deleteBtn.type = 'button';
    deleteBtn.className = 'button button-link-delete oscarpx-delete-btn';
    deleteBtn.setAttribute('data-file', fileObj.name);
    deleteBtn.textContent = 'Eliminar';

    tdActions.appendChild(restoreBtn);
    tdActions.appendChild(document.createTextNode(' '));
    tdActions.appendChild(deleteBtn);

    tr.appendChild(tdName);
    tr.appendChild(tdDate);
    tr.appendChild(tdSize);
    tr.appendChild(tdActions);
    return tr;
  }

  var backupsTable = document.getElementById('oscarpx-backups-table');
  var pendingRestoreFile = null;
  var confirmBox = document.getElementById('oscarpx-inline-restore-confirm');
  var confirmFileEl = document.getElementById('oscarpx-confirm-filename');
  var confirmRestoreBtn = document.getElementById('oscarpx-confirm-restore-btn');
  var cancelRestoreBtn = document.getElementById('oscarpx-cancel-restore-btn');

  if (cancelRestoreBtn && confirmBox) {
    cancelRestoreBtn.addEventListener('click', function () {
      pendingRestoreFile = null;
      confirmBox.style.display = 'none';
    });
  }

  if (confirmRestoreBtn && confirmBox) {
    confirmRestoreBtn.addEventListener('click', function () {
      if (!pendingRestoreFile) return;
      var targetInput = document.getElementById('oscarpx-manager-target-url');
      var targetUrl = targetInput ? targetInput.value : '';
      var chosen = pendingRestoreFile;
      pendingRestoreFile = null;
      confirmBox.style.display = 'none';
      startRestoreFlow(chosen, targetUrl);
    });
  }

  // Delegación de eventos para Eliminar (AJAX sin recargar) y Restaurar desde la tabla.
  document.addEventListener('click', function (ev) {
    var deleteBtn = ev.target && ev.target.closest ? ev.target.closest('.oscarpx-delete-btn') : null;
    if (deleteBtn) {
      var fileToDelete = deleteBtn.getAttribute('data-file');
      if (!fileToDelete) return;
      deleteBtn.disabled = true;
      deleteBtn.textContent = 'Eliminando...';

      postAjax('oscarpx_delete_backup', { filename: fileToDelete })
        .then(function (res) {
          var row = deleteBtn.closest('tr');
          if (row && row.parentNode) {
            row.parentNode.removeChild(row);
          }
          if (backupsTable) {
            var tbody = backupsTable.querySelector('tbody');
            if (tbody && tbody.querySelectorAll('tr').length === 0) {
              var emptyTr = document.createElement('tr');
              emptyTr.className = 'oscarpx-empty-row';
              var td = document.createElement('td');
              td.colSpan = 4;
              td.textContent = 'No se encontraron archivos .zip en wp-content/oscarpx-backups/.';
              emptyTr.appendChild(td);
              tbody.appendChild(emptyTr);
            }
          }
          showManagerNotice('Backup eliminado de forma segura: ' + res.deleted, false);
        })
        .catch(function (err) {
          deleteBtn.disabled = false;
          deleteBtn.textContent = 'Eliminar';
          showManagerNotice(err.message, true);
        });
      return;
    }

    var restoreRowBtn = ev.target && ev.target.closest ? ev.target.closest('.oscarpx-restore-row-btn') : null;
    if (restoreRowBtn && confirmBox && confirmFileEl) {
      pendingRestoreFile = restoreRowBtn.getAttribute('data-file');
      confirmFileEl.textContent = pendingRestoreFile || '';
      confirmBox.style.display = 'block';
    }
  });

  // Módulo de Subida por Fragmentos (File.slice() de 1 MB por petición AJAX).
  var dropzone = document.getElementById('oscarpx-dropzone');
  var uploadInput = document.getElementById('oscarpx-upload-input');
  var uploadTrack = document.getElementById('oscarpx-upload-track');
  var uploadBar = document.getElementById('oscarpx-upload-bar');
  var uploadStatus = document.getElementById('oscarpx-upload-status');
  var UPLOAD_CHUNK_BYTES = 1048576; // 1 MB por fragmento para servidores con upload_max_filesize = 2M.

  function uploadFileInChunks(file) {
    if (!file || !/\\.zip$/i.test(file.name)) {
      showManagerNotice('Selecciona un archivo con extensión .zip válida.', true);
      return;
    }

    var totalChunks = Math.max(1, Math.ceil(file.size / UPLOAD_CHUNK_BYTES));
    var uploadId = 'up-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
    if (uploadTrack) uploadTrack.style.display = 'block';

    function sendChunk(index) {
      var start = index * UPLOAD_CHUNK_BYTES;
      var end = Math.min(file.size, start + UPLOAD_CHUNK_BYTES);
      var blob = file.slice(start, end);
      var pct = Math.round(((index + 1) / totalChunks) * 100);

      if (uploadStatus) {
        uploadStatus.textContent = 'Subiendo ' + file.name + ' — fragmento ' + (index + 1) + ' de ' + totalChunks + ' (' + pct + '%)...';
      }
      if (uploadBar) {
        uploadBar.style.width = pct + '%';
        uploadBar.textContent = pct + '%';
      }

      return postAjax('oscarpx_upload_backup_chunk', {
        upload_id: uploadId,
        filename: file.name,
        chunk_index: index,
        total_chunks: totalChunks,
        chunk: blob,
      }).then(function (res) {
        if (res.done && res.file) {
          if (backupsTable) {
            var tbody = backupsTable.querySelector('tbody');
            var emptyRow = tbody ? tbody.querySelector('.oscarpx-empty-row') : null;
            if (emptyRow) tbody.removeChild(emptyRow);
            if (tbody) tbody.insertBefore(createBackupRow(res.file), tbody.firstChild);
          }
          if (uploadStatus) uploadStatus.textContent = 'Subida completada: ' + res.file.name + ' (' + res.file.size_mb + ').';
          showManagerNotice('Backup externo subido y ensamblado: ' + res.file.name, false);
          return;
        }
        return sendChunk(index + 1);
      });
    }

    sendChunk(0).catch(function (err) {
      if (uploadStatus) uploadStatus.textContent = 'Error en subida: ' + err.message;
      showManagerNotice(err.message, true);
    });
  }

  if (uploadInput) {
    uploadInput.addEventListener('change', function () {
      if (uploadInput.files && uploadInput.files[0]) {
        uploadFileInChunks(uploadInput.files[0]);
      }
    });
  }

  if (dropzone) {
    dropzone.addEventListener('dragover', function (e) {
      e.preventDefault();
      dropzone.classList.add('is-dragover');
    });
    dropzone.addEventListener('dragleave', function () {
      dropzone.classList.remove('is-dragover');
    });
    dropzone.addEventListener('drop', function (e) {
      e.preventDefault();
      dropzone.classList.remove('is-dragover');
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
        uploadFileInChunks(e.dataTransfer.files[0]);
      }
    });
  }
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

.oscarpx-dropzone {
  border: 2px dashed #8c8f94;
  background: #f6f7f7;
  padding: 20px;
  text-align: center;
  border-radius: 3px;
  margin: 12px 0;
  transition: border-color 0.15s ease, background-color 0.15s ease;
}

.oscarpx-dropzone.is-dragover {
  border-color: #2271b1;
  background: #f0f6fc;
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
