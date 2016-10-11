<?php
/**
 * Custom WordPress configurations on "wp-config.php" file.
 *
 * This file has the following configurations: MySQL settings, Table Prefix, Secret Keys, WordPress Language, ABSPATH and more.
 * For more information visit {@link https://codex.wordpress.org/Editing_wp-config.php Editing wp-config.php} Codex page.
 * Created using {@link http://generatewp.com/wp-config/ wp-config.php File Generator} on GenerateWP.com.
 *
 * @package WordPress
 * @generator GenerateWP.com
 */


/* MySQL settings */
define( 'DB_NAME',     'wpdb' );
define( 'DB_USER',     'root' );
define( 'DB_PASSWORD', 'jadolbaeb' );
define( 'DB_HOST',     'localhost' );
define( 'DB_CHARSET',  'utf8mb4' );


/* MySQL database table prefix. */
$table_prefix = 'wp_';


/* Authentication Unique Keys and Salts. */
/* https://api.wordpress.org/secret-key/1.1/salt/ */
define( 'AUTH_KEY',         '1/U.?g+~_JlDtT=Hc{,J LVa}7pro`UO-T4pY@[iNOJ[lK0I =_d5<Z[`CMa[frO' );
define( 'SECURE_AUTH_KEY',  '2/U.?g+~_JlDtT=Hc{,J LVa}7pro`UO-T4pY@[iNOJ[lK0I =_d5<Z[`CMa[frO' );
define( 'LOGGED_IN_KEY',    '3/U.?g+~_JlDtT=Hc{,J LVa}7pro`UO-T4pY@[iNOJ[lK0I =_d5<Z[`CMa[frO' );
define( 'NONCE_KEY',        '4/U.?g+~_JlDtT=Hc{,J LVa}7pro`UO-T4pY@[iNOJ[lK0I =_d5<Z[`CMa[frO' );
define( 'AUTH_SALT',        '5/U.?g+~_JlDtT=Hc{,J LVa}7pro`UO-T4pY@[iNOJ[lK0I =_d5<Z[`CMa[frO' );
define( 'SECURE_AUTH_SALT', '6/U.?g+~_JlDtT=Hc{,J LVa}7pro`UO-T4pY@[iNOJ[lK0I =_d5<Z[`CMa[frO' );
define( 'LOGGED_IN_SALT',   '7/U.?g+~_JlDtT=Hc{,J LVa}7pro`UO-T4pY@[iNOJ[lK0I =_d5<Z[`CMa[frO' );
define( 'NONCE_SALT',       '8/U.?g+~_JlDtT=Hc{,J LVa}7pro`UO-T4pY@[iNOJ[lK0I =_d5<Z[`CMa[frO' );


/* Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') )
	define('ABSPATH', dirname(__FILE__) . '/');

/* Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');
?>
