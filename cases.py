"""
This is a dictionary of '/request_address':'filename'. So, for an easy cases we
can just get data from file, concatinate it with default server banned and send
back to client.
"""
cases = {
    'zero': 'zero',
    '/': 'zero',
    '/wp-login.php': 'wplogin.html',
    '/favicon.ico': 'favicon.ico',
    '/wp-config.php': 'wpconfig.php',
    '/wp-config.bak': 'wpconfig.php',
    '/wp-config.old': 'wpconfig.php',
    '/wp-config.orig': 'wpconfig.php',
    '/wp-config.original': 'wpconfig.php',
    '/wp-config.php%7E': 'wpconfig.php',
    '/wp-config.php.bak': 'wpconfig.php',
    '/wp-config.php.old': 'wpconfig.php',
    '/wp-config.php.orig': 'wpconfig.php',
    '/wp-config.php.original': 'wpconfig.php',
    '/wp-config.php.save': 'wpconfig.php',
    '/wp-config.php.swo': 'wpconfig.php',
    '/wp-config.php_bak': 'wpconfig.php',
    '/wp-config.php.swp': 'wpconfig.php',
    '/wp-config.save': 'wpconfig.php',
    '/wp-config.txt': 'wpconfig.php',
    '/%23wp-config.php%23': 'wpconfig.php',
    '/MyAdmin/scripts/setup.php': 'wpadminsetup.php',
    '/myadmin/scripts/setup.php': 'wpadminsetup.php',
    '/phpMyAdmin/scripts/setup.php': 'wpadminsetup.php',
    '/pma/scripts/setup.php': 'wpadminsetup.php',
    '/phpMyAdmin': 'wpadmin.php',
    '/phpmyadmin': 'wpadmin.php',
    '/phpmyadmon': 'wpadmin.php',
    '/WEBDAV/': 'webdav.xml',
    '/webdav/': 'webdav.xml',
    '/bitrix/admin/index.php?lang=en': 'bitrix.html',
    '/robots.txt': 'robots',
    '/wp-content': 'wp-content.html',
    # robots
    # sitemap
}
