"""
This is a dictionary of '/request_address':'filename'. So, for an easy cases we
can just get data from file, concatinate it with default server banned and send
back to client.
"""
faces = {
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
    '/MyAdmin/scripts/setup.php': 'phpadminsetup.php',
    '/myadmin/scripts/setup.php': 'phpadminsetup.php',
    '/phpMyAdmin/scripts/setup.php': 'phpadminsetup.php',
    '/pma/scripts/setup.php': 'phpadminsetup.php',
    '//phpmyadmin/scripts/setup.php': 'phpadminsetup.php',
    '//pma/scripts/setup.php': 'phpadminsetup.php',
    '/phpmyadmin/scripts/setup.php': 'phpadminsetup.php',
    '/phpMyAdmin': 'phpadmin.php',
    '/phpmyadmin': 'phpadmin.php',
    '/phpmyadmon': 'phpadmin.php',
    '/WEBDAV/': 'webdav.xml',
    '/webdav/': 'webdav.xml',
    '/bitrix/admin/index.php?lang=en': 'bitrix.html',
    '/robots.txt': 'robots',
    '/wp-content': 'wp-content.html',
    '/cases': '../cases.txt',
    '/2phpmyadmin/': 'phpadmin.php',
    '/admin/db/': 'phpadmin.php',
    '/admin/index.php?route=common/login': 'phpadmin.php',
    '/admin/login.php': 'phpadmin.php',
    '/admin/phpmyadmin/': 'phpadmin.php',
    '/admin/phpMyAdmin/': 'phpadmin.php',
    '/admin/pMA/': 'phpadmin.php',
    '/admin/sqladmin/': 'phpadmin.php',
    '/admin/sysadmin/': 'phpadmin.php',
    '/admin/web/': 'phpadmin.php',
    '/administrator/admin/': 'phpadmin.php',
    '/administrator/db/': 'phpadmin.php',
    '/administrator/index.php': 'phpadmin.php',
    '/administrator/phpmyadmin/': 'phpadmin.php',
    '/administrator/phpMyAdmin/': 'phpadmin.php',
    '/administrator/PMA/': 'phpadmin.php',
    '/administrator/pma/': 'phpadmin.php',
    '/administrator/web/': 'phpadmin.php',
    '/database/': 'phpadmin.php',
    '/db/': 'phpadmin.php',
    '/db/db-admin/': 'phpadmin.php',
    '/db/dbadmin/': 'phpadmin.php',
    '/db/dbweb/': 'phpadmin.php',
    '/db/myadmin/': 'phpadmin.php',
    '/db/phpMyAdmin3/': 'phpadmin.php',
    '/db/phpmyadmin3/': 'phpadmin.php',
    '/db/phpMyAdmin-3/': 'phpadmin.php',
    '/db/phpmyadmin/': 'phpadmin.php',
    '/db/phpMyAdmin/': 'phpadmin.php',
    '/db/webadmin/': 'phpadmin.php',
    '/db/webdb/': 'phpadmin.php',
    '/db/websql/': 'phpadmin.php',
    '/myadmin/': 'phpadmin.php',
    '/MyAdmin/': 'phpadmin.php',
    '/mysql-admin/': 'phpadmin.php',
    '/mysql/': 'phpadmin.php',
    '/mysql/admin/': 'phpadmin.php',
    '/mysql/db/': 'phpadmin.php',
    '/mysql/mysqlmanager/': 'phpadmin.php',
    '/mysql/dbadmin/': 'phpadmin.php',
    '/mysql/pma/': 'phpadmin.php',
    '/mysql/pMA/': 'phpadmin.php',
    '/mysql/sqlmanager/': 'phpadmin.php',
    '/mysql/web/': 'phpadmin.php',
    '/mysqladmin/': 'phpadmin.php',
    '/mysqlmanager/': 'phpadmin.php',
    '/php-my-admin/': 'phpadmin.php',
    '/php-myadmin/': 'phpadmin.php',
    '/phpmanager/': 'phpadmin.php',
    '/phpmy-admin/': 'phpadmin.php',
    '/phpmy/': 'phpadmin.php',
    '/phpmyadmin2/': 'phpadmin.php',
    '/phpMyAdmin2/': 'phpadmin.php',
    '/phpmyadmin3/': 'phpadmin.php',
    '/phpMyAdmin3/': 'phpadmin.php',
    '/phpmyadmin4/': 'phpadmin.php',
    '/phpMyAdmin4/': 'phpadmin.php',
    '/phpMyAdmin-3/': 'phpadmin.php',
    '/phpMyadmin/': 'phpadmin.php',
    '/phpmyAdmin/': 'phpadmin.php',
    '/phpmyadmin/': 'phpadmin.php',
    '/phpMyAdmin/': 'phpadmin.php',
    '/phpmyadmin/index.php': 'phpadmin.php',
    '/phppma/': 'phpadmin.php',
    '/PMA2011/': 'phpadmin.php',
    '/pma2011/': 'phpadmin.php',
    '/pma2012/': 'phpadmin.php',
    '/PMA2012/': 'phpadmin.php',
    '/sql/myadmin/': 'phpadmin.php',
    '/sql/php-myadmin/': 'phpadmin.php',
    '/sql/phpmanager/': 'phpadmin.php',
    '/sql/phpmy-admin/': 'phpadmin.php',
    '/sql/phpMyAdmin2/': 'phpadmin.php',
    '/sql/phpmyadmin2/': 'phpadmin.php',
    '/sql/phpMyAdmin/': 'phpadmin.php',
    '/sql/sql-admin/': 'phpadmin.php',
    '/sql/sql/': 'phpadmin.php',
    '/sql/sqladmin/': 'phpadmin.php',
    '/sql/sqlweb/': 'phpadmin.php',
    '/sql/webadmin/': 'phpadmin.php',
    '/sql/webdb/': 'phpadmin.php',
    '/sql/websql/': 'phpadmin.php',
    '/sqlmanager/': 'phpadmin.php',
    '/pma/': 'phpadmin.php',
    '/PMA/': 'phpadmin.php',
    # robots
    # sitemap
}
