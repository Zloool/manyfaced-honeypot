"""WordPress routes — canonical WP endpoints win over Drupal/ConfigDisclosure."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import WORDPRESS_HTTP


def _wp() -> type:
    from manyfaced.handlers.wordpress_handler import WordPressHandler

    return WordPressHandler


ROUTES: list[Route] = [
    # ---- WordPress (canonical WP endpoints win over Drupal/ConfigDisclosure) ---
    Route(PathExact('/wp-login'), _wp(), WORDPRESS_HTTP, 'wordpress_wp_login'),
    Route(PathPrefix('/wp-login.php'), _wp(), WORDPRESS_HTTP, 'wordpress_wp_login_php'),
    Route(PathExact('/wp-admin'), _wp(), WORDPRESS_HTTP, 'wordpress_wp_admin'),
    Route(PathPrefix('/wp-admin/'), _wp(), WORDPRESS_HTTP, 'wordpress_wp_admin_slash'),
    Route(PathExact('/wp-content'), _wp(), WORDPRESS_HTTP, 'wordpress_wp_content'),
    Route(PathPrefix('/wp-content/'), _wp(), WORDPRESS_HTTP, 'wordpress_wp_content_slash'),
    Route(PathExact('/wp-includes'), _wp(), WORDPRESS_HTTP, 'wordpress_wp_includes'),
    Route(PathPrefix('/wp-includes/'), _wp(), WORDPRESS_HTTP, 'wordpress_wp_includes_slash'),
    # /xmlrpc.php — WordPress wins (overlap: Drupal + ConfigDisclosure also claim it)
    Route(PathExact('/xmlrpc.php'), _wp(), WORDPRESS_HTTP, 'wordpress_xmlrpc_php'),
    Route(PathExact('/wordpress'), _wp(), WORDPRESS_HTTP, 'wordpress_wordpress'),
    Route(PathPrefix('/wordpress/'), _wp(), WORDPRESS_HTTP, 'wordpress_wordpress_slash'),
    Route(PathExact('/blog'), _wp(), WORDPRESS_HTTP, 'wordpress_blog'),
    Route(PathPrefix('/blog/'), _wp(), WORDPRESS_HTTP, 'wordpress_blog_slash'),
]
