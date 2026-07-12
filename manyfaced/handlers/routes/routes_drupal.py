"""Drupal routes — canonical CMS endpoints."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import DRUPAL_HTTP


def _drupal() -> type:
    from manyfaced.handlers.drupal_handler import DrupalHandler

    return DrupalHandler


ROUTES: list[Route] = [
    # ---- Drupal (canonical CMS endpoints) ------------------------------------
    Route(PathExact('/user'), _drupal(), DRUPAL_HTTP, 'drupal_user'),
    Route(PathPrefix('/user/'), _drupal(), DRUPAL_HTTP, 'drupal_user_slash'),
    Route(PathExact('/user/login'), _drupal(), DRUPAL_HTTP, 'drupal_user_login'),
    Route(PathExact('/user/register'), _drupal(), DRUPAL_HTTP, 'drupal_user_register'),
    Route(PathExact('/admin'), _drupal(), DRUPAL_HTTP, 'drupal_admin'),
    # NOTE: the previous greedy `PathPrefix('/admin/')` shadowed non-Drupal
    # probes nested under /admin/ — PHPUnit eval-stdin RCE
    # (/admin/vendor/phpunit/...) and config/env disclosure (/admin/.env,
    # /admin/phpinfo.php). Drupal only serves a handful of real admin
    # sections, so we enumerate those explicitly (issue #503/#506/#508).
    Route(PathPrefix('/admin/content/'), _drupal(), DRUPAL_HTTP, 'drupal_admin_content'),
    Route(PathPrefix('/admin/structure/'), _drupal(), DRUPAL_HTTP, 'drupal_admin_structure'),
    Route(PathPrefix('/admin/config/'), _drupal(), DRUPAL_HTTP, 'drupal_admin_config_prefix'),
    Route(PathPrefix('/admin/people/'), _drupal(), DRUPAL_HTTP, 'drupal_admin_people'),
    Route(PathPrefix('/admin/modules/'), _drupal(), DRUPAL_HTTP, 'drupal_admin_modules'),
    Route(PathPrefix('/admin/themes/'), _drupal(), DRUPAL_HTTP, 'drupal_admin_themes'),
    Route(PathPrefix('/admin/reports/'), _drupal(), DRUPAL_HTTP, 'drupal_admin_reports'),
    Route(PathPrefix('/admin/appearance/'), _drupal(), DRUPAL_HTTP, 'drupal_admin_appearance'),
    Route(PathPrefix('/admin/help/'), _drupal(), DRUPAL_HTTP, 'drupal_admin_help'),
    Route(PathPrefix('/admin/tasks/'), _drupal(), DRUPAL_HTTP, 'drupal_admin_tasks'),
    Route(PathExact('/admin/config'), _drupal(), DRUPAL_HTTP, 'drupal_admin_config'),
    Route(PathExact('/node'), _drupal(), DRUPAL_HTTP, 'drupal_node'),
    Route(PathPrefix('/node/'), _drupal(), DRUPAL_HTTP, 'drupal_node_slash'),
    Route(PathExact('/sites'), _drupal(), DRUPAL_HTTP, 'drupal_sites'),
    Route(PathPrefix('/sites/'), _drupal(), DRUPAL_HTTP, 'drupal_sites_slash'),
    Route(
        PathExact('/sites/default'),
        _drupal(),
        1,
        'drupal_sites_default',
    ),
    # /xmlrpc.php already claimed by WordPress above — Drupal's pattern is
    # intentionally omitted here (overlap resolution: WordPress wins).
    Route(PathExact('/drupal'), _drupal(), DRUPAL_HTTP, 'drupal_drupal'),
    Route(PathPrefix('/drupal/'), _drupal(), DRUPAL_HTTP, 'drupal_drupal_slash'),
    # NOTE: Drupal has no /cgi-bin endpoints. The previous `PathExact('/cgi-bin')`
    # and `PathPrefix('/cgi-bin/')` routes shadowed ExploitCgiHandler (which
    # handles D-Link/Tenda/GeoServer/Mozi CGI RCE probes). Those routes are
    # removed so /cgi-bin/* reaches ExploitCgiHandler (issue #505).
    # /files — Drupal wins (overlap: WebDAV also claims it; separate brief)
    Route(PathExact('/files'), _drupal(), DRUPAL_HTTP, 'drupal_files'),
    Route(PathPrefix('/files/'), _drupal(), DRUPAL_HTTP, 'drupal_files_slash'),
]
