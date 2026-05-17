"""Drupal routes — canonical CMS endpoints."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route


def _drupal() -> type:
    from manyfaced.handlers.drupal_handler import DrupalHandler

    return DrupalHandler


ROUTES: list[Route] = [
    # ---- Drupal (canonical CMS endpoints) ------------------------------------
    Route(PathExact('/user'), _drupal(), 1, 'drupal_user'),
    Route(PathPrefix('/user/'), _drupal(), 1, 'drupal_user_slash'),
    Route(PathExact('/user/login'), _drupal(), 1, 'drupal_user_login'),
    Route(PathExact('/user/register'), _drupal(), 1, 'drupal_user_register'),
    Route(PathExact('/admin'), _drupal(), 1, 'drupal_admin'),
    Route(PathPrefix('/admin/'), _drupal(), 1, 'drupal_admin_slash'),
    Route(PathExact('/admin/config'), _drupal(), 1, 'drupal_admin_config'),
    Route(PathExact('/node'), _drupal(), 1, 'drupal_node'),
    Route(PathPrefix('/node/'), _drupal(), 1, 'drupal_node_slash'),
    Route(PathExact('/sites'), _drupal(), 1, 'drupal_sites'),
    Route(PathPrefix('/sites/'), _drupal(), 1, 'drupal_sites_slash'),
    Route(
        PathExact('/sites/default'),
        _drupal(),
        1,
        'drupal_sites_default',
    ),
    # /xmlrpc.php already claimed by WordPress above — Drupal's pattern is
    # intentionally omitted here (overlap resolution: WordPress wins).
    Route(PathExact('/drupal'), _drupal(), 1, 'drupal_drupal'),
    Route(PathPrefix('/drupal/'), _drupal(), 1, 'drupal_drupal_slash'),
    Route(PathExact('/cgi-bin'), _drupal(), 1, 'drupal_cgi_bin'),
    Route(PathPrefix('/cgi-bin/'), _drupal(), 1, 'drupal_cgi_bin_slash'),
    # /files — Drupal wins (overlap: WebDAV also claims it; separate brief)
    Route(PathExact('/files'), _drupal(), 1, 'drupal_files'),
    Route(PathPrefix('/files/'), _drupal(), 1, 'drupal_files_slash'),
]
