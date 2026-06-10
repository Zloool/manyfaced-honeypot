"""WebDAV routes — WebDAV-specific endpoints."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import WEBDAV_HTTP


def _webdav() -> type:
    from manyfaced.handlers.webdav_handler import WebDAVHandler

    return WebDAVHandler


ROUTES: list[Route] = [
    # ---- WebDAV (canonical WebDAV endpoints) -------------------------------
    Route(PathExact('/webdav'), _webdav(), WEBDAV_HTTP, 'webdav_root'),
    Route(PathPrefix('/webdav/'), _webdav(), WEBDAV_HTTP, 'webdav_root_slash'),
    Route(PathExact('/dav'), _webdav(), WEBDAV_HTTP, 'webdav_dav'),
    Route(PathPrefix('/dav/'), _webdav(), WEBDAV_HTTP, 'webdav_dav_slash'),
    Route(PathExact('/remote.php'), _webdav(), WEBDAV_HTTP, 'webdav_remote_php'),
    Route(PathPrefix('/remote.php/'), _webdav(), WEBDAV_HTTP, 'webdav_remote_php_slash'),
    Route(PathExact('/owncloud'), _webdav(), WEBDAV_HTTP, 'webdav_owncloud'),
    Route(PathPrefix('/owncloud/'), _webdav(), WEBDAV_HTTP, 'webdav_owncloud_slash'),
    Route(PathExact('/caldav'), _webdav(), WEBDAV_HTTP, 'webdav_caldav'),
    Route(PathPrefix('/caldav/'), _webdav(), WEBDAV_HTTP, 'webdav_caldav_slash'),
    Route(PathExact('/carddav'), _webdav(), WEBDAV_HTTP, 'webdav_carddav'),
    Route(PathPrefix('/carddav/'), _webdav(), WEBDAV_HTTP, 'webdav_carddav_slash'),
    Route(PathExact('/web'), _webdav(), WEBDAV_HTTP, 'webdav_web'),
    Route(PathPrefix('/web/'), _webdav(), WEBDAV_HTTP, 'webdav_web_slash'),
]
