"""cPanel / WHM routes — hosting control panel endpoints."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import CPANEL_HTTP


def _cpanel() -> type:
    from manyfaced.handlers.cpanel_handler import CPanelHandler

    return CPanelHandler


ROUTES: list[Route] = [
    # ---- cPanel / WHM --------------------------------------------------------
    Route(PathExact('/cpanel'), _cpanel(), CPANEL_HTTP, 'cpanel_cpanel'),
    Route(PathPrefix('/cpanel/'), _cpanel(), CPANEL_HTTP, 'cpanel_cpanel_slash'),
    Route(
        PathExact('/cpanel/hotlinkprotect'),
        _cpanel(),
        1,
        'cpanel_hotlinkprotect',
    ),
    Route(PathExact('/whm'), _cpanel(), CPANEL_HTTP, 'cpanel_whm'),
    Route(PathPrefix('/whm/'), _cpanel(), CPANEL_HTTP, 'cpanel_whm_slash'),
    Route(PathExact('/whm/login'), _cpanel(), CPANEL_HTTP, 'cpanel_whm_login'),
    Route(PathExact('/webmail'), _cpanel(), CPANEL_HTTP, 'cpanel_webmail'),
    Route(PathPrefix('/webmail/'), _cpanel(), CPANEL_HTTP, 'cpanel_webmail_slash'),
    Route(PathExact('/webmail/login'), _cpanel(), CPANEL_HTTP, 'cpanel_webmail_login'),
    Route(PathExact('/mail'), _cpanel(), CPANEL_HTTP, 'cpanel_mail'),
    Route(PathPrefix('/mail/'), _cpanel(), CPANEL_HTTP, 'cpanel_mail_slash'),
    Route(PathExact('/webdisk'), _cpanel(), CPANEL_HTTP, 'cpanel_webdisk'),
    Route(PathPrefix('/webdisk/'), _cpanel(), CPANEL_HTTP, 'cpanel_webdisk_slash'),
    Route(PathExact('/cpsess'), _cpanel(), CPANEL_HTTP, 'cpanel_cpsess'),
    Route(PathExact('/setup1'), _cpanel(), CPANEL_HTTP, 'cpanel_setup1'),
    Route(PathPrefix('/setup1/'), _cpanel(), CPANEL_HTTP, 'cpanel_setup1_slash'),
    Route(PathExact('/~'), _cpanel(), CPANEL_HTTP, 'cpanel_tilde'),
]
