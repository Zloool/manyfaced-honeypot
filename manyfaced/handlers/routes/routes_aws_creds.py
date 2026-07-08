"""AWS routes (scaffold). TODO: refine to match real probe paths."""

from __future__ import annotations

from manyfaced.handlers.router import PathExact, PathPrefix, Route

from manyfaced.common.status import AWS_HTTP


def _aws_creds() -> type:
    from manyfaced.handlers.aws_creds_handler import AWSHandler

    return AWSHandler


ROUTES: list[Route] = [
    # ---- AWS (issue #285) ----
    Route(PathExact('/.aws/credentials'), _aws_creds(), AWS_HTTP, 'aws_creds_0'),
    Route(PathPrefix('/.aws/credentials/'), _aws_creds(), AWS_HTTP, 'aws_creds_prefix_0'),
    Route(PathExact('/aws/credentials'), _aws_creds(), AWS_HTTP, 'aws_creds_1'),
    Route(PathPrefix('/aws/credentials/'), _aws_creds(), AWS_HTTP, 'aws_creds_prefix_1'),
    Route(PathExact('/.env.aws'), _aws_creds(), AWS_HTTP, 'aws_creds_2'),
]
