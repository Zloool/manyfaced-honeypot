"""manyfaced handlers package.

Two handler hierarchies exist:

**Server-side (encrypted messages from client):**
    - BaseHandler: Abstract base for decrypting and routing encrypted messages
    - Used by ServerHandler in server/server.py

**Client-side (raw HTTP from bots):**
    - HTTPHandlerBase: Abstract base for service-specific HTTP handlers
    - HTTPHandler: Main entry point, routes to service handlers via Router
    - Router + Route: Explicit ordered route table for HTTP dispatch
    - BotProfile: Per-bot state tracking for each handler

**Service handlers (client-side):**
    - WordPressHandler: WordPress CMS responses
    - PhpMyAdminHandler: phpMyAdmin responses
    - JenkinsHandler: Jenkins CI/CD responses
    - TomcatHandler: Apache Tomcat responses
    - DrupalHandler: Drupal CMS responses
    - CPanelHandler: cPanel/WHM responses
    - BitrixHandler: 1C-Bitrix CMS responses
    - WebDAVHandler: WebDAV responses
    - ConfigDisclosureHandler: Fake config file disclosures
    - GenericHandler: Default handler for unknown paths (monster page)

**Routing:**
    - Router: Ordered route table, first match wins
    - Route: (matcher, handler_cls, detected_id, name)
    - PathPrefix/PathExact/Any: Matcher implementations
"""

from manyfaced.handlers.base_handler import (
    BaseHandler,
    HTTPHandlerBase,
    BotProfile,
)
from manyfaced.handlers.http_handler import HTTPHandler
from manyfaced.handlers.router import Router, Route, PathPrefix, PathExact, Any

# Service handlers
from manyfaced.handlers.wordpress_handler import WordPressHandler
from manyfaced.handlers.phpmyadmin_handler import PhpMyAdminHandler
from manyfaced.handlers.jenkins_handler import JenkinsHandler
from manyfaced.handlers.tomcat_handler import TomcatHandler
from manyfaced.handlers.drupal_handler import DrupalHandler
from manyfaced.handlers.cpanel_handler import CPanelHandler
from manyfaced.handlers.bitrix_handler import BitrixHandler
from manyfaced.handlers.webdav_handler import WebDAVHandler
from manyfaced.handlers.config_disclosure_handler import ConfigDisclosureHandler
from manyfaced.handlers.generic_handler import GenericHandler

__all__ = [
    # Server-side
    'BaseHandler',
    # Client-side core
    'HTTPHandler',
    'HTTPHandlerBase',
    'Router',
    'Route',
    'PathPrefix',
    'PathExact',
    'Any',
    'BotProfile',
    # Service handlers
    'WordPressHandler',
    'PhpMyAdminHandler',
    'JenkinsHandler',
    'TomcatHandler',
    'DrupalHandler',
    'CPanelHandler',
    'BitrixHandler',
    'WebDAVHandler',
    'ConfigDisclosureHandler',
    'GenericHandler',
]
