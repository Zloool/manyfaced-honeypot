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
from manyfaced.handlers.dbadmin_handler import DBAdminHandler
from manyfaced.handlers.docker_handler import DockerHandler
from manyfaced.handlers.mcp_handler import MCPHandler
from manyfaced.handlers.iot_handler import IoTHandler
from manyfaced.handlers.nginx_probe_handler import NginxProbeHandler
from manyfaced.handlers.k8s_handler import KubernetesHandler
from manyfaced.handlers.nextjs_handler import NextjsHandler
from manyfaced.handlers.atlassian_handler import AtlassianHandler
from manyfaced.handlers.spring_handler import SpringHandler
from manyfaced.handlers.aws_creds_handler import AWSHandler
from manyfaced.handlers.hnap_handler import HNAPHandler
from manyfaced.handlers.squid_handler import SquidHandler
from manyfaced.handlers.elastic_handler import ElasticHandler  # noqa: F401
from manyfaced.handlers.env_disc_handler import EnvDiscHandler  # noqa: F401
from manyfaced.handlers.phpunit_handler import PhpUnitHandler  # noqa: F401
from manyfaced.handlers.nginx_handler import NginxHandler  # noqa: F401
from manyfaced.handlers.magento_handler import MagentoHandler
from manyfaced.handlers.redis_admin_handler import RedisAdminHandler
from manyfaced.handlers.solr_handler import SolrHandler
from manyfaced.handlers.grafana_handler import GrafanaHandler
from manyfaced.handlers.plex_handler import PlexHandler
from manyfaced.handlers.jupyter_handler import JupyterHandler
from manyfaced.handlers.rabbitmq_handler import RabbitMQHandler
from manyfaced.handlers.gitlab_handler import GitLabHandler
from manyfaced.handlers.elasticsearch_handler import ElasticsearchHandler
from manyfaced.handlers.zabbix_handler import ZabbixHandler
from manyfaced.handlers.laravel_handler import LaravelHandler
from manyfaced.handlers.thinkphp_handler import ThinkPHPHandler
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
    'DBAdminHandler',
    'DockerHandler',
    'MCPHandler',
    'IoTHandler',
    'NginxProbeHandler',
    'KubernetesHandler',
    'NextjsHandler',
    'AtlassianHandler',
    'SpringHandler',
    'AWSHandler',
    'HNAPHandler',
    'SquidHandler',
    'MagentoHandler',
    'RedisAdminHandler',
    'SolrHandler',
    'GrafanaHandler',
    'PlexHandler',
    'JupyterHandler',
    'RabbitMQHandler',
    'GitLabHandler',
    'ElasticsearchHandler',
    'ZabbixHandler',
    'LaravelHandler',
    'ThinkPHPHandler',
    'GenericHandler',
    'ElasticHandler',
]
