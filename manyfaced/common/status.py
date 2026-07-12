UNKNOWN_HTTP = 4294967294
SSH_CLIENT = 4294967293
UNKNOWN_NON_HTTP = 4294967292
EMPTY_CONNECTION = 4294967291  # Zero-byte connection (port scan, no data sent)
UNKNOWN_DNS = 4294967290  # DNS-over-TCP probe
UNKNOWN_MONGODB = 4294967289  # MongoDB wire protocol probe
UNKNOWN_REDIS = 4294967288  # Redis RESP protocol probe
UNKNOWN_TLS = 4294967287  # TLS ClientHello (handshake)
UNKNOWN_SMB = 4294967286  # SMB/NBT (NetBIOS Session Service) probe
UNKNOWN_TELNET = 4294967285  # Telnet probe
UNKNOWN_RDP = 4294967284  # RDP probe
UNKNOWN_VNC = 4294967283  # VNC probe
# SIP/SNMP are UDP-only probes — the honeypot had no UDP transport before the
# UDP face work (issue #388), so these IDs are added there. The next free
# descending values below FINGERPRINT_PROBE (4294967282) are used to keep the
# high non-HTTP ID space contiguous.
UNKNOWN_SIP = 4294967281  # SIP (Session Initiation Protocol) UDP probe
UNKNOWN_SNMP = 4294967280  # SNMP (Simple Network Management Protocol) UDP probe
FINGERPRINT_PROBE = (
    4294967282  # High-entropy random-path honeypot-fingerprinting probe (issue #324)
)

# HTTP service-specific detected IDs (for routing to service handlers)
WORDPRESS_HTTP = 1001
PHPMYADMIN_HTTP = 1002
JENKINS_HTTP = 1003
TOMCAT_HTTP = 1004
DRUPAL_HTTP = 1005
CPANEL_HTTP = 1006
BITRIX_HTTP = 1007
WEBDAV_HTTP = 1008
CONFIG_DISCLOSURE_HTTP = 1009

BOT_TIMEOUT = 5
CLIENT_TIMEOUT = 2

# Scaffolded 'Add missing handler' faces (issues #272-#298)
THINKPHP_HTTP = 1010
LARAVEL_HTTP = 1011
ZABBIX_HTTP = 1012
ELASTIC_HTTP = 1013
GITLAB_HTTP = 1014
RABBITMQ_HTTP = 1015
JUPYTER_HTTP = 1016
PLEX_HTTP = 1017
GRAFANA_HTTP = 1018
SOLR_HTTP = 1019
REDIS_ADMIN_HTTP = 1020
MAGENTO_HTTP = 1021
SQUID_HTTP = 1022
HNAP_HTTP = 1023
AWS_HTTP = 1024
SPRING_HTTP = 1025
ATLASSIAN_HTTP = 1026
NEXTJS_HTTP = 1027
KUBERNETES_HTTP = 1028
NGINX_PROBE_HTTP = 1029
IOT_HTTP = 1030
MCP_HTTP = 1031
DOCKER_HTTP = 1032
DBADMIN_HTTP = 1033
# Env / config disclosure face (issue #272) — scaffold omitted this constant;
# added here so the env_disc handler can import its detected-id per the task spec.
ENV_DISC_HTTP = 1034
# Exploit-scanner honeypot faces (issue #350): D-Link/Tenda CGI RCE (router
# command-injection -> wget malware-drop), pearcmd LFI/RCE, path traversal.
EXPLOIT_CGI_HTTP = 1035
# PHPUnit eval-stdin RCE (CVE-2017-9841). Distinct from ENV_DISC_HTTP
# (1034) so real RCE probes are not mislabeled as env-disclosure captures
# (issue #475). Previously phpunit_handler fell back to 1034, colliding with
# ENV_DISC_HTTP; this constant fixes the detected_id collision.
PHPUNIT_HTTP = 1047
