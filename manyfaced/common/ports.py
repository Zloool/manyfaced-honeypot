"""Shared port constants for honeypot configuration.

Extracted from config.py and client.py to avoid duplication.
"""

# Default top 50 ports for --top-ports mode (extracted to avoid duplication)
DEFAULT_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 5901, 6379, 8080, 8443,
    9200, 11211, 27017, 5672, 15672, 4369, 2181, 9090, 8888, 7001, 7002,
    11300, 11301, 11302, 11303, 11304, 11305, 11306, 11307, 11308, 11309,
    11310, 11311, 5000,
]

PORT_MODES = ('single', 'top', 'all')
