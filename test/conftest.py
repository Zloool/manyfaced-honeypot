"""
Configure import path and mock dependencies for testing.
"""

import os
import sys
from unittest.mock import MagicMock

# Make manyfaced package importable from project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock geoip before any module that uses it is imported
geoip_mock = MagicMock()
geoip_mock.geolite2.geolite2 = geoip_mock.geolite2
sys.modules['geoip'] = geoip_mock
sys.modules['geoip.geolite2'] = geoip_mock.geolite2
sys.modules['GeoIP'] = MagicMock()
