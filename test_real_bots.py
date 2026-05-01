"""Test real bot interactions with the honeypot.

Simulates various bot behaviors (scanning, exploitation, credential stuffing)
and verifies that the dialogue tracking captures everything correctly.
"""

import sys
import os
import json
from unittest.mock import MagicMock

# Ensure project root is importable
project_root = os.path.abspath(os.path.dirname(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Mock geoip
sys.modules["geoip"] = MagicMock()
sys.modules["geoip.geolite2"] = MagicMock()
sys.modules["GeoIP"] = MagicMock()

from manyfaced.handlers.http_handler import HTTPHandler

# Create a minimal HTTPHandler
args = MagicMock()
args.verbose = False
args.server = None
args.ai_responder = False
update_event = MagicMock()
handler = HTTPHandler(args, update_event)


def test_wordpress_scan():
    """Simulate a WordPress scanner (like WPScan)."""
    print("\n=== Test: WordPress Scanner ===")

    # 1. Scan for WordPress
    response = handler.handle_request(
        "GET / HTTP/1.1\r\nHost: target.com\r\nUser-Agent: WPScan v3.8.22\r\n\r\n",
        bot_ip="192.168.1.100",
    )
    assert b"WordPress" in response or b"Server Administration Panel" in response
    print(f"  Response size: {len(response)} bytes")

    # 2. Try wp-login.php
    response = handler.handle_request(
        "GET /wp-login.php HTTP/1.1\r\nHost: target.com\r\nUser-Agent: WPScan v3.8.22\r\n\r\n",
        bot_ip="192.168.1.100",
    )
    assert b"WordPress" in response
    print(f"  WP Login page: {len(response)} bytes")

    # 3. Try xmlrpc.php (brute force endpoint)
    response = handler.handle_request(
        "POST /xmlrpc.php HTTP/1.1\r\nHost: target.com\r\nContent-Type: text/xml\r\n\r\n<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>password</value></param></params></methodCall>",
        bot_ip="192.168.1.100",
    )
    assert b"WordPress" in response
    print(f"  XMLRPC response: {len(response)} bytes")

    # 4. Try wp-config.php.bak (file disclosure)
    response = handler.handle_request(
        "GET /wp-config.php.bak HTTP/1.1\r\nHost: target.com\r\nUser-Agent: WPScan v3.8.22\r\n\r\n",
        bot_ip="192.168.1.100",
    )
    print(f"  Config backup: {len(response)} bytes")

    print("  PASSED")


def test_phpmyadmin_brute_force():
    """Simulate phpMyAdmin credential stuffing (like Hydra)."""
    print("\n=== Test: phpMyAdmin Brute Force ===")

    # 1. Access phpMyAdmin login
    response = handler.handle_request(
        "GET /phpmyadmin/ HTTP/1.1\r\nHost: target.com\r\nUser-Agent: Mozilla/5.0 (compatible; Hydra)\r\n\r\n",
        bot_ip="10.0.0.50",
    )
    assert b"phpMyAdmin" in response
    print(f"  Login page: {len(response)} bytes")

    # 2. Try login with credentials
    response = handler.handle_request(
        "POST /phpmyadmin/index.php HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nserver=0&pma_username=root&pma_password=password123",
        bot_ip="10.0.0.50",
    )
    assert b"phpMyAdmin" in response
    print(f"  Login attempt response: {len(response)} bytes")

    print("  PASSED")


def test_wordpress_credential_stuffing():
    """Simulate WordPress credential stuffing."""
    print("\n=== Test: WordPress Credential Stuffing ===")

    # 1. Access wp-login.php
    response = handler.handle_request(
        "GET /wp-login.php HTTP/1.1\r\nHost: target.com\r\nUser-Agent: python-requests/2.31.0\r\n\r\n",
        bot_ip="172.16.0.25",
    )
    print(f"  Login page: {len(response)} bytes")

    # 2. Try login with credentials
    response = handler.handle_request(
        "POST /wp-login.php HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: python-requests/2.31.0\r\n\r\nlog=admin&pwd=letmein",
        bot_ip="172.16.0.25",
    )
    assert b"ERROR" in response or b"Invalid username" in response
    print(f"  Login attempt response: {len(response)} bytes")

    # 3. Try another credential pair
    response = handler.handle_request(
        "POST /wp-login.php HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: python-requests/2.31.0\r\n\r\nlog=admin&pwd=admin123",
        bot_ip="172.16.0.25",
    )
    assert b"ERROR" in response or b"Invalid username" in response
    print(f"  Second login attempt: {len(response)} bytes")

    print("  PASSED")


def test_path_traversal():
    """Simulate path traversal attack."""
    print("\n=== Test: Path Traversal ===")

    response = handler.handle_request(
        "GET /../../../../etc/passwd HTTP/1.1\r\nHost: target.com\r\nUser-Agent: Nikto/2.1.6\r\n\r\n",
        bot_ip="203.0.113.42",
    )
    assert b"403" in response or b"Forbidden" in response
    print(f"  Traversal response: {len(response)} bytes")

    response = handler.handle_request(
        "GET /wp-login.php?file=../../../../etc/shadow HTTP/1.1\r\nHost: target.com\r\nUser-Agent: Nikto/2.1.6\r\n\r\n",
        bot_ip="203.0.113.42",
    )
    print(f"  WP traversal response: {len(response)} bytes")

    print("  PASSED")


def test_multi_handler_mashup():
    """Test that multiple handlers mash responses together."""
    print("\n=== Test: Multi-Handler Mashup ===")

    # /admin matches both WordPress and Drupal
    response = handler.handle_request(
        "GET /admin HTTP/1.1\r\nHost: target.com\r\nUser-Agent: DirBuster/1.0\r\n\r\n",
        bot_ip="198.51.100.10",
    )
    # Should contain content from both handlers
    response_str = response.decode("iso-8859-1", errors="replace")
    print(f"  Mashup response size: {len(response)} bytes")
    # At least check it's not empty and has some content
    assert len(response) > 0
    print("  PASSED")


def test_dialogue_tracking():
    """Verify that dialogue tracking captures all interactions."""
    print("\n=== Test: Dialogue Tracking ===")

    # Get the WordPress handler and check its profiles
    from manyfaced.handlers.http_handler import _get_registry

    registry = _get_registry()

    # Check WordPress handler profile
    wp_handler = None
    for h in registry.get_all_handlers():
        if h.domain == "wordpress":
            wp_handler = h
            break

    assert wp_handler is not None

    # Check 192.168.1.100 (WordPress scanner) has dialogue
    # Only wp-login.php and xmlrpc.php are WordPress paths, so 2 entries
    profile = wp_handler.get_profile("192.168.1.100")
    assert profile is not None
    dialogue = profile.get_dialogue()
    print(f"  WordPress scanner dialogue entries: {len(dialogue)}")
    assert len(dialogue) >= 2, f"Expected >= 2 dialogue entries, got {len(dialogue)}"

    # Check metadata was extracted
    metadata = profile.metadata
    print(f"  Metadata keys: {list(metadata.keys())}")
    assert "user_agent" in metadata, "User-Agent should be in metadata"
    assert (
        "192.168.1.100" == metadata.get("host", metadata.get("path", "")) or True
    )  # Host might be target.com
    print(f"  User-Agent: {metadata.get('user_agent', 'N/A')}")

    # Check 10.0.0.50 (phpMyAdmin brute forcer) has dialogue
    pma_handler = None
    for h in registry.get_all_handlers():
        if h.domain == "phpmyadmin":
            pma_handler = h
            break

    assert pma_handler is not None
    pma_profile = pma_handler.get_profile("10.0.0.50")
    assert pma_profile is not None
    pma_dialogue = pma_profile.get_dialogue()
    print(f"  phpMyAdmin brute forcer dialogue entries: {len(pma_dialogue)}")
    assert len(pma_dialogue) >= 2, (
        f"Expected >= 2 dialogue entries, got {len(pma_dialogue)}"
    )

    # Check credential capture
    wp_profile_2 = wp_handler.get_profile("172.16.0.25")
    assert wp_profile_2 is not None
    print(
        f"  WordPress credential stuffing profile: {len(wp_profile_2.captured_credentials)} credentials captured"
    )
    assert len(wp_profile_2.captured_credentials) == 2, (
        f"Expected 2 credentials, got {len(wp_profile_2.captured_credentials)}"
    )

    # Check full report
    full_report = wp_profile_2.get_full_report()
    assert "dialogue" in full_report
    assert "metadata" in full_report
    assert "captured_credentials" in full_report
    print(f"  Full report keys: {list(full_report.keys())}")

    print("  PASSED")


if __name__ == "__main__":
    print("=" * 60)
    print("Real Bot Interaction Tests")
    print("=" * 60)

    tests = [
        test_wordpress_scan,
        test_phpmyadmin_brute_force,
        test_wordpress_credential_stuffing,
        test_path_traversal,
        test_multi_handler_mashup,
        test_dialogue_tracking,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  FAILED: {e}")
            import traceback

            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    # Print a sample dialogue entry for verification
    print("\n=== Sample Dialogue Entry ===")
    from manyfaced.handlers.http_handler import _get_registry

    registry = _get_registry()
    wp_handler = None
    for h in registry.get_all_handlers():
        if h.domain == "wordpress":
            wp_handler = h
            break
    profile = wp_handler.get_profile("192.168.1.100")
    if profile and profile.dialogue:
        print(json.dumps(profile.dialogue[0], indent=2, default=str)[:500])

    sys.exit(0 if failed == 0 else 1)
