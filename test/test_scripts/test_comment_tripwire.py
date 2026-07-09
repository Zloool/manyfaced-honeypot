"""Tests for scripts/comment_tripwire.py (issue #325 classifier)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'scripts'))

import comment_tripwire as ct  # noqa: E402


class TestClassify(unittest.TestCase):
    """The heuristic: untrusted author AND a risk signal -> flag."""

    def test_trusted_author_never_flagged(self):
        # MEMBER/OWNER/COLLABORATOR/CONTRIBUTOR are pre-vetted.
        for assoc in ('OWNER', 'MEMBER', 'COLLABORATOR', 'CONTRIBUTOR'):
            flag, reason = ct.classify(assoc, 'download http://evil.com/x.zip now')
            self.assertFalse(flag, msg=assoc)
            self.assertIsNone(reason)

    def test_untrusted_with_archive_link_flags(self):
        flag, reason = ct.classify(
            'NONE', 'patch is here: https://evil.com/exploit.zip password: 1234'
        )
        self.assertTrue(flag)
        self.assertIn('archive', reason.lower())

    def test_untrusted_with_exe_filename_flags(self):
        flag, reason = ct.classify('FIRST_TIME_CONTRIBUTOR', 'run evil.exe to fix it')
        self.assertTrue(flag)
        self.assertIn('archive', reason.lower())

    def test_untrusted_with_shortener_link_flags(self):
        flag, reason = ct.classify('FIRST_TIMER', 'see https://bit.ly/3xKq for details')
        self.assertTrue(flag)
        self.assertIn('external', reason.lower())

    def test_untrusted_with_github_only_link_no_flag(self):
        flag, _ = ct.classify(
            'NONE',
            'see https://github.com/Zloool/manyfaced-honeypot/issues/325 and https://gist.github.com/abc for context',
        )
        self.assertFalse(flag)

    def test_untrusted_benign_text_no_flag(self):
        flag, _ = ct.classify('NONE', 'thanks for the quick fix, works now!')
        self.assertFalse(flag)

    def test_untrusted_external_domain_flags(self):
        flag, reason = ct.classify('NONE', 'mirror at https://some-random-host.ru/p')
        self.assertTrue(flag)
        self.assertIn('external', reason.lower())

    def test_untrusted_tar_gz_archive_flags(self):
        flag, _ = ct.classify('FIRST_TIME_CONTRIBUTOR', 'grab backup.tar.gz')
        self.assertTrue(flag)

    def test_untrusted_markdown_archive_link_flags(self):
        flag, _ = ct.classify('NONE', '[drop](https://x.com/a/ransom.rar)')
        self.assertTrue(flag)

    def test_unparseable_url_treated_as_risky(self):
        # A malformed URL that yields no host should still be treated as risky.
        flag, _ = ct.classify('NONE', 'get it at http://')
        self.assertTrue(flag)


if __name__ == '__main__':
    import unittest

    unittest.main()
