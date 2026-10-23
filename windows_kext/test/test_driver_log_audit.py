"""Offline tests for the narrow PrintMemoryStats audit exception."""
import unittest

from driver_log_audit import is_memory_stats


MESSAGES = (
    'Packet cache: 0 entries',
    'Connection cache: IPv4 9 entries, IPv6 0 entries',
    'Untracked connection cache: IPv4 0 entries, IPv6 0 entries',
    'BandwidthStats cache: TCPv4 1, TCPv6 2, UDPv4 3, UDPv6 4 entries',
    'TCP endpoint cache: 0 entries, 0 pending closures',
    'UDP endpoint cache: 2 endpoints, 5 peers',
    'UDP flow cache: 4 entries, 0 callbacks in progress',
    'ICMP echo cache: 0 entries',
)


class DriverLogAuditTests(unittest.TestCase):
    def line(self, message, prefix='14:59:14.058 ', source=r'src\device.rs:728', level='ERROR'):
        return f'{prefix}[LOG {level}] {source} {message}'

    def test_all_eight_requested_counter_formats(self):
        for message in MESSAGES:
            for prefix in ('', '14:59:14.058 '):
                with self.subTest(message=message, prefix=prefix):
                    self.assertTrue(is_memory_stats(self.line(message, prefix=prefix), requested=True))

    def test_explicit_request_is_required(self):
        for message in MESSAGES:
            with self.subTest(message=message):
                self.assertFalse(is_memory_stats(self.line(message)))
                self.assertFalse(is_memory_stats(self.line(message), requested=False))

    def test_other_driver_errors_remain_errors(self):
        for message in ('failed to inject packet', 'Packet cache: failed to allocate',
                        'UDP flow cache: invalid context', 'Verdict invalid id',
                        'Packet cache: -1 entries'):
            with self.subTest(message=message):
                self.assertFalse(is_memory_stats(self.line(message), requested=True))

    def test_prefix_suffix_and_multiline_content_are_not_ignored(self):
        line = self.line(MESSAGES[0])
        for changed in (line + ' failed', 'failure: ' + line,
                        line + '\n[LOG ERROR] failed to inject', line + '\n'):
            with self.subTest(changed=changed):
                self.assertFalse(is_memory_stats(changed, requested=True))

    def test_other_sources_and_levels_are_not_ignored(self):
        for source in (r'src\packet.rs:728', r'other\device.rs:728', 'device.rs:728'):
            with self.subTest(source=source):
                self.assertFalse(is_memory_stats(self.line(MESSAGES[0], source=source), requested=True))
        for level in ('WARN', 'CRIT', 'INFO'):
            with self.subTest(level=level):
                self.assertFalse(is_memory_stats(self.line(MESSAGES[0], level=level), requested=True))


if __name__ == '__main__':
    unittest.main()
