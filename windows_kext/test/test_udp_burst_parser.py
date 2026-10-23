"""Offline compatibility tests for UDP burst monitor records."""
import unittest

from test_udp_burst_closure import CONN


class UdpBurstParserTests(unittest.TestCase):
    def record(self, version=4, tid='', direction='outbound', payload='payload: deadbeef\n', newline='\n'):
        local, remote = ('127.0.0.1', '127.0.0.2') if version == 4 else ('::1', '::1')
        text = (
            f'13:56:32.734 [CONN v{version}] id=17 pid=4568 {tid}{direction} '
            'proto=17(UDP) layer=3(network)\n'
            f'          {local}:54829 -> {remote}:54828  payload=284 bytes\n'
        )
        if payload:
            text += '          ' + payload
        text += '          -> verdict PermanentAccept sent\n'
        return text.replace('\n', newline)

    def test_legacy_and_tid_headers_preserve_all_fields(self):
        for version in (4, 6):
            local, remote = ('127.0.0.1', '127.0.0.2') if version == 4 else ('::1', '::1')
            for tid in ('', 'tid=904 ', 'tid=0 '):
                for direction in ('outbound', 'inbound'):
                    for newline in ('\n', '\r\n'):
                        with self.subTest(version=version, tid=tid, direction=direction, newline=newline):
                            match = CONN.search(self.record(version, tid, direction, newline=newline))
                            self.assertIsNotNone(match)
                            self.assertEqual(match.groups(), (
                                '17', '4568', direction, local, '54829', remote, '54828', 'PermanentAccept',
                            ))

    def test_optional_payload_line(self):
        for tid in ('', 'tid=904 '):
            for payload in ('', 'payload: (none)\n', 'payload: deadbeef\n'):
                with self.subTest(tid=tid, payload=payload):
                    self.assertIsNotNone(CONN.search(self.record(tid=tid, payload=payload)))

    def test_invalid_tid_is_not_silently_accepted(self):
        for tid in ('tid= ', 'tid=abc ', 'tid=-1 ', 'tid=904 tid=905 '):
            with self.subTest(tid=tid):
                self.assertIsNone(CONN.search(self.record(tid=tid)))

    def test_non_udp_or_failed_verdict_is_not_accepted(self):
        record = self.record(tid='tid=904 ')
        self.assertIsNone(CONN.search(record.replace('proto=17(UDP)', 'proto=6(TCP)')))
        self.assertIsNone(CONN.search(record.replace('PermanentAccept sent', 'PermanentAccept FAILED')))


if __name__ == '__main__':
    unittest.main()
