"""Offline parser checks for the SIO_RCVALL ownership regression."""
import unittest

from test_raw_receive_lifecycle import events


class RawReceiveParserTests(unittest.TestCase):
    def test_current_connection_with_metadata(self):
        parsed = events(
            '12:00:00.001 [CONN v4] id=7 pid=123 tid=456 outbound proto=17(UDP) layer=3(network)\n'
            '          192.168.3.2:50001 -> 192.168.3.2:50002  payload=32 bytes\n'
            '          compartment_id=1 condition_flags=0x00800011 interface_index=6 sub_interface_index=0\n'
            '          -> verdict PermanentAccept sent\n'
        )
        self.assertEqual(parsed, [dict(kind='CONN', pid=123, direction='outbound',
                                      signature=(17, '192.168.3.2', 50001, '192.168.3.2', 50002))])

    def test_native_and_false_observer_end_keep_their_pid(self):
        text = (
            '12:00:01.001 [END  v4] pid=123 outbound proto=6(TCP) 192.168.3.2:50001 -> 192.168.3.2:50002\r\n'
            '12:00:01.002 [END  v4] pid=999 inbound proto=17(UDP) 192.168.3.2:50002 -> 192.168.3.2:50001\r\n'
        )
        parsed = events(text)
        self.assertEqual([e['pid'] for e in parsed], [123, 999])
        self.assertEqual([e['kind'] for e in parsed], ['END', 'END'])
        self.assertEqual([e['signature'][0] for e in parsed], [6, 17])

    def test_older_connection_without_tid(self):
        self.assertEqual(events(
            '[CONN v4] id=1 pid=2320 inbound proto=6(TCP) layer=4(transport)\r\n'
            '  192.168.3.2:3389 -> 192.168.137.1:22600  payload=76 bytes\r\n'
        )[0]['pid'], 2320)

    def test_diagnostics_and_other_families_are_not_native_v4_events(self):
        self.assertEqual(events(
            '[LOG ERROR] endpoint already associated\n'
            '[END  v6] pid=123 inbound proto=17(UDP) ::1:50001 -> ::1:50002\n'
            '[BANDWIDTH v4] proto=17\n'
        ), [])


if __name__ == '__main__':
    unittest.main()
