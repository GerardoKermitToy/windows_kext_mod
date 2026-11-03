"""Parser/oracle tests for the bounded NAT transit ICMP regression."""
import unittest
import xml.etree.ElementTree as ET

from test_icmp_transit import (
    TRANSIT_PATTERN, check_transit_records, check_wfp_sublayers, ping_statistics,
)


class PingStatisticsTests(unittest.TestCase):
    def test_success_summary(self):
        self.assertEqual(
            ping_statistics('6 packets transmitted, 6 received, 0% packet loss, time 1261ms'),
            dict(sent=6, received=6, duplicates=0, duplicate_reply=False),
        )

    def test_duplicate_replies_are_not_packet_loss(self):
        result = ping_statistics(
            '64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 (DUP!)\n'
            '6 packets transmitted, 6 received, +5 duplicates, 0% packet loss, time 5038ms')
        self.assertEqual(result['received'], 6)
        self.assertEqual(result['duplicates'], 5)
        self.assertTrue(result['duplicate_reply'])

    def test_packet_loss_and_busybox_summary(self):
        self.assertEqual(ping_statistics('6 packets transmitted, 0 packets received, 100% packet loss'),
                         dict(sent=6, received=0, duplicates=0, duplicate_reply=False))

    def test_missing_summary_is_not_success(self):
        with self.assertRaises(AssertionError):
            ping_statistics('ssh: connection timed out')


class TransitRecordsTests(unittest.TestCase):
    def test_local_packets_are_not_transit(self):
        check_transit_records('    payload: 4500001400010000400100007f0000017f000001\n')

    def test_marked_transit_packet_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'transit ICMP'):
            check_transit_records('    payload: 45000054' + TRANSIT_PATTERN.hex() + '0000\n')

    def test_no_records_is_valid(self):
        check_transit_records('Duration elapsed, stopping...\n')


class WfpSublayerTests(unittest.TestCase):
    def snapshot(self, inbound=28672, universal=32768, default=65534, filters=None):
        document = ET.Element('wfpstate')
        sublayers = ET.SubElement(document, 'subLayers')
        for key, name, weight in (
            ('inbound', 'PortmasterInboundPacketSublayer', inbound),
            ('default', 'PortmasterSublayer', default),
            ('FWPM_SUBLAYER_UNIVERSAL', 'UNIVERSAL', universal),
        ):
            item = ET.SubElement(sublayers, 'item')
            ET.SubElement(item, 'subLayerKey').text = key
            ET.SubElement(ET.SubElement(item, 'displayData'), 'name').text = name
            ET.SubElement(item, 'weight').text = str(weight)
        layers = ET.SubElement(ET.SubElement(document, 'layers'), 'item')
        items = ET.SubElement(layers, 'filters')
        if filters is None:
            filters = {
                'Portmaster Packet Inbound IPv4': 'inbound',
                'Portmaster Packet Inbound IPv6': 'inbound',
                'Portmaster Packet Outbound IPv4': 'default',
                'Portmaster ALE Inbound IPv6': 'default',
            }
        for name, key in filters.items():
            item = ET.SubElement(items, 'item')
            ET.SubElement(ET.SubElement(item, 'displayData'), 'name').text = name
            ET.SubElement(item, 'subLayerKey').text = key
        return ET.tostring(document, encoding='unicode')

    def test_normalized_weight_below_nat_is_valid(self):
        result = check_wfp_sublayers(self.snapshot(inbound=32764))
        self.assertEqual(result['inbound_weight'], 32764)
        self.assertEqual(result['universal_weight'], 32768)

    def test_observed_collision_above_nat_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'priority crossed native NAT'):
            check_wfp_sublayers(self.snapshot(inbound=32771))

    def test_equal_or_higher_priority_is_rejected(self):
        for weight in (32768, 65535):
            with self.subTest(weight=weight), self.assertRaises(AssertionError):
                check_wfp_sublayers(self.snapshot(inbound=weight))

    def test_actual_universal_weight_is_used(self):
        check_wfp_sublayers(self.snapshot(inbound=28672, universal=28673))
        with self.assertRaises(AssertionError):
            check_wfp_sublayers(self.snapshot(inbound=28672, universal=28671))

    def test_other_callouts_keep_priority_above_nat(self):
        with self.assertRaises(AssertionError):
            check_wfp_sublayers(self.snapshot(default=32767))

    def test_filter_in_wrong_sublayer_is_rejected(self):
        for name, key in (
            ('Portmaster Packet Inbound IPv4', 'default'),
            ('Portmaster Packet Outbound IPv4', 'inbound'),
        ):
            filters = check_wfp_sublayers(self.snapshot())['filters']
            filters[name] = key
            with self.subTest(name=name), self.assertRaisesRegex(AssertionError, 'incorrect'):
                check_wfp_sublayers(self.snapshot(filters=filters))

    def test_missing_inbound_filter_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'missing inbound packet filter'):
            check_wfp_sublayers(self.snapshot(filters={'Portmaster Packet Inbound IPv4': 'inbound'}))

    def test_appended_firewall_state_is_not_parsed_as_wfp(self):
        check_wfp_sublayers(self.snapshot() + '<firewallState/>')

    def test_missing_wfp_state_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'missing WFP state'):
            check_wfp_sublayers('<firewallState/>')


if __name__ == '__main__':
    unittest.main()
