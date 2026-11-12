"""Offline parser checks for loopback control notification regressions."""
import unittest

from test_control_no_end import control_ids
from test_mld_loopback import control_ends


SOURCE = "0000:0000:0000:0000:0000:0000:0000:0001"
ALL_NODES = "ff02:0000:0000:0000:0000:0000:0000:0001"
MLD_ROUTERS = "ff02:0000:0000:0000:0000:0000:0000:0016"


def conn(event_id, destination, interface=1, protocol=58):
    return (f"[CONN v6] id={event_id} pid=0 tid=0 outbound proto={protocol}(ICMPv6) layer=3(network)\n"
            f"  {SOURCE}:0 -> {destination}:0\n"
            f"  interface_index={interface} sub_interface_index=0\n")


def end(destination, direction="outbound", protocol=58, source=SOURCE):
    return (f"[END  v6] pid=0 {direction} proto={protocol}(ICMPv6) "
            f"{source}:0 -> {destination}:0")


class ControlParserTests(unittest.TestCase):
    def test_end_parser_recognizes_each_requested_address(self):
        all_nodes = end(ALL_NODES)
        routers = end(MLD_ROUTERS)
        text = "\n".join((all_nodes, routers, end(ALL_NODES, "inbound"),
                          end(ALL_NODES, protocol=17), end(ALL_NODES, source=MLD_ROUTERS)))
        self.assertEqual(control_ends(text), [routers])
        self.assertEqual(control_ends(text, ("ff02::1", "ff02::16")), [all_nodes, routers])

    def test_notification_parser_respects_destination_and_interface(self):
        text = (conn(1, ALL_NODES) + conn(2, MLD_ROUTERS) + conn(3, ALL_NODES, interface=18)
                + conn(4, ALL_NODES, protocol=17))
        self.assertEqual(control_ids(text, True, "ff02::1"), [1])
        self.assertEqual(control_ids(text, True), [2])


if __name__ == "__main__":
    unittest.main()
