"""Recognize explicitly requested informational driver memory statistics."""
import re


MEMORY_STATS = re.compile(
    r'(?:\d{2}:\d{2}:\d{2}\.\d{3} )?'
    r'\[LOG ERROR\] src[\\/]device\.rs:\d+ '
    r'(?:Packet cache: \d+ entries'
    r'|Connection cache: IPv4 \d+ entries, IPv6 \d+ entries'
    r'|Untracked connection cache: IPv4 \d+ entries, IPv6 \d+ entries'
    r'|BandwidthStats cache: TCPv4 \d+, TCPv6 \d+, UDPv4 \d+, UDPv6 \d+ entries'
    r'|TCP endpoint cache: \d+ entries, \d+ pending closures'
    r'|UDP endpoint cache: \d+ endpoints, \d+ peers'
    r'|UDP flow cache: \d+ entries, \d+ callbacks in progress'
    r'|ICMP echo cache: \d+ entries)'
)


def is_memory_stats(line, *, requested=False):
    return bool(requested and MEMORY_STATS.fullmatch(line))
