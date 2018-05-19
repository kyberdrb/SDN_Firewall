from pox.core import core
import pox.lib.packet as pkt

log = core.getLogger()

class TransProto:

    def __init__(self):
        self._protocols = {\
            "tcp":   pkt.ipv4.TCP_PROTOCOL,
            "udp":   pkt.ipv4.UDP_PROTOCOL,
            "icmp": pkt.ipv4.ICMP_PROTOCOL,
            "igmp": pkt.ipv4.IGMP_PROTOCOL
        }

    def number(self, protocol):
        return self._protocols.get(protocol, None)