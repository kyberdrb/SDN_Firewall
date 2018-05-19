from pox.core import core
import pox.lib.packet as pkt

log = core.getLogger()

class AppProto:

    def __init__(self):
        self._protocols = {\
            "ftp":    21,
            "http":   80,
            "telnet": 23,
            "smtp":   25
        }

    def number(self, protocol):
        return self._protocols.get(protocol, None)