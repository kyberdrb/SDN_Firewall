from pox.core import core
import pox.openflow.libopenflow_01 as of
from transproto import TransProto
from appproto import AppProto

log = core.getLogger()

class OFMtch:

    def __init__(self):
        self.OFMatch = None
        self.testAttr = "init"

    def createMatchStruct(self):
        self.OFMatch = of.ofp_match()
        self.testAttr += " + createMatchStruct"
        return self
        
    # 'priority' with 'actions' can be uset to turn the current 'permissive' fw mode, to 'restrictive' mode: Allowing rules will have higher priority, blocking rules lower, so that allowing rules will be in front of the blocking rules
    def packetType(self, type):
        if type == "IPv4":
            self.OFMatch.dl_type = 0x800
        self.testAttr += " + packetType (" + type + ")"
        return self

    def transProto(self, protocol):
        self.OFMatch.nw_proto = TransProto().number(protocol)
        self.testAttr += " + transProto (" + protocol + ")"
        return self

    def appProto(self, protocol):
        self.OFMatch.tp_dst = AppProto().number(protocol)
        self.testAttr += " + appProto (" + protocol + ")"
        return self