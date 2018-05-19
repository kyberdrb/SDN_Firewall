from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class OFMsg:

    def __init__(self):
        self.OFMessage = None
        self.testAttr = "init"

    def createFlowTableEntry(self):
        self.OFMessage = of.ofp_flow_mod()
        self.testAttr += " + createFlowTableEntry"
        return self
        
    # 'priority' with 'actions' can be uset to turn the current 'permissive' fw mode, to 'restrictive' mode: Allowing rules will have higher priority, blocking rules lower, so that allowing rules will be in front of the blocking rules
    def priority(self, priority):
        self.OFMessage.priority = priority
        self.testAttr += " + priority"
        return self

    # The 'of.OFPP_NONE' in 'ofp_action_output' means, that the traffic, that matches with the rule, will be dropped
    def jump(self, action):
        if action == "DROP":
            act = of.ofp_action_output(port = of.OFPP_NONE)
        elif action == "ACCEPT":
            act = of.ofp_action_output(port = of.OFPP_FLOOD)
        
        self.OFMessage.actions.append(act)
        self.testAttr += " + jump (action: " + action + ")"
        return self

    def match(self, match_struct):
        self.OFMessage.match = match_struct
        self.testAttr += " + match"
        return self

    def addOrDeleteOFRule(self, action):
        self.testAttr += " + addOrDelete - action: " + action
        if action == "del":
            self.OFMessage.command = of.OFPFC_DELETE
            self.OFMessage.flags = of.OFPFF_SEND_FLOW_REM
            log.info("Rule have been removed from the switch - forward: H1 -> H2")
        elif action == "add":
            log.info("Rule have been added to the switch - forward: H1 -> H2")
        return self