import pox.openflow.libopenflow_01 as of

class OFMsg:

    def __init__ (self):
        self.OFMessage = None
        self.testAttr = "init"

    def createFlowTableEntry(self):
        self.OFMessage = of.ofp_flow_mod()
        self.testAttr += " + createFlowTableEntry"
        return self
        
    # 'priority' with 'actions' can be uset to turn the current 'permissive' fw mode, to 'restrictive' mode
    def priority(self, priority):
        self.OFMessage.priority = priority
        self.testAttr += " + priority"
        return self

    # The 'of.OFPP_NONE' in 'ofp_action_output' means, that the traffic, that matches with the rule, will be dropped
    # Possible actions: "DROP" and "ACCEPT"
    def action(self, action):
        self.testAttr += " + action"
        return self

