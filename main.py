from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr, IPAddr
import os
import csv
from threading import Timer
import rule as fwrule
import hashlib as checksum

log = core.getLogger()

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        self.firewall = {}
        log.info("*** Starting SDN Firewall ***")

    def _handle_ConnectionUp (self, event):
        self.connection = event.connection
        log.info(
            "Switch [ID:" + \
            dpidToStr(event.dpid) + \
            "] has been successfully " + \
            "connected to the controller"
        )
        rules = self.rulesFilePath("fwRules.csv")
        self.addRulesFromFile(rules)

    def rulesFilePath (self, rulesFileName):
        currentDir = os.path.dirname(__file__)
        fwPkgPath = os.path.abspath(currentDir)
        fwRulesPath = os.path.join(fwPkgPath, rulesFileName)
        return fwRulesPath

    def addRulesFromFile(self, rulesFile):
        with open(rulesFile, "rb") as rules:
            rulesList = csv.reader(rules)

            for rule in rulesList:
                if rule[0] == "id":
                    continue

                newRule = fwrule.Rule(
                    src = rule[1], 
                    dst = rule[2], 
                    ip_proto = rule[3], 
                    app_proto = rule[4], 
                    expiration = rule[5], 
                    delay = rule[6]
                )
                ruleID = self.generateRuleID(newRule)

                if int(newRule.delay) > 0:
                    self.activateRuleAfterDelay(newRule, ruleID)
                    self.removeRuleAfterExpiration(newRule, ruleID)
                else:
                    newRule = self.adjustDelayValue(newRule)
                    self.addFirewallRule(newRule, ruleID)

    def generateRuleID(
            self,
            rule):
        id = checksum.md5()
        id.update(rule.src)
        id.update(rule.dst)
        id.update(rule.ip_proto)
        id.update(rule.app_proto)
        return id.hexdigest()

    def activateRuleAfterDelay(self, newRule, ruleID):
        Timer(
            int(newRule.delay), 
            self.addFirewallRule, 
            [newRule, ruleID]
        ).start()

    def removeRuleAfterExpiration(self, newRule, ruleID):
        delayPlusExpiration = int(newRule.delay) + int(newRule.expiration)
        Timer(
            delayPlusExpiration, 
            self.delFirewallRule, 
            [newRule, ruleID]
        ).start()

    def adjustDelayValue(self, newRule):
        if int(newRule.delay) > 65535:
            newRule.delay = 65535
        else:
            newRule.delay = 0
        return newRule

    def addFirewallRule (self, rule, ruleID):
        if ruleID in self.firewall:
                message = "RULE EXISTS!: drop:"
        else:
            self.firewall[ruleID] = rule
            self.pushRuleToSwitch(rule, action="add")
            message = "Rule added: drop:"
        message += " id:" + ruleID + " " + str(rule)
        log.info(message)
        self.showFirewallRules()

    # TODO - basically, make this method should look similar to the 'addFirewallRule': add 'rule' parameter + edit all parameters like: 'src' to 'rule.src' etc. -> see 'addFirewallRule' method
    def delFirewallRule (self, rule, ruleID):
        if ruleID in self.firewall:
            del self.firewall[ruleID]
            self.pushRuleToSwitch(rule, action="del")
            message = "Rule Deleted: drop:"
        else:
            message = "RULE DOESN'T EXIST!: drop:"
        message += " id:" + ruleID + " " + str(rule)
        log.info(message)
        self.showFirewallRules()

    def pushRuleToSwitch (self, rule, action):
        # TODO - for 'msg' object create new class, that will use function chaining
        # TODO - Move the creating of a switch flow table entry to a separate method
        msg = of.ofp_flow_mod()

        # TODO - Move the setting of rule priority to a separate method - 'priority' with 'actions' can be uset to turn the current 'permissive' fw mode, to 'restrictive' mode
        msg.priority = 20

        # TODO - Move the setting of rule action to a separate method. The 'of.OFPP_NONE' in 'ofp_action_output' means, that the traffic, that matches with the rule, will be dropped
        msg.actions.append(
            of.ofp_action_output(
                port=of.OFPP_NONE
            )
        )

        # TODO - Move to separate method with more meaningful name
        # TODO - Remove the rule from the 'firewall' datastructure after its expiration - maybe create another Timer at the time, when the rule is added to the 'firewall' datastructure, that will call the 'delFirewallRule' method
        #msg.hard_timeout = int(rule.expiration)

###################################################################

        # TODO - Move the creating of a match structure to a separate method
        match = of.ofp_match()

        # TODO - Move setting packet ethernet type as IPv4 to a separate method
        match.dl_type = 0x800;

###################################################################

        # TODO - Move the transport protocol matching to a separate class 'TransportProtocol' to a method 'number'
        if rule.ip_proto == "tcp":
            match.nw_proto = pkt.ipv4.TCP_PROTOCOL
        if rule.ip_proto == "udp":
            match.nw_proto = pkt.ipv4.UDP_PROTOCOL
        elif rule.ip_proto == "icmp":
            match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
        elif rule.ip_proto == "igmp":
            match.nw_proto = pkt.ipv4.IGMP_PROTOCOL
        else:
            match.nw_proto = None

###################################################################

        # TODO - Move the application protocol matching to a separate class 'AppProtocol' to a method 'number'
        if rule.app_proto == "ftp":
            match.tp_dst = 21
        elif rule.app_proto == "http":
            match.tp_dst = 80
        elif rule.app_proto == "telnet":
            match.tp_dst = 23
        elif rule.app_proto == "smtp":
            match.tp_dst = 25
        else:
            match.tp_dst = None

###################################################################

        # TODO - Move the setting of the flow rule for src:host1 dst:host2 in the match structure to a separate method 'def matchIPAddr(self, host1, host2)'
        if rule.src != "any":
            match.nw_src = IPAddr(rule.src)
        if rule.dst != "any":
            match.nw_dst = IPAddr(rule.dst)
        msg.match = match

        # TODO - Move the rule addition/removal to/from the switch to a separate method. Again, this logic, whether to add/remove rule to/from a switch should be two separate methods
        if action == "del":
            msg.command=of.OFPFC_DELETE
            msg.flags = of.OFPFF_SEND_FLOW_REM
            self.connection.send(msg)
            log.info("Rule have been removed from the switch - forward: H1 -> H2")
        elif action == "add":
            self.connection.send(msg)
            log.info("Rule have been added to the switch - forward: H1 -> H2")

###################

        # TODO - Move the setting of the flow rule for src:host2 dst:host1 in the match structure to a separate method 'def matchIPAddr(self, host1, host2)' - same method as with the flow rule for src:host1 dst:host2
        if rule.dst != "any":
            match.nw_src = IPAddr(rule.dst)
        if rule.src != "any":
            match.nw_dst = IPAddr(rule.src)
        msg.match = match

        # TODO - Move the rule addition/removal to/from the switch to a separate method. Again, this logic, whether to add/remove rule to/from a switch should be two separate methods
        if action == "del":
            msg.command=of.OFPFC_DELETE
            msg.flags = of.OFPFF_SEND_FLOW_REM
            self.connection.send(msg)
            log.info("Rule have been removed from the switch - backward: H2 -> H1")
        elif action == "add":
            self.connection.send(msg)
            log.info("Rule have been added to the switch - backward: H2 -> H1")

    def showFirewallRules (self):
        message = "\n                         " + \
            "*** LIST OF FIREWALL RULES ***\n\n"
        if len(self.firewall) > 0:
            for ruleID,rule in self.firewall.items():
                message += "id: " + ruleID + " " + str(rule) + "\n"
        else:
            message += "The list of rules is empty.\n"
        log.info(message)

def launch ():
    core.registerNew(Firewall)
