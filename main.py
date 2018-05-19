from pox.core import core

# TODO - delete the import below after successful migration to "of_message" and "of_match"
import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *
from pox.lib.util import dpidToStr

# TODO - delete the import below after successful migration to "of_match"
import pox.lib.packet as pkt

from pox.lib.addresses import EthAddr, IPAddr
import os
import csv
from threading import Timer
import hashlib as checksum
from rule import Rule
import of_message
import of_match

log = core.getLogger()

class Firewall(EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        self.firewall = {}
        log.info("*** Starting SDN Firewall ***")

    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        log.info(
            "Switch [ID:" + \
            dpidToStr(event.dpid) + \
            "] has been successfully " + \
            "connected to the controller"
        )
        rules = self.rulesFilePath("fwRules.csv")
        self.addRulesFromFile(rules)

    def rulesFilePath(self, rulesFileName):
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

                newRule = Rule(
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

    def addFirewallRule(self, rule, ruleID):
        if ruleID in self.firewall:
                message = "RULE EXISTS!: drop:"
        else:
            self.firewall[ruleID] = rule
            self.pushRuleToSwitch(rule, action="add")
            message = "Rule added: drop:"
        message += " id:" + ruleID + " " + str(rule)
        log.info(message)
        self.showFirewallRules()

    def delFirewallRule(self, rule, ruleID):
        if ruleID in self.firewall:
            del self.firewall[ruleID]
            self.pushRuleToSwitch(rule, action="del")
            message = "Rule Deleted: drop:"
        else:
            message = "RULE DOESN'T EXIST!: drop:"
        message += " id:" + ruleID + " " + str(rule)
        log.info(message)
        self.showFirewallRules()

    def pushRuleToSwitch(self, rule, action):
        matchStruct = of_match.OFMtch()\
            .createMatchStruct()\
            .packetType("IPv4")\
            .transProto(rule.ip_proto)\
            .appProtoDst(rule.app_proto)

        ''' # TODO - Move the application protocol matching to a separate class 'AppProtocol' to a method 'number'
        if rule.app_proto == "ftp":
            match.tp_dst = 21
        elif rule.app_proto == "http":
            match.tp_dst = 80
        elif rule.app_proto == "telnet":
            match.tp_dst = 23
        elif rule.app_proto == "smtp":
            match.tp_dst = 25
        else:
            match.tp_dst = None '''

        match = matchStruct.OFMatch

#################################

        # TODO - Move the setting of the flow rule for src:host1 dst:host2 in the match structure to a separate method 'def matchIPAddr(self, host1, host2)'
        if rule.src != "any":
            match.nw_src = IPAddr(rule.src)
        if rule.dst != "any":
            match.nw_dst = IPAddr(rule.dst)
        
###################################################################

        message = of_message.OFMsg()\
            .createFlowTableEntry()\
            .priority(20)\
            .jump("DROP")\
            .match(match)\
            .addOrDeleteOFRule(action)
        msg = message.OFMessage

        self.connection.send(msg)

###################################################################

        # TODO - Move the setting of the flow rule for src:host2 dst:host1 in the match structure to a separate method 'def matchIPAddr(self, host1, host2)' - same method as with the flow rule for src:host1 dst:host2
        if rule.dst != "any":
            match.nw_src = IPAddr(rule.dst)
        if rule.src != "any":
            match.nw_dst = IPAddr(rule.src)

###################################################################

        msg = message\
            .match(match)\
            .OFMessage

        self.connection.send(msg)
        
        print message.testAttr
        print matchStruct.testAttr

    def showFirewallRules(self):
        message = "\n                         " + \
            "*** LIST OF FIREWALL RULES ***\n\n"
        if len(self.firewall) > 0:
            for ruleID,rule in self.firewall.items():
                message += "id: " + ruleID + " " + str(rule) + "\n"
        else:
            message += "The list of rules is empty.\n"
        log.info(message)

def launch():
    core.registerNew(Firewall)
