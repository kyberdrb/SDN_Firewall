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
                    trans_proto = rule[3], 
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
        id.update(rule.trans_proto)
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
        match = None
        message = None

        ''' match = self.createOFMatch(
            match, rule, rule.src, rule.dst)
        message = self.createOFMsg(message, match.OFMatch, action)
        self.connection.send(message.OFMessage)

        match = self.createOFMatch(
            match, rule, rule.src, rule.dst)
        message = self.createOFMsg(message, match.OFMatch, action)
        self.connection.send(message.OFMessage) '''

        self.createAndSendOFRule(
            match, rule, 
            rule.src, rule.dst, 
            message, action)
        self.createAndSendOFRule(
            match, rule, 
            rule.dst, rule.src, 
            message, action)

    def createAndSendOFRule(self, match, rule, src, dst, message, action):
        match = self.createOFMatch(
            match, rule, src, dst)
        message = self.createOFMsg(message, match.OFMatch, action)
        self.connection.send(message.OFMessage)

    def createOFMatch(self, match, rule, src, dst, pktType = "IPv4"):
        if match == None:
            match = of_match.OFMtch().createMatchStruct()
        
        match\
        .packetType(pktType)\
        .transProto(rule.trans_proto)\
        .appProtoDst(rule.app_proto)\
        .source(src)\
        .destination(dst)

        log.info(match.testAttr)
        return match

    def createOFMsg(self, msg, match, action, priority = 20,jump = "DROP"):
        if msg == None:
            msg = of_message.OFMsg().createFlowTableEntry()

        msg\
            .priority(priority)\
            .jump(jump)\
            .match(match)\
            .addOrDeleteOFRule(action)

        log.info(msg.testAttr)
        return msg

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
