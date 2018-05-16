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
        log.info("Connection to the controller created")
        self.loadRules()
        log.info("Rules for the switch " + \
            dpidToStr(event.dpid) + \
            " have been successfuly updated")

    def loadRules (self):
        fwRules = self.openRulesFile("fwRules.csv")
        self.addRules(fwRules)

    def openRulesFile(self, filename):
        fwPkgPath = os.path.abspath(
            os.path.dirname(__file__)
        )
        fwRules = filename
        fwRules = os.path.join(fwPkgPath, fwRules)
        return fwRules

    def addRules(self, fileWithRules):
        with open(fileWithRules, "rb") as rules:
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
                    log.info("Adding rule after " + newRule.delay + "s!")
                    # TODO - prist na to, preco pravidlo, ktore ma byt aktivovane po casovej odozve sa oneskori o dalsich 20 sekund. Mozno vytvorit vlastnu triedu 'Thread' s danou operaciou namiesto 'Timer' objektu? V kazdom pripade, odstranovanie pravidla cez "hard_timeout" v pushRuleToSwitch funguje spravne a presne.
                    # Sice je nastaveny 'delay' na urcity pocet sekund, ale
                    # POX si to uvedomi az o dalsich cca 30 sekund neskor
                    Timer(
                        int(newRule.delay), 
                        self.addFirewallRule, 
                        [newRule, ruleID]
                    ).start()
                else:
                    if int(newRule.delay) > 65535:
                        newRule.delay = 65535
                    else:
                        newRule.delay = 0
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

    def addFirewallRule (self, rule, ruleID):
        # TODO - porovnavanie dat do samostatnej metody - porovnavat checksumy, kluce vo 'firewall' Dictionary, pre jednotlive pravidla - porovnavanie by potom vyzeralo takto: if ruleID in self.firewall: ...
        # TODO - OTESTOVAT
        if ruleID in self.firewall:
                message = "Rule exists: drop:"
        else:
            # TODO - upravit pridavanie pravidla - odstranit 'value' parameter -> potom do struktury 'firewall' pridavat pravidla sposobom: self.firewall[ruleID] = rule
            # TODO - OTESTOVAT
            self.firewall[ruleID] = rule
            self.pushRuleToSwitch(
                rule.src, 
                rule.dst, 
                rule.ip_proto, 
                rule.app_proto, 
                rule.expiration
            )
            message = "Rule added: drop:"
        message += " id:" + ruleID
        message += str(rule)
        log.info(message)
        self.showFirewallRules()

    # TODO - basically, make this method should look similar to the 'addFirewallRule': add 'rule' parameter + edit all parameters like: 'src' to 'rule.src' etc. -> see 'addFirewallRule' method
    def delFirewallRule (
            self, 
            src=0, 
            dst=0, 
            ip_proto=0, 
            app_proto=0, 
            expiration = 0,
            delay = 0, 
            value=True):
        if  (src,
            dst, 
            ip_proto, 
            app_proto) in self.firewall:
                del self.firewall[(
                    src, 
                    dst, 
                    ip_proto, 
                    app_proto
                )]
                self.pushRuleToSwitch(
                    src, 
                    dst, 
                    ip_proto, 
                    app_proto, 
                    expiration
                )
                message = "Rule Deleted: drop:"
        else:
            message = "Rule doesn't exist: drop:"
        ''' message += self.ruleInfo(
            src, 
            dst, 
            ip_proto, 
            app_proto, 
            expiration,
            delay
        ) '''
        log.info(message)
        self.showFirewallRules()

    def pushRuleToSwitch (
            self, 
            src, 
            dst, 
            ip_proto, 
            app_proto, 
            expiration):
        # creating a switch flow table entry
        msg = of.ofp_flow_mod()
        msg.priority = 20
        msg.actions.append(
            of.ofp_action_output(
                port=of.OFPP_NONE
            )
        )

        # TODO - if 'expiration' is equal to 0 the rule will persist
        # TODO - after rule expiration, remove it from the 'firewall' datastructure
        # Setting the expiration of the rule (in seconds)
        expiry = int(expiration)
        msg.hard_timeout = expiry

###################################################################

        # creating a match structure
        match = of.ofp_match()

        # set packet ethernet type as IPv4
        match.dl_type = 0x800;

###################################################################

        # IP protocol match
        if ip_proto == "tcp":
            match.nw_proto = pkt.ipv4.TCP_PROTOCOL
        if ip_proto == "udp":
            match.nw_proto = pkt.ipv4.UDP_PROTOCOL
        elif ip_proto == "icmp":
            match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
        elif ip_proto == "igmp":
            match.nw_proto = pkt.ipv4.IGMP_PROTOCOL

###################################################################

        # Application protocol match
        if app_proto == "ftp":
            match.tp_dst = 21
        elif app_proto == "http":
            match.tp_dst = 80
        elif app_proto == "telnet":
            match.tp_dst = 23
        elif app_proto == "smtp":
            match.tp_dst = 25

###################################################################

        # Decide, whether the rule should be kept or removed
        if expiry == 0:
            action = "del"
        else:
            action = "add"

###################################################################

        # flow rule for src:host1 dst:host2
        if src != "any":
            match.nw_src = IPAddr(src)
        if dst != "any":
            match.nw_dst = IPAddr(dst)
        msg.match = match

        if action == "del":
            msg.command=of.OFPFC_DELETE
            msg.flags = of.OFPFF_SEND_FLOW_REM
            self.connection.send(msg)
            log.info("Rule have been removed from the switch - forward: H1 -> H2")
        elif action == "add":
            self.connection.send(msg)
            log.info("Rule have been added to the switch - forward: H1 -> H2")

###################

        # flow rule for src:host2 dst:host1
        if dst != "any":
            match.nw_src = IPAddr(dst)
        if src != "any":
            match.nw_dst = IPAddr(src)
        msg.match = match

        if action == "del":
            msg.command=of.OFPFC_DELETE
            msg.flags = of.OFPFF_SEND_FLOW_REM
            self.connection.send(msg)
            log.info("Rule have been removed from the switch - backward: H2 -> H1")
        elif action == "add":
            self.connection.send(msg)
            log.info("Rule have been added to the switch - backward: H2 -> H1")

    # TODO - OTESTOVAT
    def showFirewallRules (self):
        message = "    *** LIST OF FIREWALL RULES ***\n\n"
        log.info(message)
        for ruleID,rule in self.firewall.items():
            message += "id: " + ruleID + " " + str(rule) + "\n"
        ''' print self.firewall '''
        log.info(message)

def launch ():
    core.registerNew(Firewall)


        
