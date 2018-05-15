from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr, IPAddr
import os
import csv
from threading import Timer


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
        fwPkgPath = os.path.abspath(
            os.path.dirname(__file__)
        )
        fwRules = "fwRules.csv"
        fwRules = os.path.join(fwPkgPath, fwRules)

        with open(fwRules, "rb") as rules:
            rulesList = csv.reader(rules)

            for rule in rulesList:
                if rule[0] == "id":
                    continue

                delay = int(rule[6])
                if delay <= 0:
                    delay = 0
                    log.info("Delay adjusted from " + rule[6] + " to " + str(delay) + "s")
                    self.addFirewallRule(
                        rule[1], 
                        rule[2], 
                        rule[3], 
                        rule[4], 
                        rule[5], 
                        str(delay))
                else:
                    log.info("Adding rule after " + str(delay) + "s!")
                    delayedRule = rule
                    newDelay = delay
                    # Sice je nastaveny 'delay' na urcity pocet sekund, ale
                    # POX si to uvedomi az o dalsich cca 20-30 sekund neskor
                    Timer(delay, lambda: self.addFirewallRule(
                        delayedRule[1], 
                        delayedRule[2], 
                        delayedRule[3], 
                        delayedRule[4], 
                        delayedRule[5], 
                        str(newDelay))
                    ).start()

    def showFirewallRules (self):
        message = "*** List Of Firewall Rules ***\n\n"
        for item in self.firewall:
            if item[4] != "0":
                message += self.ruleInfo(
                    item[0], 
                    item[1], 
                    item[2], 
                    item[3], 
                    item[4],
                    item[5]
                )
        log.info(message)

        # Zaujimave, 'firewall' je Dictionary
        # struktura s KOMPOZITNYM klucom
        #print(self.firewall)

    def addFirewallRule (
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
            app_proto, 
            expiration) in self.firewall:
                message = "Rule exists: drop:"
        else:
            self.firewall[(
                src, 
                dst, 
                ip_proto, 
                app_proto, 
                expiration,
                delay)] = value
            self.pushRuleToSwitch(
                src, 
                dst, 
                ip_proto, 
                app_proto, 
                expiration
            )
            message = "Rule added: drop:"
        message += self.ruleInfo(
            src, 
            dst, 
            ip_proto, 
            app_proto, 
            expiration,
            delay
        )
        log.info(message)
        self.showFirewallRules()

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
        message += self.ruleInfo(
            src, 
            dst, 
            ip_proto, 
            app_proto, 
            expiration,
            delay
        )
        log.info(message)

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

        # Setting the expiration of the rule
        expiry = int(expiration)
        msg.hard_timeout = expiry

###################################################################

        # creating a match structure
        match = of.ofp_match()

        # set packet ethernet type as IP
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
        elif action == "add":
            self.connection.send(msg)

###################

        # flow rule for src:host2 dst:host1
        if dst != "any":
            match.nw_src = IPAddr(dst)
        if src != "any":
            match.nw_dst = IPAddr(src)
        msg.match = match

        if action == "delete":
            msg.command=of.OFPFC_DELETE
            msg.flags = of.OFPFF_SEND_FLOW_REM
            self.connection.send(msg)
        elif action == "add":
            self.connection.send(msg)

    def ruleInfo (
            self, 
            src, 
            dst, 
            ip_proto, 
            app_proto, 
            expiration,
            delay):
        return  " src:" + src + \
                " dst:" + dst + \
                " ip_proto:" + ip_proto + \
                " app_proto:" + app_proto + \
                " expiration:" + expiration + "s" + \
                " delay:" + delay + "\n"

def launch ():
    core.registerNew(Firewall)


        
