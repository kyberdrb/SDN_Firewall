from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr, IPAddr
import os
import csv


log = core.getLogger()

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        self.firewall = {}
        log.info("*** Starting SDN Firewall ***")

        self.FTP_PORT      = 21
        self.HTTP_PORT     = 80
        self.TELNET_PORT   = 23
        self.SMTP_PORT     = 25

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

        # creating a match structure
        match = of.ofp_match()

        # set packet ethernet type as IP
        match.dl_type = 0x800;

        # Setting the expiration of the rule
        d = int(expiration)
        if d == 0:
            action = "del"
        else:
            action = "add"

        msg.hard_timeout = d

        # IP protocol match
        if ip_proto == "tcp":
            match.nw_proto = pkt.ipv4.TCP_PROTOCOL
        if ip_proto == "udp":
            match.nw_proto = pkt.ipv4.UDP_PROTOCOL
        elif ip_proto == "icmp":
            match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
        elif ip_proto == "igmp":
            match.nw_proto = pkt.ipv4.IGMP_PROTOCOL

        #Application protocol match
        if app_proto == "ftp":
            match.tp_dst = self.FTP_PORT
        elif app_proto == "http":
            match.tp_dst = self.HTTP_PORT
        elif app_proto == "telnet":
            match.tp_dst = self.TELNET_PORT
        elif app_proto == "smtp":
            match.tp_dst = self.SMTP_PORT

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

    def addFirewallRule (
            self, 
            src=0, 
            dst=0, 
            ip_proto=0, 
            app_proto=0, 
            expiration = 0, 
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
                expiration)] = value
            self.pushRuleToSwitch(
                src, 
                dst, 
                ip_proto, 
                app_proto, 
                expiration
            )
            message = "Rule added: drop:"
        message += \
            " src:" + src + \
            " dst:" + dst + \
            " ip_proto:" + ip_proto + \
            " app_proto:" + app_proto + \
            " expiration:" + expiration + "s"
        log.info(message)

    def delFirewallRule (
            self, 
            src=0, 
            dst=0, 
            ip_proto=0, 
            app_proto=0, 
            expiration = 0, 
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
                message += \
                    " src:" + src + \
                    " dst:" + dst + \
                    " ip_proto:" + ip_proto + \
                    " app_proto:" + app_proto
                log.info(message)
        else:
            message = "Rule doesn't exist: drop:"
            message += \
                    " src:" + src + \
                    " dst:" + dst + \
                    " ip_proto:" + ip_proto + \
                    " app_proto:" + app_proto
            log.info(message)

    def showFirewallRules (self):
        log.info("*** List Of Firewall Rules ***")
        rule_num = 1
        for item in self.firewall:
            if item[4] != "0":
                message = \
                    "Rule " + rule_num + ": " + \
                    "src:" + item[0] + " " + \
                    "dst:" + item[1] + " " + \
                    "ip_proto:" + item[2] + " " + \
                    "app_proto:" + str(item[3])
                log.info(message)
            rule_num += 1
            
    def _handle_ConnectionUp (self, event):
        self.connection = event.connection
        log.info("Connection to the controller created")

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
                self.addFirewallRule(
                    rule[1], 
                    rule[2], 
                    rule[3], 
                    rule[4], 
                    rule[5])

        self.showFirewallRules()
        message = "Firewall rules updated for the switch "
        message += dpidToStr(event.dpid)
        log.info(message)

def launch ():
    core.registerNew(Firewall)


        
