class Rule:

    def __init__(
            self,
            src, 
            dst, 
            ip_proto, 
            app_proto, 
            expiration,
            delay):
        self.src = src
        self.dst = dst
        self.ip_proto = ip_proto
        self.app_proto = app_proto
        self.expiration = expiration
        self.delay = delay

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
                " delay:" + delay + "s"

    def helloWorld(self):
        print "Hello World!"