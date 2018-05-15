class Rule:

    """TODO - add an '_id' attribute with only a getter (@property, without setter).
    It will be calculated from src, dst, ip_proto and app_proto as a sha256 value.
    This attribute will be then used for comparing duplicate rules"""
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
'''         self._id = generateID(
            self.src,
            self.dst,
            self.ip_proto,
            self.app_proto
        ) '''

    @property
    def delay(self):
        return delay

    @delay.setter
    def delay(self, delay):
        if delay < 0:
            self.delay = 0
        elif delay > 65535:
            self.delay = 65535
        else:
            self.delay = delay

'''     def generateID(
            self
            src,
            dst,
            ip_proto,
            app_proto):
        # make a checksum of these parameters - one number/alplanumeric string '''

'''     @property
    def id(self):
        return _id '''

    def ruleInfo (self):
        return  " src:" + self.src + \
                " dst:" + self.dst + \
                " ip_proto:" + self.ip_proto + \
                " app_proto:" + self.app_proto + \
                " expiration:" + self.expiration + "s" + \
                " delay:" + self.delay + "s"
