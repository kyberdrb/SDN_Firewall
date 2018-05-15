import hashlib as checksum

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
        self._id = self.generateID(
            self.src,
            self.dst,
            self.ip_proto,
            self.app_proto
        )

    def generateID(
            self,
            src,
            dst,
            ip_proto,
            app_proto):
        h = hashlib.md5()
        h.update(src)
        h.update(dst)
        h.update(ip_proto)
        h.update(app_proto)
        return h.hexdigest()

    @property
    def id(self):
        return _id

    def ruleInfo (self):
        return  "id:" + self._id + \
                " src:" + self.src + \
                " dst:" + self.dst + \
                " ip_proto:" + self.ip_proto + \
                " app_proto:" + self.app_proto + \
                " expiration:" + self.expiration + "s" + \
                " delay:" + str(self.delay) + "s"
