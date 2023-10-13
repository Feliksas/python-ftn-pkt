from datetime import datetime
from backports.zoneinfo import ZoneInfo


ENCODING_DEFAULT="cp866"

class Addr(object):
    def __init__(self):
        self.zone = 0      # 2 bytes
        self.net = 0       # 2 bytes
        self.node = 0      # 2 bytes
        self.point = 0     # 2 bytes
        self.domain = ""   # 9 bytes

class ProductCode(object):
    def __init__(self):
        self.lo = 0        # 1 byte
        self.hi = 0        # 1 byte

class ProductRevision(object):
    def __init__(self):
        self.minor = 0     # 1 byte
        self.major = 0     # 1 byte

class Product(object):
    def __init__(self):
        self.code = ProductCode()
        self.rev = ProductRevision()

class CapabilityWord(object):
    def __init__(self):
        self.first = 0     # 2 bytes
        self.second = 0    # 2 bytes

class Attributes(object):
    def __init__(self):
        self.private = False                # bit 0 
        self.crash = False                  # bit 1
        self.received = False               # bit 2
        self.sent = False                   # bit 3
        self.file_attached = False          # bit 4
        self.in_transit = False             # bit 5
        self.orphan = False                 # bit 6
        self.kill_sent = False              # bit 7
        self.local = False                  # bit 8
        self.hold_for_pickup = False        # bit 9
        self.file_request = False           # bit 11
        self.return_receipt_request = False # bit 12       
        self.is_return_receipt = False      # bit 13
        self.audit_request = False          # bit 14
        self.file_update_request = False    # bit 15


class PktHeader(object):                         # Header size: 58 bytes 
    def __init__(self):
        self.orig_addr = Addr()                  # 8 bytes
        self.dest_addr = Addr()                  # 8 bytes
        self.created = datetime.fromtimestamp(0) # 12 bytes
        self.baud = 0                            # 2 bytes
        self.version = 0                         # 2 bytes 
        self.product = Product()                 # 4 bytes
        self.passwd = ""                         # 8 bytes
        self.aux_net = 0                         # 2 bytes
        self.cap_word = CapabilityWord()         # 3 bytes

    def deserialize(self, packet):
        packet.seek(0)
        self.orig_addr.node = _read_int_le(packet, 2)
        self.dest_addr.node = _read_int_le(packet, 2)
        self.created = _read_time_le(packet) # 12 bytes
        self.baud = _read_int_le(packet,2) # Unused
        self.version = _read_int_le(packet, 2)
        self.orig_addr.net = _read_int_le(packet, 2)
        self.dest_addr.net = _read_int_le(packet, 2)
        self.product.code.lo = _read_int_le(packet, 1)
        self.product.rev.major = _read_int_le(packet, 1)
        self.passwd = _read_str_ascii(packet, 8)
        self.orig_addr.zone = _read_int_le(packet, 2)
        self.dest_addr.zone = _read_int_le(packet, 2)
        self.aux_net = _read_int_le(packet, 2)
        self.cap_word.first = _read_int_be(packet, 2)
        self.product.code.hi = _read_int_le(packet, 1)
        self.product.rev.minor = _read_int_le(packet, 1)
        self.cap_word.second = _read_int_le(packet, 2)
        packet.seek(4, 1) # Additional zone info, unused
        self.orig_addr.point = _read_int_le(packet, 2)
        self.dest_addr.point = _read_int_le(packet, 2)
        packet.seek(4, 1) # ProdData, unused

    def serialize(self, packet):
        packet.seek(0)
        _write_int_le(self.orig_addr.node, packet, 2)
        _write_int_le(self.dest_addr.node, packet, 2)
        _write_time_le(self.created, packet)
        _write_int_le(self.baud, packet, 2)
        _write_int_le(self.version, packet, 2)
        _write_int_le(self.orig_addr.net, packet, 2)
        _write_int_le(self.dest_addr.net, packet, 2)
        _write_int_le(self.product.code.lo, packet, 1)
        _write_int_le(self.product.rev.major, packet, 1)
        _write_str_ascii(self.passwd, packet, 8)
        _write_int_le(self.orig_addr.zone, packet, 2)
        _write_int_le(self.dest_addr.zone, packet, 2)
        _write_int_le(self.aux_net, packet, 2)
        _write_int_be(self.cap_word.first, packet, 2)
        _write_int_le(self.product.code.hi, packet, 1)
        _write_int_le(self.product.rev.minor, packet, 1)
        _write_int_le(self.cap_word.second, packet, 2)
        _write_int_le(self.orig_addr.zone, packet, 2)
        _write_int_le(self.dest_addr.zone, packet, 2)
        _write_int_le(self.orig_addr.point, packet, 2)
        _write_int_le(self.dest_addr.point, packet, 2)
        _write_int_be(0, packet, 4)

class PktBody(object):          # up to 128K (32K in DOS)
    def __init__(self, encoding=ENCODING_DEFAULT):
        self.encoding = encoding
        self.orig_addr = Addr()   # 4 bytes
        self.dest_addr = Addr()   # 4 bytes
        self.type = 0             # 2 bytes
        self.attrs = Attributes() # 2 bytes
        self.timestamp = ""       # 20 bytes 
        self.to_user = ""         # variable string, null-terminated, 36 bytes max
        self.from_user = ""       # variable string, null-terminated, 36 bytes max
        self.subject = ""         # variable string, null-terminated, 72 bytes max
        self.text = ""            # variable string, null-terminated

    def deserialize(self, packet, seek=True):
        if seek:
            packet.seek(58, 0)
        self.type = _read_int_le(packet, 2)
        self.orig_addr.node = _read_int_le(packet, 2)
        self.dest_addr.node = _read_int_le(packet, 2)
        self.orig_addr.net = _read_int_le(packet, 2)
        self.dest_addr.net = _read_int_le(packet, 2)
        self.attrs = _read_attrs(packet)
        packet.seek(2,1) # Unused cost fields
        self.timestamp = _read_str_ascii(packet, 20)
        self.to_user = _read_str_encoded_zt(packet, self.encoding)
        self.from_user = _read_str_encoded_zt(packet, self.encoding)
        self.subject = _read_str_encoded_zt(packet, self.encoding)
        self.text = _read_str_encoded_zt(packet, self.encoding).replace('\r', '\r\n')

    def serialize(self, packet, seek=True):
        if seek:
            packet.seek(58, 0)
        _write_int_le(self.type, packet, 2)
        _write_int_le(self.orig_addr.node, packet, 2)
        _write_int_le(self.dest_addr.node, packet, 2)
        _write_int_le(self.orig_addr.net, packet, 2)
        _write_int_le(self.dest_addr.net, packet, 2)
        _write_attrs(self.attrs, packet)
        _write_int_be(0, packet, 2)
        _write_str_ascii(self.timestamp, packet, 20)
        _write_str_encoded_zt(self.to_user, packet, self.encoding, 36)
        _write_str_encoded_zt(self.from_user, packet, self.encoding, 36)
        _write_str_encoded_zt(self.subject, packet, self.encoding, 72)
        _write_str_encoded_zt(self.text.replace('\r\n', '\r'), packet, self.encoding)

    @property
    def encoding(self):
        return self._encoding

    @encoding.setter
    def encoding(self, value):
        self._encoding = value


class FtnPacket(object):
    def __init__(self):
        self.header = PktHeader()
        self.body = [] # List of PktBody

    def serialize(self, packet):
        self.header.serialize(packet)
        for body in self.body:
            body.serialize(packet, seek=False)
        _write_int_be(0, packet, 2)

    def deserialize(self,packet):
        fsize = packet.seek(0,2)
        packet.seek(0)
        self.header.deserialize(packet)
        while (packet.tell() < fsize) and (packet.read(1) != b'\x00'):
            packet.seek(-1, 1)
            next_body = PktBody()
            next_body.deserialize(packet, seek=False)
            self.body.append(next_body)


def _read_int_le(fd, size):
    return int.from_bytes(fd.read(size), byteorder='little')

def _read_int_be(fd, size):
    return int.from_bytes(fd.read(size), byteorder='big')

def _write_int_le(val, fd, size):
    fd.write(val.to_bytes(size, byteorder='little'))
    return

def _write_int_be(val, fd, size):
    fd.write(val.to_bytes(size, byteorder='big'))
    return

def _read_str_ascii(fd, length):
    return fd.read(length).decode('ascii')

def _write_str_ascii(data, fd, length):
    if len(data) < length:
        out = data+'\0'*(length-len(data))
    else:
        out = data
    fd.write(out[0:length].encode('ascii'))
    return

def _read_str_encoded_zt(fd, encoding):
    stringbuf = bytearray()
    while (token := _read_int_le(fd, 1)) != 0:
        stringbuf.append(token)

    return stringbuf.decode(encoding)

def _write_str_encoded_zt(data, fd, encoding, maxlen=None):
    if (maxlen is not None) and (len(data) > maxlen):
        out = data[0:maxlen]
    else:
        out = data
    fd.write(out.encode(encoding)+b'\0')
    return

def _read_time_le(fd):
    year = _read_int_le(fd, 2)
    month = _read_int_le(fd, 2)+1 # tm_mon 0-11
    day = _read_int_le(fd, 2)
    hour = _read_int_le(fd, 2)
    minute = _read_int_le(fd, 2)
    second = _read_int_le(fd, 2)
    return datetime(year, month, day, hour, minute, second, tzinfo=ZoneInfo("UTC"))

def _write_time_le(dt, fd):
    _write_int_le(dt.year, fd, 2)
    _write_int_le(dt.month-1, fd, 2)
    _write_int_le(dt.day, fd, 2)
    _write_int_le(dt.hour, fd, 2)
    _write_int_le(dt.minute, fd, 2)
    _write_int_le(dt.second, fd, 2)
    return

def _read_attrs(fd):
    attrs_raw = _read_int_le(fd, 2)
    attrs = Attributes()
    if attrs_raw & 1:
        attrs.private = True
    if attrs_raw & 2:
        attrs.crash = True
    if attrs_raw & 4:
        attrs.received = True
    if attrs_raw & 8:
        attrs.sent = True
    if attrs_raw & 16:
        attrs.file_attached = True
    if attrs_raw & 32:
        attrs.in_transit = True
    if attrs_raw & 64:
        attrs.orphan = True
    if attrs_raw & 128:
        attrs.kill_sent = True
    if attrs_raw & 256:
        attrs.local = True
    if attrs_raw & 512:
        attrs.hold_for_pickup = True
    if attrs_raw & 2048:
        attrs.file_request = True
    if attrs_raw & 4096:
        attrs.return_receipt_request = True
    if attrs_raw & 8192:
        attrs.is_return_receipt = True
    if attrs_raw & 16384:
        attrs.audit_request = True
    if attrs_raw & 32768:
        attrs.file_update_request = True

    return attrs

def _write_attrs(attrs, fd):
    attrs_raw = 0
    if attrs.private:
        attrs_raw += 1
    if attrs.crash:
        attrs_raw += 2
    if attrs.received:
        attrs_raw += 4
    if attrs.sent:
        attrs_raw += 8
    if attrs.file_attached:
        attrs_raw += 16
    if attrs.in_transit:
        attrs_raw += 32
    if attrs.orphan:
        attrs_raw += 64
    if attrs.kill_sent:
        attrs_raw += 128
    if attrs.local:
        attrs_raw += 256
    if attrs.hold_for_pickup:
        attrs_raw += 512
    if attrs.file_request:
        attrs_raw += 2048
    if attrs.return_receipt_request:
        attrs_raw += 4096
    if attrs.is_return_receipt:
        attrs_raw += 8192
    if attrs.audit_request:
        attrs_raw += 16384
    if attrs.file_update_request:
        attrs_raw += 32768
    _write_int_le(attrs_raw, fd, 2)
    return
