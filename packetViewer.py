#!/usr/bin/env python3


import sys

from ftn_codec import FtnPacket

def attrs2names(attrs):
    attrs_lst = []
    if attrs.private:
        attrs_lst.append("Private")
    if attrs.crash:
        attrs_lst.append("Crash")
    if attrs.received:
        attrs_lst.append("Received")
    if attrs.sent:
        attrs_lst.append("Sent")
    if attrs.file_attached:
        attrs_lst.append("File Attached")
    if attrs.in_transit:
        attrs_lst.append("In Transit")
    if attrs.orphan:
        attrs_lst.append("Orphan")
    if attrs.kill_sent:
        attrs_lst.append("Kill Sent")
    if attrs.local:
        attrs_lst.append("Local")
    if attrs.hold_for_pickup:
        attrs_lst.append("Hold For Pickup")
    if attrs.file_request:
        attrs_lst.append("File Request")
    if attrs.return_receipt_request:
        attrs_lst.append("Return Receipt Request")
    if attrs.is_return_receipt:
        attrs_lst.append("Is Return Receipt")
    if attrs.audit_request:
        attrs_lst.append("Audit Request")
    if attrs.file_update_request:
        attrs_lst.append("File Update Request")

    return attrs_lst

def main():
  pkt = FtnPacket()
  with open(sys.argv[1], 'rb') as fd:
      pkt.deserialize(fd)

      print(f"Read packet {sys.argv[1].split('/')[-1]}")
      print("----------------------------------------")
      print("Header data:")
      print(f"Originating address: {pkt.header.orig_addr.zone}:{pkt.header.orig_addr.net}/{pkt.header.orig_addr.node}.{pkt.header.orig_addr.point}")
      print(f"Destination address: {pkt.header.dest_addr.zone}:{pkt.header.dest_addr.net}/{pkt.header.dest_addr.node}.{pkt.header.dest_addr.point}")
      print(f"Created at: {pkt.header.created}")
      print(f"Baud: {pkt.header.baud}")
      print(f"Version: {pkt.header.version}")
      print(f"Product code: high byte {pkt.header.product.code.hi}, low byte {pkt.header.product.code.lo}")
      print(f"Product revision: major {pkt.header.product.rev.major}, minor {pkt.header.product.rev.minor}")
      print(f"Packet password: {pkt.header.passwd}")
      print(f"Auxiliary net: {pkt.header.aux_net}")
      print(f"First capability word (big endian): {pkt.header.cap_word.first}, second capability word (little endian): {pkt.header.cap_word.second}")

      for body in pkt.body:
          print("----------------------------------------")
          print(f"Body data:")
          print(f"Type: {body.type}")
          print(f"Origin: {body.orig_addr.net}/{body.orig_addr.node}")
          print(f"Destination: {body.dest_addr.net}/{body.dest_addr.node}")
          print(f"Attributes: {','.join(attrs2names(body.attrs))}")
          print(f"Timestamp: {body.timestamp}")
          print(f"To user: {body.to_user}")
          print(f"From user: {body.from_user}")
          print(f"Subject: {body.subject}")
          print(f"Text:")
          print(body.text)

if __name__ == '__main__':
    main()
