#!/usr/bin/env python3


import sys
import json
import binascii

from ftn_codec import FtnPacket

JSONSCHEMA = {
     "header": {
        "from": "",
        "to": "",
        "created": "",
        "version": 2,
        "baud": 0,
        "password": "",
        "product": "",
        "product_version": "",
        "aux_net": "",
        "cap_word": ""
     },
     "body": [
#        {
#            "from": "",
#            "to": "",
#            "type": 2,
#            "attrs": {
#                "private": False,
#                "crash": False,
#                "received": False,
#                "sent": False,
#                "file_attached": False,
#                "in_transit": False,
#                "orphan": False,
#                "kill_sent": False,
#                "local": False,
#                "hold_for_pickup": False,
#                "file_request": False,
#                "return_receipt_request": False,
#                "is_return_receipt": False,
#                "audit_request": False,
#                "file_update_request": False
#            },
#            "timestamp": "",
#            "recipient": "",
#            "sender": "",
#            "subject": "",
#            "text": []
#        }
     ]
}

def make_ftn_address(zone, net, node, point=0):
    if point:
        return f"{zone}:{net}/{node}.{point}"
    else:
        return f"{zone}:{net}/{node}"

def main():
    pkt = FtnPacket()
    with open(sys.argv[1], 'rb') as fd:
        pkt.deserialize(fd)
  
    packet_json = JSONSCHEMA
    packet_json["header"]["from"] = make_ftn_address(
        pkt.header.orig_addr.zone,
        pkt.header.orig_addr.net,
        pkt.header.orig_addr.node,
        pkt.header.orig_addr.point,
    )
    packet_json["header"]["to"] = make_ftn_address(
        pkt.header.dest_addr.zone,
        pkt.header.dest_addr.net,
        pkt.header.dest_addr.node,
        pkt.header.dest_addr.point,
    )
    packet_json["header"]["created"] = int(pkt.header.created.timestamp())
    packet_json["header"]["baud"] = pkt.header.baud
    packet_json["header"]["version"] = pkt.header.version
    packet_json["header"]["password"] = ''.join(filter(lambda x: True if x != '\0' else False, pkt.header.passwd))
    packet_json["header"]["product"] = binascii.hexlify(bytearray((pkt.header.product.code.hi,pkt.header.product.code.lo))).decode('ascii') 
    packet_json["header"]["product_version"] = f"{str(pkt.header.product.rev.major)}.{str(pkt.header.product.rev.minor)}"
    packet_json["header"]["aux_net"] = pkt.header.aux_net
    packet_json["header"]["cap_word"] = binascii.hexlify(pkt.header.cap_word.first.to_bytes(2,'big')).decode('ascii')
 
    for body in pkt.body:
       new_body = {}
  
       new_body["from"] = make_ftn_address(
        body.orig_addr.zone,
        body.orig_addr.net,
        body.orig_addr.node,
        body.orig_addr.point,
       )

       new_body["to"] = make_ftn_address(
        body.dest_addr.zone,
        body.dest_addr.net,
        body.dest_addr.node,
        body.dest_addr.point,
       )
       new_body["type"] = body.type 
       new_body["attrs"] = {
         "private": body.attrs.private,
         "crash": body.attrs.crash,
         "received": body.attrs.received,
         "sent": body.attrs.sent,
         "file_attached": body.attrs.file_attached,
         "in_transit": body.attrs.in_transit,
         "orphan": body.attrs.orphan,
         "kill_sent": body.attrs.kill_sent,
         "local": body.attrs.local,
         "hold_for_pickup": body.attrs.hold_for_pickup,
         "file_request": body.attrs.file_request,
         "return_receipt_request": body.attrs.return_receipt_request,
         "is_return_receipt": body.attrs.is_return_receipt,
         "audit_request": body.attrs.audit_request,
         "file_update_request": body.attrs.file_update_request
       } 
       new_body["timestamp"] = body.timestamp
       new_body["recipient"] = body.to_user
       new_body["sender"] = body.from_user
       new_body["subject"] = body.subject
       new_body["text"] = body.text.split('\r\n')
       packet_json["body"].append(new_body)
  
  
    with open(sys.argv[2], 'w') as fd:
        json.dump(packet_json, fd, indent=4)        

if __name__ == '__main__':
    main()
