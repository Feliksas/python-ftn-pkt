#!/usr/bin/env python3


import sys
import json
import binascii
from datetime import datetime

from ftn_codec import FtnPacket, PktBody

def parse_ftn_address(addr):
    zone_net, node_point = addr.split('/')
    zonepart = zone_net.split(':')
    nodepart = node_point.split('.')

    return {"zone": int(zonepart[0]), "net": int(zonepart[1]), "node": int(nodepart[0]), "point": int(nodepart[1]) if len(nodepart) > 1 else 0}


def main():
    packet_json = None
    with open(sys.argv[1], 'r') as fd:
        packet_json = json.load(fd)

    pkt = FtnPacket()
    
    orig_addr = parse_ftn_address(packet_json["header"]["from"])
    dest_addr = parse_ftn_address(packet_json["header"]["to"])
    
    pkt.header.orig_addr.zone = orig_addr["zone"]
    pkt.header.orig_addr.net = orig_addr["net"]
    pkt.header.orig_addr.node = orig_addr["node"]
    pkt.header.orig_addr.point = orig_addr["point"]
    
    pkt.header.dest_addr.zone = dest_addr["zone"]
    pkt.header.dest_addr.net = dest_addr["net"]
    pkt.header.dest_addr.node = dest_addr["node"]
    pkt.header.dest_addr.point = dest_addr["point"]

    pkt.header.created = datetime.utcfromtimestamp(packet_json["header"]["created"])
    pkt.header.baud = packet_json["header"]["baud"]
    pkt.header.version = packet_json["header"]["version"]
    pkt.header.passwd = packet_json["header"]["password"]

    prod_code = bytearray(binascii.unhexlify(packet_json["header"]["product"]))
    pkt.header.product.code.hi, pkt.header.product.code.lo = prod_code[0], prod_code[1]
    pkt.header.product.rev.major, pkt.header.product.rev.minor = map(lambda x: int(x), packet_json["header"]["product_version"].split('.'))
    pkt.header.aux_net = packet_json["header"]["aux_net"]
    pkt.header.cap_word.first = pkt.header.cap_word.second = int.from_bytes(binascii.unhexlify(packet_json["header"]["cap_word"]), 'big')

    for body in packet_json["body"]:
        new_body = PktBody()
        
        orig_addr = parse_ftn_address(body["from"])
        dest_addr = parse_ftn_address(body["to"])
        new_body.orig_addr.net = orig_addr["net"]
        new_body.orig_addr.node = orig_addr["node"]
        new_body.dest_addr.net = dest_addr["net"]
        new_body.dest_addr.node = dest_addr["node"]

        new_body.type = body["type"]
        new_body.attrs.private = body["attrs"]["private"] 
        new_body.attrs.crash = body["attrs"]["crash"] 
        new_body.attrs.received = body["attrs"]["received"] 
        new_body.attrs.sent = body["attrs"]["sent"] 
        new_body.attrs.file_attached = body["attrs"]["file_attached"] 
        new_body.attrs.in_transit = body["attrs"]["in_transit"] 
        new_body.attrs.orphan = body["attrs"]["orphan"] 
        new_body.attrs.kill_sent = body["attrs"]["kill_sent"] 
        new_body.attrs.local = body["attrs"]["local"] 
        new_body.attrs.hold_for_pickup = body["attrs"]["hold_for_pickup"] 
        new_body.attrs.file_request = body["attrs"]["file_request"] 
        new_body.attrs.return_receipt_request = body["attrs"]["return_receipt_request"] 
        new_body.attrs.is_return_receipt = body["attrs"]["is_return_receipt"] 
        new_body.attrs.audit_request = body["attrs"]["audit_request"] 
        new_body.attrs.file_update_request = body["attrs"]["file_update_request"]

        new_body.timestamp = body["timestamp"]
        new_body.to_user = body["recipient"]
        new_body.from_user = body["sender"]
        new_body.subject = body["subject"]
        new_body.text = '\r\n'.join(body["text"])

        pkt.body.append(new_body)


    with open(sys.argv[2], 'wb') as fd:
        pkt.serialize(fd)

if __name__ == '__main__':
    main()
