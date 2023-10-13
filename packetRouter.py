#!/usr/bin/env python3

import os
import sys
import binascii
from pkt_decoder import PktHeader,PktBody


hdr = PktHeader()
body = PktBody()
with open(sys.argv[1], 'rb') as infile:
   try:
      hdr.deserialize(infile)
   except:
      print("Packet corrupted, bailing out")
      sys.exit(0)

   if f"{hdr.dest_addr.zone}:{hdr.dest_addr.net}/{hdr.dest_addr.node}.{hdr.dest_addr.point}" == "2:5020/2332.0":
       hdr.dest_addr.point=1
       body.deserialize(infile)
       if "AREA" in body.text:
           print("Echomail does not concern us")
           sys.exit(0)
       if "INTL" in body.text:
           splitmsg = body.text.split('\r\n')
           fmptpos = -1
           for idx, line in enumerate(splitmsg):
               if "FMPT" in line:
                   fmptpos = idx
           if fmptpos >= 0:
               splitmsg.insert(fmptpos+1, "\x01TOPT 1")
           body.text = "\r\n".join(splitmsg)

   else:
       print("Packet is not for boss point, bailing out")
       sys.exit(0)

with open(f"/var/spool/ftn/localinb/{binascii.b2a_hex(os.urandom(4)).decode('ascii')}.pkt", 'wb') as outfile:
    hdr.serialize(outfile)
    body.serialize(outfile)

sys.exit(0)
