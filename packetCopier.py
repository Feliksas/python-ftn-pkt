#!/usr/bin/env python3


import sys

from ftn_codec import FtnPacket

def main():
  pkt = FtnPacket()
  with open(sys.argv[1], 'rb') as fd:
      pkt.deserialize(fd)

  with open(sys.argv[2], 'wb') as fd:
      pkt.serialize(fd)

if __name__ == '__main__':
    main()
