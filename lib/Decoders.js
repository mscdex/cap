// Link Layer Protocols ========================================================

exports.Ethernet = function(b, offset) {
  offset || (offset = 0);
  var i;
  var ret = {
    info: {
      dstmac: '',
      srcmac: '',
      type: undefined,
      vlan: undefined,
      length: undefined
    },
    offset: undefined
  };

  // 32-bit Destination MAC Address
  for (i = 0; i < 6; ++i) {
    if (b[offset] < 16)
      ret.info.dstmac += '0';
    ret.info.dstmac += b[offset++].toString(16);
    if (i < 5)
      ret.info.dstmac += ':';
  }

  // 32-bit Source MAC Address
  for (i = 0; i < 6; ++i) {
    if (b[offset] < 16)
      ret.info.srcmac += '0';
    ret.info.srcmac += b[offset++].toString(16);
    if (i < 5)
      ret.info.srcmac += ':';
  }
  if (b[offset] === 0x81 && b[offset + 1] === 0x00) {
    // VLAN tag
    offset += 2;
    ret.info.vlan = {
      priority: b[offset] >> 0x1F,
      CFI: (b[offset] & 0x10) > 0,
      VID: ((b[offset] & 0x0F) << 8) + b[offset + 1]
    };
    offset += 2;
  }

  // 16-bit Type/Length
  var typelen = b.readUInt16BE(offset, true);
  if (typelen <= 1500)
    ret.info.length = typelen;
  else if (typelen >= 1536)
    ret.info.type = typelen;

  ret.offset = offset + 2;
  return ret;
};

// Internet Layer Protocols ====================================================

exports.IPV4 = function(b, offset) {
  offset || (offset = 0);
  var origoffset = offset, i;
  var ret = {
    info: {
      hdrlen: undefined,
      dscp: undefined,
      ecn: undefined,
      totallen: undefined,
      id: undefined,
      flags: undefined,
      fragoffset: undefined,
      ttl: undefined,
      protocol: undefined,
      hdrchecksum: undefined,
      srcaddr: '',
      dstaddr: '',
      options: undefined
    },
    hdrlen: undefined,
    offset: undefined
  };

  // 4-bit Version -- always value of 4 (skip)

  // 4-bit Internet Header Length
  ret.info.hdrlen = (b[offset++] & 0x0F);

  // 6-bit Differentiated Services Code Point
  ret.info.dscp = ((b[offset] & 0xFC) >> 2);

  // 2-bit Explicit Congestion Notification
  ret.info.ecn = (b[offset++] & 0x03);

  // 16-bit Total Length
  ret.info.totallen = b.readUInt16BE(offset, true);
  offset += 2;

  // 16-bit Identification
  ret.info.id = b.readUInt16BE(offset, true);
  offset += 2;

  // 3-bit Flags
  ret.info.flags = ((b[offset] & 0xE0) >> 5);

  // 13-bit Fragment Offset
  ret.info.fragoffset = ((b[offset++] & 0x1F) << 8) + b[offset++];

  // 8-bit Time to Live
  ret.info.ttl = b[offset++];

  // 8-bit Protocol
  ret.info.protocol = b[offset++];

  // 16-bit Header Checksum
  ret.info.hdrchecksum = b.readUInt16BE(offset, true);
  offset += 2;

  // 32-bit Source Address
  for (i = 0; i < 4; ++i) {
    ret.info.srcaddr += b[offset++];
    if (i < 3)
      ret.info.srcaddr += '.';
  }

  // 32-bit Destination Address
  for (i = 0; i < 4; ++i) {
    ret.info.dstaddr += b[offset++];
    if (i < 3)
      ret.info.dstaddr += '.';
  }

  if (ret.info.hdrlen > 5) {
    // TODO: options
  }

  ret.hdrlen = (ret.info.hdrlen * 4);
  ret.offset = origoffset + ret.hdrlen;

  // Check for zero total length due to TSO
  if (ret.info.totallen === 0)
    ret.info.totallen = (b.length - ret.offset) + ret.hdrlen;

  return ret;
};

var IPV6_EXTENSIONS = {
  0: 'Hop-by-Hop Options',
  43: 'Routing',
  44: 'Fragment',
  50: 'Encapsulating Security Payload',
  51: 'Authentication Header',
  //59: 'No Next Header',
  60: 'Destination Options',
  135: 'Mobility'
};

exports.IPV6 = function(b, offset) {
  offset || (offset = 0);
  var i;
  var ret = {
    info: {
      class: undefined,
      flowLabel: undefined,
      extensions: undefined,
      protocol: undefined,
      hopLimit: undefined,
      srcaddr: '',
      dstaddr: ''
    },
    payloadlen: undefined,
    offset: undefined
  };

  // 4-bit Version -- always value of 6 (skip)

  // 8-bit Traffic Class
  ret.info.class = ((b[offset] & 0x0F) << 4) + ((b[++offset] & 0xF0) >> 4);

  // 20-bit Flow Label
  ret.info.flowLabel = ((b[offset] & 0x0F) << 16) + b.readUInt16BE(++offset, true);
  offset += 2;

  // 16-bit Payload Length
  ret.info.payloadlen = b.readUInt16BE(offset, true);
  offset += 2;

  // 8-bit Next Header
  var nextHeader = b[offset++], curHeader = nextHeader, hdrExtLen;

  // 8-bit Hop Limit
  ret.info.hopLimit = b[offset++];

  // 128-bit Source Address
  for (i = 0; i < 16; ++i) {
    if (b[offset] < 16)
      ret.info.srcaddr += '0';
    ret.info.srcaddr += b[offset++].toString(16);
    if (i < 15)
      ret.info.srcaddr += ':';
  }

  // 128-bit Destination Address
  for (i = 0; i < 16; ++i) {
    if (b[offset] < 16)
      ret.info.dstaddr += '0';
    ret.info.dstaddr += b[offset++].toString(16);
    if (i < 15)
      ret.info.dstaddr += ':';
  }

  while (IPV6_EXTENSIONS[curHeader] !== undefined) {
    // TODO: parse extensions
    if (curHeader === 0 || curHeader === 43 || curHeader === 60
        || curHeader === 135) {
      // Header Extension Length field is in 8-byte units
      nextHeader = b[offset];
      hdrExtLen = b[offset + 1];
      offset += 8;
      offset += (8 * hdrExtLen);
    } else if (curHeader === 44) {
      nextHeader = b[offset];
      offset += 8;
    } else if (curHeader === 51) {
      // Payload Length field is in 4-byte units
      // I believe this length already excludes the Next Header and Payload
      // Length fields
      nextHeader = b[offset++];
      offset += (4 * b[offset]);
    }
    curHeader = nextHeader;
  }
  
  if (curHeader !== 59) {
    ret.info.protocol = curHeader;
    ret.offset = offset;
  }

  return ret;
};

exports.ICMPV4 = function(b, nbytes, offset) {
  offset || (offset = 0);
  var type, code, checksum, i, j;

  var ret = {
    info: undefined,
    offset: undefined
  };

  // 8-bit Type
  type = b[offset++];

  // 8-bit Code
  code = b[offset++];

  // 16-bit Header Checksum
  checksum = b.readUInt16BE(offset, true);
  offset += 2;

  var IPhdr, addr;
  if (type === 0 || type === 15 || type === 16 || type === 37) {
    // Echo reply / Information request / Information reply
    // / Domain name request

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      identifier: undefined,
      seqno: undefined
    };

    // 16-bit Identifier
    ret.info.identifier = b.readUInt16BE(offset, true);
    offset += 2;

    // 16-bit Sequence Number
    ret.info.seqno = b.readUInt16BE(offset, true);
    offset += 2;

    // For Echo reply, (Optional) data from `offset` to end ...
  } else if (type === 3 && code === 4) {
    // Destination unreachable with Next-hop MTU

    offset += 2; // skip unused part

    // 16-bit Next-hop MTU
    var mtu = b.readUInt16BE(offset, true);
    offset += 2;

    // IPv4 Header
    IPhdr = exports.IPV4(b, offset);
    offset = IPhdr.offset;

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      nextHopMTU: mtu,
      IPHeader: { info: IPhdr.info, hdrlen: IPhdr.hdrlen },
      dataOffset: offset
    };

    // First 8 bytes of original datagram's data
    offset += 8;
  } else if (type === 3 || type === 4 || type === 11) {
    // Destination unreachable (other) / Source quench / Time exceeded

    offset += 4; // skip unused part

    // IPv4 Header
    IPhdr = exports.IPV4(b, offset);
    offset = IPhdr.offset;

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      IPHeader: { info: IPhdr.info, hdrlen: IPhdr.hdrlen },
      dataOffset: offset
    };

    // First 8 bytes of original datagram's data
    offset += 8;
  } else if (type === 5) {
    // Redirect

    // 32-bit Redirected Gateway IP Address
    addr = '';
    for (i = 0; i < 4; ++i) {
      addr += b[offset++];
      if (i < 3)
        addr += '.';
    }

    // IPv4 Header
    IPhdr = exports.IPV4(b, offset);
    offset = IPhdr.offset;

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      gatewayAddr: addr,
      IPHeader: { info: IPhdr.info, hdrlen: IPhdr.hdrlen },
      dataOffset: offset
    };

    // First 8 bytes of original datagram's data
    offset += 8;
  } else if (type === 12 || type === 31 || type === 40) {
    // Parameter problem / Conversion error / Security failure

    var ptr;
    if (type === 12) {
      // 8-bit Pointer
      ptr = b[offset++];

      offset += 3; // skip unused part
    } else  if (type === 31) {
      // 32-bit Pointer
      ptr = b.readUInt32BE(offset, true);
      offset += 4;
    } else {
      offset += 2; // skip unused part
      ptr = b.readUInt16BE(offset, true);
      offset += 2;
    }

    // IPv4 Header
    IPhdr = exports.IPV4(b, offset);
    offset = IPhdr.offset;

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      pointer: ptr,
      IPHeader: { info: IPhdr.info, hdrlen: IPhdr.hdrlen },
      dataOffset: offset
    };

    if (type === 12 || type === 40) {
      // First 8 bytes of original datagram's data
      offset += 8;
    } else {
      // First 256 bytes of original datagram's data
      offset += 256;
    }
  } else if (type === 9) {
    // Router advertisement

    // 8-bit Number of Addresses
    var nAddrs = b[offset++];

    // 8-bit Address Entry Size (2 for ICMPv4)
    var entrySize = b[offset++];

    // 16-bit Lifetime
    var lifetime = b.readUInt16BE(offset, true);
    offset += 2;

    var addrs;
    if (nAddrs > 0 && entrySize === 2) {
      addrs = new Array(nAddrs);
      for (i = 0; i < nAddrs; ++i) {
        addr = '';
        for (j = 0; j < 4; ++j) {
          addr += b[offset++];
          if (j < 3)
            addr += '.';
        }
        addrs.push({ addr: addr, pref: b.readInt32BE(offset, true) });
        offset += 4;
      }
    }

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      lifetime: lifetime,
      addrs: addrs
    };
  } else if (type === 3 || type === 4 || type === 11) {
    // Destination unreachable (other) / Source quench / Time exceeded

    offset += 4; // skip unused part

    // IPv4 Header
    IPhdr = exports.IPV4(b, offset);
    offset = IPhdr.offset;

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      IPHeader: { info: IPhdr.info, hdrlen: IPhdr.hdrlen },
      dataOffset: offset
    };

    // First 8 bytes of original datagram's data
    offset += 8;
  } else if (type === 13) {
    // Timestamp

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      identifier: undefined,
      seqno: undefined,
      originate: undefined
    };

    // 16-bit Identifier
    ret.info.identifier = b.readUInt16BE(offset, true);
    offset += 2;

    // 16-bit Sequence Number
    ret.info.seqno = b.readUInt16BE(offset, true);
    offset += 2;

    // 32-bit Originate Timestamp
    ret.info.originate = b.readUInt32BE(offset, true);
    offset += 4;
  } else if (type === 14) {
    // Timestamp reply

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      identifier: undefined,
      seqno: undefined,
      originate: undefined,
      receive: undefined,
      transmit: undefined
    };

    // 16-bit Identifier
    ret.info.identifier = b.readUInt16BE(offset, true);
    offset += 2;

    // 16-bit Sequence Number
    ret.info.seqno = b.readUInt16BE(offset, true);
    offset += 2;

    // 32-bit Originate Timestamp
    ret.info.originate = b.readUInt32BE(offset, true);
    offset += 4;

    // 32-bit Receive Timestamp
    ret.info.receive = b.readUInt32BE(offset, true);
    offset += 4;

    // 32-bit Transmit Timestamp
    ret.info.transmit = b.readUInt32BE(offset, true);
    offset += 4;
  } else if (type === 17 || type === 18) {
    // Address mask request / reply

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      identifier: undefined,
      seqno: undefined,
      mask: ''
    };

    // 16-bit Identifier
    ret.info.identifier = b.readUInt16BE(offset, true);
    offset += 2;

    // 16-bit Sequence Number
    ret.info.seqno = b.readUInt16BE(offset, true);
    offset += 2;

    // 32-bit Address Mask
    for (i = 0; i < 4; ++i) {
      ret.info.mask += b[offset++];
      if (i < 3)
        ret.info.mask += '.';
    }
  } else if (type === 30) {
    // Traceroute

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      identifier: undefined,
      outHopCount: undefined,
      retHopCount: undefined,
      outLnkSpeed: undefined,
      outLnkMTU: undefined
    };

    // 16-bit Identifier
    ret.info.identifier = b.readUInt16BE(offset, true);
    offset += 2;

    offset += 2; // skip unused part

    // 16-bit Outbound Hop Count
    ret.info.outHopCount = b.readUInt16BE(offset, true);
    offset += 2;

    // 32-bit Return Hop Count
    ret.info.retHopCount = b.readUInt32BE(offset, true);
    offset += 4;

    // 32-bit Outbound Link Speed
    ret.info.outLnkSpeed = b.readUInt32BE(offset, true);
    offset += 4;

    // 32-bit Outbound Link MTU
    ret.info.outLnkMTU = b.readUInt32BE(offset, true);
    offset += 4;
  }/* else if (type === 38) {
    // Domain name reply

    ret.info = {
      type: type,
      code: code,
      checksum: checksum,
      identifier: undefined,
      seqno: undefined,
      ttl: undefined,
      names: undefined
    };

    // 16-bit Identifier
    ret.info.identifier = b.readUInt16BE(offset, true);
    offset += 2;

    // 16-bit Sequence Number
    ret.info.seqno = b.readUInt16BE(offset, true);
    offset += 2;

    // 32-bit Time-To-Live
    ret.info.ttl = b.readInt32BE(offset, true);
    offset += 2;

    if (offset < nbytes) {
      var names = [], length, ptr;
      while (true) {
        // 8-bit Length
        length = b[offset++];
        if (length === 0)
          break;
        
      }
      ret.info.names = names;
    }
  }*/ else {
    ret.info = {
      type: type,
      code: code,
      checksum: checksum
    };
    offset += 4; // skip "rest of header" part
  }

  ret.offset = offset;
  return ret;
};

// Transport Layer Protocols ===================================================

exports.TCP = function(b, offset) {
  offset || (offset = 0);
  var origoffset = offset;
  var ret = {
    info: {
      srcport: undefined,
      dstport: undefined,
      seqno: undefined,
      ackno: undefined,
      flags: undefined,
      window: undefined,
      checksum: undefined,
      urgentptr: undefined,
      options: undefined
    },
    hdrlen: undefined,
    offset: undefined
  };

  // 16-bit Source Port
  ret.info.srcport = b.readUInt16BE(offset, true);
  offset += 2;

  // 16-bit Destination Port
  ret.info.dstport = b.readUInt16BE(offset, true);
  offset += 2;

  // 32-bit Sequence Number
  ret.info.seqno = b.readUInt32BE(offset, true);
  offset += 4;

  // 32-bit Acknowledgement Number
  ret.info.ackno = b.readUInt32BE(offset, true);
  offset += 4;

  // 4-bit Data Offset
  var dataoffset = ((b[offset] & 0xF0) >> 4);

  // 3-bit Reserved (skip)

  // 9-bit Flags
  ret.info.flags = ((b[offset++] & 1) << 8) + b[offset++];

  if ((ret.info.flags & 0x10) === 0) // ACK
    ret.info.ackno = undefined;

  // 16-bit Window Size
  ret.info.window = b.readUInt16BE(offset, true);
  offset += 2;

  // 16-bit Checksum
  ret.info.checksum = b.readUInt16BE(offset, true);
  offset += 2;

  // 16-bit Urgent Pointer
  if ((ret.info.flags & 0x20) > 0) // URG
    ret.info.urgentptr = b.readUInt16BE(offset, true);
  offset += 2;

  // skip Options parsing for now ...

  ret.hdrlen = (dataoffset * 4);
  ret.offset = origoffset + ret.hdrlen;
  return ret;
};

exports.UDP = function(b, offset) {
  offset || (offset = 0);
  var ret = {
    info: {
      srcport: undefined,
      dstport: undefined,
      length: undefined,
      checksum: undefined
    },
    offset: undefined
  };

  // 16-bit Source Port
  ret.info.srcport = b.readUInt16BE(offset, true);
  offset += 2;

  // 16-bit Destination Port
  ret.info.dstport = b.readUInt16BE(offset, true);
  offset += 2;

  // 16-bit Length (header + data)
  ret.info.length = b.readUInt16BE(offset, true) - 8;
  offset += 2;

  // 16-bit Checksum
  ret.info.checksum = b.readUInt16BE(offset, true);
  offset += 2;

  ret.offset = offset;
  return ret;
};

exports.SCTP = function(b, nbytes, offset) {
  offset || (offset = 0);
  var ret = {
    info: {
      srcport: undefined,
      dstport: undefined,
      verifyTag: undefined,
      checksum: undefined,
      chunks: undefined
    },
    offset: undefined
  };

  // 16-bit Source Port
  ret.info.srcport = b.readUInt16BE(offset, true);
  offset += 2;

  // 16-bit Destination Port
  ret.info.dstport = b.readUInt16BE(offset, true);
  offset += 2;

  // 16-bit Checksum
  ret.info.checksum = b.readUInt16BE(offset, true);
  offset += 2;

  if (offset < nbytes) {
    var chunks = [], type, flags, length;
    while (offset < nbytes) {
      // 8-bit Chunk Type
      type = b[offset++];

      // 8-bit Chunk Flags
      flags = b[offset++];

      // 16-bit Chunk Length
      length = b.readUInt16BE(offset, true);
      offset += 2;

      chunks.push({
        type: type,
        flags: flags,
        offset: offset,
        length: length
      });

      offset += length;
    }
    ret.info.chunks = chunks;
  }

  ret.offset = offset;
  return ret;
};

exports.ARP = function(b, offset) {
  offset || (offset = 0);
  var ret = {
    info: {
      hardwareaddr: undefined,
      protocol: undefined,
      hdrlen: undefined,
      protlen: undefined,
      opcode: undefined,
      sendermac: '',
      senderip: '',
      targetmac: '',
      targetip: ''
    },
    offset: undefined
  };
  ret.info.hardwareaddr = b.readUInt16BE(offset, true);
  offset += 2;
  ret.info.protocol = b.readUInt16BE(offset, true);
  offset += 2;
  ret.info.hdrlen = b.readInt8(offset, true);
  offset += 1;
  ret.info.protlen = b.readInt8(offset, true);
  offset += 1;
  ret.info.opcode = b.readUInt16BE(offset, true);
  offset += 2;
  if (ret.info.hdrlen == 6 && ret.info.protlen == 4) {
    for (i = 0; i < 6; ++i) {
      ret.info.sendermac += ('00' + b[offset++].toString(16)).substr(-2);
      if (i < 5)
        ret.info.sendermac += ':';
    }

    for (i = 0; i < 4; ++i) {
      ret.info.senderip += b[offset++];
      if (i < 3)
        ret.info.senderip += '.';
    }

    for (i = 0; i < 6; ++i) {
      ret.info.targetmac += ('00' + b[offset++].toString(16)).substr(-2);
      if (i < 5)
        ret.info.targetmac += ':';
    }

    for (i = 0; i < 4; ++i) {
      ret.info.targetip += b[offset++];
      if (i < 3)
        ret.info.targetip += '.';
    }
  }
  ret.offset = offset;
  return ret;
};

// Exported Constants ==========================================================

exports.PROTOCOL = {
  ETHERNET: {
    // Taken from (as of 2012-03-16):
    //     http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.txt
   'IPV4': 2048, // Internet IP (IPv4)                                    [IANA]
   'X.75': 2049, // X.75 Internet                                [Neil_Sembower]
   'CHAOSNET': 2052, // Chaosnet                                 [Neil_Sembower]
   'X.25': 2053, // X.25 Level 3                                 [Neil_Sembower]
   'ARP': 2054, // ARP                                                    [IANA]
   'ARP-RELAY': 2056, // Frame Relay ARP                               [RFC1701]
   'TRILL': 8947, // TRILL                                             [RFC6325]
   'L2-IS-IS': 8948, // L2-IS-IS                                       [RFC6325]
   'ARP-REVERSE': 32821, // Reverse ARP                 [RFC903][Joseph_Murdock]
   'APPLETALK': 32923, // Appletalk                              [Neil_Sembower]
   'APPLETALK-AARP': 33011, // AppleTalk AARP (Kinetics)         [Neil_Sembower]
   'VLAN': 33024, // IEEE 802.1Q VLAN-tagged frames (initially Wellfleet)
   'SNMP': 33100, // SNMP                                     [Joyce_K_Reynolds]
   'XTP': 33149, // XTP                                          [Neil_Sembower]
   'IPV6': 34525, // IPv6                                                 [IANA]
   'TCPIP-COMPRESS': 34667, // TCP/IP Compression                      [RFC1144]
   'PPP': 34827, // PPP                                                   [IANA]
   'GSMP': 34828, // GSMP                                                 [IANA]
   'PPPOE-DISCOVER': 34915, // PPPoE Discovery Stage                   [RFC2516]
   'PPPOE-SESSION': 34916, // PPPoE Session Stage                      [RFC2516]
   'LOOPBACK': 36864 // Loopback                                 [Neil_Sembower]
  },
  IP: {
    // Taken from (as of 2012-10-17):
    //     http://www.iana.org/assignments/protocol-numbers/protocol-numbers.txt
    'HOPOPT': 0, // IPv6 Hop-by-Hop Option                             [RFC2460]
    'ICMP': 1, // Internet Control Message                              [RFC792]
    'IGMP': 2, // Internet Group Management                            [RFC1112]
    'GGP': 3, // Gateway-to-Gateway                                     [RFC823]
    'IPV4': 4, // IPv4 encapsulation                                   [RFC2003]
    'ST': 5, // Stream                                        [RFC1190][RFC1819]
    'TCP': 6, // Transmission Control                                   [RFC793]
    'CBT': 7, // CBT                                            [Tony_Ballardie]
    'EGP': 8, // Exterior Gateway Protocol                 [RFC888][David_Mills]
    'IGP': 9, // any private interior gateway (used by
              // [Internet_Assigned_Numbers_Authority] Cisco for their IGRP)
    'BBN-RCC-MON': 10, // BBN RCC Monitoring                     [Steve_Chipman]
    'NVP-II': 11, // Network Voice Protocol               [RFC741][Steve_Casner]
    'PUP': 12, // PUP            [Boggs, D., J. Shoch, E. Taft, and R. Metcalfe,
               //                 "PUP: An Internetwork Architecture",
               //                 XEROX Palo Alto Research Center, CSL-79-10,
               //                 July 1979; also in IEEE Transactions on
               //                 Communication, Volume COM-28, Number 4,
               //                 April 1980.]
               //                                                      [[XEROX]]
    'ARGUS': 13, // ARGUS                                   [Robert_W_Scheifler]
    'EMCON': 14, // EMCON                                    [<mystery contact>]
    'XNET': 15, // Cross Net Debugger       [Haverty, J.,
                //                           "XNET Formats for Internet Protocol
                //                            Version 4",
                //                           IEN 158, October 1980.]
                //                                                [Jack_Haverty]
    'CHAOS': 16, // Chaos                                       [J_Noel_Chiappa]
    'UDP': 17, // User Datagram                             [RFC768][Jon_Postel]
    'MUX': 18, // Multiplexing                         [Cohen, D. and J. Postel,
               //                                       "Multiplexing Protocol",
               //                                       IEN 90, USC/Information
               //                                       Sciences Institute,
               //                                       May 1979.]
               //                                                   [Jon_Postel]
    'DCN-MEAS': 19, // DCN Measurement Subsystems                  [David_Mills]
    'HMP': 20, // Host Monitoring                        [RFC869][Robert_Hinden]
    'PRM': 21, // Packet Radio Measurement                         [Zaw_Sing_Su]
    'XNS-IDP': 22, // XEROX NS IDP       ["The Ethernet, A Local Area Network: 
                   //                      Data Link Layer and Physical Layer
                   //                      Specification", AA-K759B-TK,
                   //                      Digital Equipment Corporation,
                   //                      Maynard, MA. Also as: "The Ethernet 
                   //                      - A Local Area Network",
                   //                      Version 1.0,
                   //                      Digital Equipment Corporation,
                   //                      Intel Corporation, Xerox Corporation,
                   //                      September 1980. And: "The Ethernet,
                   //                       A Local Area Network: Data Link
                   //                       Layer and Physical Layer
                   //                       Specifications",
                   //                      Digital, Intel and Xerox,
                   //                      November 1982. And: XEROX,
                   //                      "The Ethernet, A Local Area Network: 
                   //                       Data Link Layer and Physical Layer
                   //                       Specification",
                   //                      X3T51/80-50, Xerox Corporation,
                   //                      Stamford, CT., October 1980.]
                   //                                                  [[XEROX]]
    'TRUNK-1': 23, // Trunk-1                                      [Barry_Boehm]
    'TRUNK-2': 24, // Trunk-2                                      [Barry_Boehm]
    'LEAF-1': 25, // Leaf-1                                        [Barry_Boehm]
    'LEAF-2': 26, // Leaf-2                                        [Barry_Boehm]
    'RDP': 27, // Reliable Data Protocol                 [RFC908][Robert_Hinden]
    'IRTP': 28, // Internet Reliable Transaction          [RFC938][Trudy_Miller]
    'ISO-TP4': 29, // ISO Transport Protocol Class 4 [RFC905][<mystery contact>]
    'NETBLT': 30, // Bulk Data Transfer Protocol           [RFC969][David_Clark]
    'MFE-NSP': 31, // MFE Network Services Protocol   [Shuttleworth, B.,
                   //                                  "A Documentary of MFENet,
                   //                                   a National Computer
                   //                                   Network", UCRL-52317,
                   //                                   Lawrence Livermore Labs,
                   //                                   Livermore, California,
                   //                                   June 1977.]
                   //                                             [Barry_Howard]
    'MERIT-INP': 32, // MERIT Internodal Protocol            [Hans_Werner_Braun]
    'DCCP': 33, // Datagram Congestion Control Protocol                [RFC4340]
    '3PC': 34, // Third Party Connect Protocol              [Stuart_A_Friedberg]
    'IDPR': 35, // Inter-Domain Policy Routing Protocol      [Martha_Steenstrup]
    'XTP': 36, // XTP                                             [Greg_Chesson]
    'DDP': 37, // Datagram Delivery Protocol                      [Wesley_Craig]
    'IDPR-CMTP': 38, // IDPR Control Message Transport Proto [Martha_Steenstrup]
    'TP++': 39, // TP++ Transport Protocol                       [Dirk_Fromhein]
    'IL': 40, // IL Transport Protocol                           [Dave_Presotto]
    'IPV6': 41, // IPv6 encapsulation                                  [RFC2473]
    'SDRP': 42, // Source Demand Routing Protocol               [Deborah_Estrin]
    'IPV6-ROUTE': 43, // Routing Header for IPv6                 [Steve_Deering]
    'IPV6-FRAG': 44, // Fragment Header for IPv6                 [Steve_Deering]
    'IDRP': 45, // Inter-Domain Routing Protocol                     [Sue_Hares]
    'RSVP': 46, // Reservation Protocol           [RFC2205][RFC3209][Bob_Braden]
    'GRE': 47, // Generic Routing Encapsulation               [RFC1701][Tony_Li]
    'DSR': 48, // Dynamic Source Routing Protocol                      [RFC4728]
    'BNA': 49, // BNA                                             [Gary Salamon]
    'ESP': 50, // Encap Security Payload                               [RFC4303]
    'AH': 51, // Authentication Header                                 [RFC4302]
    'I-NLSP': 52, // Integrated Net Layer Security TUBA         [K_Robert_Glenn]
    'SWIPE': 53, // IP with Encryption                          [John_Ioannidis]
    'NARP': 54, // NBMA Address Resolution Protocol                    [RFC1735]
    'MOBILE': 55, // IP Mobility                               [Charlie_Perkins]
    'TLSP': 56, // Transport Layer Security Protocol using Kryptonet key
                // management
                //                                              [Christer_Oberg]
    'SKIP': 57, // SKIP                                            [Tom_Markson]
    'ICMPV6': 58, // ICMP for IPv6                                     [RFC2460]
    'IPV6-NONXT': 59, // No Next Header for IPv6                       [RFC2460]
    'IPV6-OPTS': 60, // Destination Options for IPv6                   [RFC2460]
    // 61 any host internal protocol       [Internet_Assigned_Numbers_Authority]
    'CFTP': 62, // CFTP                                [Forsdick, H., "CFTP",
                //                                      Network Message,
                //                                      Bolt Beranek and Newman,
                //                                      January 1982.]
                //                                              [Harry_Forsdick]
    // 63 any local network                [Internet_Assigned_Numbers_Authority]
    'SAT-EXPAK': 64, // SATNET and Backroom EXPAK            [Steven_Blumenthal]
    'KRYPTOLAN': 65, // Kryptolan                                     [Paul Liu]
    'RVD': 66, // MIT Remote Virtual Disk Protocol           [Michael_Greenwald]
    'IPPC': 67, // Internet Pluribus Packet Core             [Steven_Blumenthal]
    // 68 any distributed file system      [Internet_Assigned_Numbers_Authority]
    'SAT-MON': 69, // SATNET Monitoring                      [Steven_Blumenthal]
    'VISA': 70, // VISA Protocol                                   [Gene_Tsudik]
    'IPCV': 71, // Internet Packet Core Utility              [Steven_Blumenthal]
    'CPNX': 72, // Computer Protocol Network Executive         [David Mittnacht]
    'CPHB': 73, // Computer Protocol Heart Beat                [David Mittnacht]
    'WSN': 74, // Wang Span Network                            [Victor Dafoulas]
    'PVP': 75, // Packet Video Protocol                           [Steve_Casner]
    'BR-SAT-MON': 76, // Backroom SATNET Monitoring          [Steven_Blumenthal]
    'SUN-ND': 77, // SUN ND PROTOCOL-Temporary                  [William_Melohn]
    'WB-MON': 78, // WIDEBAND Monitoring                     [Steven_Blumenthal]
    'WB-EXPAK': 79, // WIDEBAND EXPAK                        [Steven_Blumenthal]
    'ISO-IP': 80, // ISO Internet Protocol                     [Marshall_T_Rose]
    'VMTP': 81, // VMTP                                          [Dave_Cheriton]
    'SECURE-VMTP': 82, // SECURE-VMTP                            [Dave_Cheriton]
    'VINES': 83, // VINES                                           [Brian Horn]
    'TTP': 84, // TTP                                              [Jim_Stevens]
    'IPTM': 84, // Protocol Internet Protocol Traffic Manager      [Jim_Stevens]
    'NSFNET-IGP': 85, // NSFNET-IGP                          [Hans_Werner_Braun]
    'DGP': 86, // Dissimilar Gateway Protocol   [M/A-COM Government Systems,
               //                                "Dissimilar Gateway Protocol
               //                                 Specification, Draft Version",
               //                                Contract no. CS901145,
               //                                November 16, 1987.]
               //                                                  [Mike_Little]
    'TCF': 87, // TCF                                       [Guillermo_A_Loyola]
    'EIGRP': 88, // EIGRP                    [Cisco Systems,
                 //                           "Gateway Server Reference Manual",
                 //                           Manual Revision B, January 10,
                 //                           1988.]
                 //                          [Guenther_Schreiner]
    'OSPFIGP': 89, // OSPFIGP              [RFC1583][RFC2328][RFC5340][John_Moy]
    'SPRITE-RPC': 90, // Sprite RPC Protocol   [Welch, B., "The Sprite Remote
                      //                        Procedure Call System",
                      //                        Technical Report,
                      //                        UCB/Computer Science Dept.,
                      //                        86/302, University of California
                      //                        at Berkeley, June 1986.]
                      //                       [Bruce Willins]
    'LARP': 91, // Locus Address Resolution Protocol                [Brian Horn]
    'MTP': 92, // Multicast Transport Protocol                 [Susie_Armstrong]
    'AX.25': 93, // AX.25 Frames                                  [Brian_Kantor]
    'IPIP': 94, // IP-within-IP Encapsulation Protocol          [John_Ioannidis]
    'MICP': 95, // Mobile Internetworking Control Pro.          [John_Ioannidis]
    'SCC-SP': 96, // Semaphore Communications Sec. Pro.            [Howard_Hart]
    'ETHERIP': 97, // Ethernet-within-IP Encapsulation                 [RFC3378]
    'ENCAP': 98, // Encapsulation Header              [RFC1241][Robert_Woodburn]
    // 99 any private encryption scheme    [Internet_Assigned_Numbers_Authority]
    'GMTP': 100, // GMTP                                                [[RXB5]]
    'IFMP': 101, // Ipsilon Flow Management Protocol                [Bob_Hinden]
                 //                                       [November 1995, 1997.]
    'PNNI': 102, // PNNI over IP                                   [Ross_Callon]
    'PIM': 103, // Protocol Independent Multicast      [RFC4601][Dino_Farinacci]
    'ARIS': 104, // ARIS                                         [Nancy_Feldman]
    'SCPS': 105, // SCPS                                          [Robert_Durst]
    'QNX': 106, // QNX                                          [Michael_Hunter]
    'A/N': 107, // Active Networks                                  [Bob_Braden]
    'IPCOMP': 108, // IP Payload Compression Protocol                  [RFC2393]
    'SNP': 109, // Sitara Networks Protocol                 [Manickam_R_Sridhar]
    'COMPAQ-PEER': 110, // Compaq Peer Protocol                   [Victor_Volpe]
    'IPX-IN-IP': 111, // IPX in IP                                      [CJ_Lee]
    'VRRP': 112, // Virtual Router Redundancy Protocol                 [RFC5798]
    'PGM': 113, // PGM Reliable Transport Protocol               [Tony_Speakman]
    // 114 any 0-hop protocol              [Internet_Assigned_Numbers_Authority]
    'L2TP': 115, // Layer Two Tunneling Protocol        [RFC3931][Bernard_Aboba]
    'DDX': 116, // D-II Data Exchange (DDX)                        [John_Worley]
    'IATP': 117, // Interactive Agent Transfer Protocol            [John_Murphy]
    'STP': 118, // Schedule Transfer Protocol               [Jean_Michel_Pittet]
    'SRP': 119, // SpectraLink Radio Protocol                    [Mark_Hamilton]
    'UTI': 120, // UTI                                          [Peter_Lothberg]
    'SMP': 121, // Simple Message Protocol                         [Leif_Ekblad]
    'SM': 122, // SM                                             [Jon_Crowcroft]
    'PTP': 123, // Performance Transparency Protocol             [Michael_Welzl]
    'ISIS': 124, // over IPv4                                  [Tony_Przygienda]
    'FIRE': 125, //                                            [Criag_Partridge]
    'CRTP': 126, // Combat Radio Transport Protocol             [Robert_Sautter]
    'CRUDP': 127, // Combat Radio User Datagram                 [Robert_Sautter]
    'SSCOPMCE': 128, //                                             [Kurt_Waber]
    'IPLT': 129, //                                                 [[Hollbach]]
    'SPS': 130, // Secure Packet Shield                          [Bill_McIntosh]
    'PIPE': 131, // Private IP Encapsulation within IP          [Bernhard_Petri]
    'SCTP': 132, // Stream Control Transmission Protocol     [Randall_R_Stewart]
    'FC': 133, // Fibre Channel                      [Murali_Rajagopal][RFC6172]
    'RSVP-E2E-IGNORE': 134, //                                         [RFC3175]
    'MOBILITY HEADER': 135, //                                         [RFC6275]
    'UDPLITE': 136, //                                                 [RFC3828]
    'MPLS-IN-IP': 137, //                                              [RFC4023]
    'MANET': 138, // MANET Protocols                                   [RFC5498]
    'HIP': 139, // Host Identity Protocol                              [RFC5201]
    'SHIM6': 140, // Shim6 Protocol                                    [RFC5533]
    'WESP': 141, // Wrapped Encapsulating Security Payload             [RFC5840]
    'ROHC': 142 // Robust Header Compression                           [RFC5858]
  }
};
for (var category in exports.PROTOCOL)
  for (var protocol in exports.PROTOCOL[category])
    exports.PROTOCOL[category][exports.PROTOCOL[category][protocol]] = protocol;