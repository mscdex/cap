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

exports.IPv4 = function(b, offset) {
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

exports.IPv6 = function(b, offset) {
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
  info.class = ((b[offset] & 0x0F) << 4) + ((b[++offset] & 0xF0) >> 4);

  // 20-bit Flow Label
  info.flowLabel = ((b[offset] & 0x0F) << 16) + b.readUInt16BE(++offset, true);
  offset += 2;

  // 16-bit Payload Length
  info.payloadlen = b.readUInt16BE(offset, true);
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
    if (curHeader === 0 || curHeader == 43 || curHeader === 60
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

  // 16-bit Length
  ret.info.length = b.readUInt16BE(offset, true);
  offset += 2;

  // 16-bit Checksum
  ret.info.checksum = b.readUInt16BE(offset, true);
  offset += 2;

  ret.offset = offset;
  return ret;
};