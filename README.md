
Description
===========

A cross-platform binding for performing packet capturing with [node.js](http://nodejs.org/).

[![Build Status](https://travis-ci.org/mscdex/cap.svg)](https://travis-ci.org/mscdex/cap)
[![Build status](https://ci.appveyor.com/api/projects/status/hypcya975yogcu9h)](https://ci.appveyor.com/project/mscdex/cap)


Requirements
============

* [node.js](http://nodejs.org/) -- v4.0.0 or newer

* For Windows: [Npcap with WinPcap compatibility](https://nmap.org/npcap/)

* For *nix: libpcap and libpcap-dev/libpcap-devel packages


Install
============

    npm install cap


Examples
========

* Capture and decode all outgoing TCP data packets destined for port 80 on the interface for 192.168.0.10:

```javascript
var Cap = require('cap').Cap;
var decoders = require('cap').decoders;
var PROTOCOL = decoders.PROTOCOL;

var c = new Cap();
var device = Cap.findDevice('192.168.0.10');
var filter = 'tcp and dst port 80';
var bufSize = 10 * 1024 * 1024;
var buffer = Buffer.alloc(65535);

var linkType = c.open(device, filter, bufSize, buffer);

c.setMinBytes && c.setMinBytes(0);

c.on('packet', function(nbytes, trunc) {
  console.log('packet: length ' + nbytes + ' bytes, truncated? '
              + (trunc ? 'yes' : 'no'));

  // raw packet data === buffer.slice(0, nbytes)

  if (linkType === 'ETHERNET') {
    var ret = decoders.Ethernet(buffer);

    if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
      console.log('Decoding IPv4 ...');

      ret = decoders.IPV4(buffer, ret.offset);
      console.log('from: ' + ret.info.srcaddr + ' to ' + ret.info.dstaddr);

      if (ret.info.protocol === PROTOCOL.IP.TCP) {
        var datalen = ret.info.totallen - ret.hdrlen;

        console.log('Decoding TCP ...');

        ret = decoders.TCP(buffer, ret.offset);
        console.log(' from port: ' + ret.info.srcport + ' to port: ' + ret.info.dstport);
        datalen -= ret.hdrlen;
        console.log(buffer.toString('binary', ret.offset, ret.offset + datalen));
      } else if (ret.info.protocol === PROTOCOL.IP.UDP) {
        console.log('Decoding UDP ...');

        ret = decoders.UDP(buffer, ret.offset);
        console.log(' from port: ' + ret.info.srcport + ' to port: ' + ret.info.dstport);
        console.log(buffer.toString('binary', ret.offset, ret.offset + ret.info.length));
      } else
        console.log('Unsupported IPv4 protocol: ' + PROTOCOL.IP[ret.info.protocol]);
    } else
      console.log('Unsupported Ethertype: ' + PROTOCOL.ETHERNET[ret.info.type]);
  }
});
```

* Send an arbitrary packet: An arp request for example

```javascript
var Cap = require('cap').Cap;
var c = new Cap();
var device = Cap.findDevice('192.168.1.200');
var filter = 'arp';
var bufSize = 10 * 1024 * 1024;
var buffer = Buffer.alloc(65535);

var linkType = c.open(device, filter, bufSize, buffer);


// To use this example, change Source Mac, Sender Hardware Address (MAC) and Target Protocol address
var buffer = Buffer.from([
    // ETHERNET
    0xff, 0xff, 0xff, 0xff, 0xff,0xff,                  // 0    = Destination MAC
    0x84, 0x8F, 0x69, 0xB7, 0x3D, 0x92,                 // 6    = Source MAC
    0x08, 0x06,                                         // 12   = EtherType = ARP
    // ARP
    0x00, 0x01,                                         // 14/0   = Hardware Type = Ethernet (or wifi)
    0x08, 0x00,                                         // 16/2   = Protocol type = ipv4 (request ipv4 route info)
    0x06, 0x04,                                         // 18/4   = Hardware Addr Len (Ether/MAC = 6), Protocol Addr Len (ipv4 = 4)
    0x00, 0x01,                                         // 20/6   = Operation (ARP, who-has)
    0x84, 0x8f, 0x69, 0xb7, 0x3d, 0x92,                 // 22/8   = Sender Hardware Addr (MAC)
    0xc0, 0xa8, 0x01, 0xc8,                             // 28/14  = Sender Protocol address (ipv4)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                 // 32/18  = Target Hardware Address (Blank/nulls for who-has)
    0xc0, 0xa8, 0x01, 0xc9                              // 38/24  = Target Protocol address (ipv4)
]);

try {
  // send will not work if pcap_sendpacket is not supported by underlying `device`
  c.send(buffer, buffer.length);
} catch (e) {
  console.log("Error sending packet:", e);
}

// TCPDUMP.  Note: Some values are changed by the network stack when the broadcast arp message is received.
//12:28:33.230319 ARP, Ethernet (len 6), IPv4 (len 4), Request who-has 192.168.1.200 tell 192.168.1.199, length 46
//0x0000:  ffff ffff ffff 848f 69b7 3d92 0806 0001  ........i.=.....
//0x0010:  0800 0604 0001 848f 69b7 3d92 c0a8 01c7  ........i.=.....
//0x0020:  0000 0000 0000 c0a8 01c8 0000 0000 0000  ................
//0x0030:  0000 0000 0000 0000 0000 0000            ............
//12:28:33.230336 ARP, Ethernet (len 6), IPv4 (len 4), Reply 192.168.1.200 is-at 74:ea:3a:a3:e6:69, length 28
//0x0000:  848f 69b7 3d92 74ea 3aa3 e669 0806 0001  ..i.=.t.:..i....
//0x0010:  0800 0604 0002 74ea 3aa3 e669 c0a8 01c8  ......t.:..i....
//0x0020:  848f 69b7 3d92 c0a8 01c7                 ..i.=.....

```

* List all network devices:

```javascript
var Cap = require('cap').Cap;

console.dir(Cap.deviceList());

// example output on Linux:
// [ { name: 'eth0',
//     addresses:
//      [ { addr: '192.168.0.10',
//          netmask: '255.255.255.0',
//          broadaddr: '192.168.0.255' } ] },
//   { name: 'nflog',
//     description: 'Linux netfilter log (NFLOG) interface',
//     addresses: [] },
//   { name: 'any',
//     description: 'Pseudo-device that captures on all interfaces',
//     addresses: [] },
//   { name: 'lo',
//     addresses:
//      [ { addr: '127.0.0.1', netmask: '255.0.0.0' },
//        { addr: '::1',
//          netmask: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' } ],
//     flags: 'PCAP_IF_LOOPBACK' } ]
```


API
===

Cap events
----------

* **packet**(< _integer_ >nbytes, < _boolean_ >truncated) - A packet `nbytes` in size was captured. `truncated` indicates if the entire packet did not fit inside the _Buffer_ supplied to open().


Cap methods
-----------

* **(constructor)**() - Creates and returns a new Cap instance.

* **open**(< _string_ >device, < _string_ >filter, < _integer_ >bufSize, < _Buffer_ >buffer) - _(void)_ - Opens `device` and starts capturing packets using `filter`. To see the syntax for `filter` check [`pcap-filter` man page](http://www.tcpdump.org/manpages/pcap-filter.7.html). `bufSize` is the size of the internal buffer that libpcap uses to temporarily store packets until they are emitted. `buffer` is a Buffer large enough to store one packet. If open() is called again without a previous call to close(), an implicit close() will occur first.

* **close**() - _(void)_ - Stops capturing.

* **setMinBytes**(< _integer_ >nBytes) - _(void)_ - **(Windows ONLY)** This sets the minimum number of packet bytes that must be captured before the full packet data is made available. If this value is set too high, you may not receive any packets until WinPCap's internal buffer fills up. Therefore it's generally best to pass in 0 to this function after calling open(), despite it resulting in more syscalls.

* **send**(< _Buffer_ >buffer[, < _integer_ >nBytes]) - _(void)_ - Sends an arbitrary, raw packet on the opened device. `nBytes` is the number of bytes in `buffer` to send (starting from position 0) and defaults to `buffer.length`.


Cap static methods
------------------

* **findDevice**([< _string_ >ip]) - _mixed_ - If `ip` is given, the (first) device name associated with `ip`, or undefined is returned if not found. If `ip` is not given, the device name of the first non-loopback device is returned.

* **deviceList**() - _array_ - Returns a list of available devices and related information.


Decoders static methods
-----------------------

The following methods are available off of `require('cap').decoders`. They parse the relevant protocol header and return an object containing the parsed information:

* Link Layer Protocols

    * **Ethernet**(< _Buffer_ buf[, < _integer_ >bufOffset=0])

* Internet Layer Protocols

    * **IPV4**(< _Buffer_ buf[, < _integer_ >bufOffset=0])

    * **IPV6**(< _Buffer_ buf[, < _integer_ >bufOffset=0])

    * **ICMPV4**(< _Buffer_ buf, < _integer_ >nbytes[, < _integer_ >bufOffset=0])

* Transport Layer Protocols

    * **TCP**(< _Buffer_ buf[, < _integer_ >bufOffset=0])

    * **UDP**(< _Buffer_ buf[, < _integer_ >bufOffset=0])

    * **SCTP**(< _Buffer_ buf, < _integer_ >nbytes[, < _integer_ >bufOffset=0])
