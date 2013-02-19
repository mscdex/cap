
Description
===========

A cross-platform binding for performing packet capturing with [node.js](http://nodejs.org/).

This binding is tested on Windows and Linux.


Requirements
============

* [node.js](http://nodejs.org/) -- v0.8.0 or newer

* For Windows: [WinPcap](http://www.winpcap.org/install/default.htm)

* For *nix: libpcap and libpcap-dev packages


Install
============

    npm install cap


Examples
========

* Capture and decode all outgoing TCP data packets destined for port 80 on the interface for 192.168.0.10:

```javascript
var Cap = require('cap').Cap,
    decoders = require('cap').decoders,
    PROTOCOL = decoders.PROTOCOL;

var c = new Cap(),
    device = Cap.findDevice('192.168.0.10'),
    filter = 'tcp and dst port 80',
    bufSize = 10 * 1024 * 1024,
    buffer = new Buffer(65535);

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

* **open**(< _string_ >device, < _string_ >filter, < _integer_ >bufSize, < _Buffer_ >buffer) - _(void)_ - Opens `device` and starts capturing packets using `filter`. `bufSize` is the size of the internal buffer that libpcap uses to temporarily store packets until they are emitted. `buffer` is a Buffer large enough to store one packet. If open() is called again without a previous call to close(), an implicit close() will occur first.

* **close**() - _(void)_ - Stops capturing.

* **setMinBytes**(< _integer_ >nBytes) - _(void) - **(Windows ONLY)** This sets the minimum number of packet bytes that must be captured before the full packet data is made available. If this value is set too high, you may not receive any packets until WinPCap's internal buffer fills up. Therefore it's generally best to pass in 0 to this function after calling open(), despite it resulting in more syscalls.


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
