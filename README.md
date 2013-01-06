
Description
===========

A binding for performing packet capturing with [node.js](http://nodejs.org/).

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

* Capture all outgoing TCP data packets destined for port 80 on the interface for 192.168.0.10:

```javascript
var Cap = require('cap').Cap;

var c = new Cap(),
    device = Cap.findDevice('192.168.0.10'),
    filter = 'tcp and dst port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) > 0)',
    bufSize = 10 * 1024 * 1024,
    buffer = new Buffer(65535);

p.open(device, filter, bufSize, buffer);
p.on('packet', function(nbytes, trunc) {
  console.log('packet: length ' + nbytes + ' bytes, truncated? '
              + (trunc ? 'yes' : 'no'));
  // raw packet data === buffer.slice(0, nbytes)
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


Cap static methods
------------------

* **findDevice**([< _string_ >ip]) - _mixed_ - If `ip` is given, the (first) device name associated with `ip`, or undefined if not found, is returned. Otherwise the device name of the first non-loopback device is returned.

* **deviceList**() - _array_ - Returns a list of available devices and related information.


TODO
====

* Packet decoding?
