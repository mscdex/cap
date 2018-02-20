var Cap = require('../lib/Cap').Cap;
var decoders = require('../lib/Cap').decoders;
var PROTOCOL = decoders.PROTOCOL;

var path = require('path');
var assert = require('assert');
var http = require('http');

var t = -1;
var group = path.basename(__filename, '.js') + '/';
var timeout;
var localIP;

var tests = [
  { run: function() {
      var p = new Cap();
      var device = Cap.findDevice(localIP);
      var filter = [
        'tcp',
        'dst port 80',
        '(((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) > 0)'
      ].join(' and ');
      var bufSize = 10 * 1024 * 1024;
      var buffer = Buffer.alloc(65535);
      var linkType = p.open(device, filter, bufSize, buffer);
      var evCount = 0;

      p.setMinBytes && p.setMinBytes(0);
      p.once('packet', function(nbytes, trunc) {
        assert.strictEqual(nbytes > 0, true);
        p.close();
        var payload = getTCPPayload(buffer, linkType);
        assert.strictEqual(/^GET \/ HTTP\/1\.1/.test(payload), true);
        checkDone();
      });
      http.get('http://google.com', function(res) {
        res.once('end', checkDone);
        res.resume();
      });
      function checkDone() {
        if (++evCount === 2)
          next();
      }
    },
    what: 'Capture outbound HTTP traffic'
  },
];

function getTCPPayload(buffer, linkType) {
  var payload;
  if (linkType === 'ETHERNET') {
    var ret = decoders.Ethernet(buffer);
    if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
      ret = decoders.IPV4(buffer, ret.offset);
      if (ret.info.protocol === PROTOCOL.IP.TCP) {
        var datalen = ret.info.totallen - ret.hdrlen;
        ret = decoders.TCP(buffer, ret.offset);
        datalen -= ret.hdrlen;
        payload = buffer.toString('binary',
                                  ret.offset,
                                  ret.offset + datalen);
      }
    }
  }
  return payload;
}

function next() {
  clearTimeout(timeout);
  if (t > -1)
    console.log('Finished %j', tests[t].what);
  if (t === tests.length - 1)
    return;
  var v = tests[++t];
  timeout = setTimeout(function() {
    throw new Error('Capture timeout');
  }, 20 * 1000);
  console.log('Executing %j', v.what);
  v.run.call(v);
}

function makeMsg(msg, what) {
  return '[' + group + (what || tests[t].what) + ']: ' + msg;
}

process.once('uncaughtException', function(err) {
  if (t > -1 && !/(?:^|\n)AssertionError: /i.test(''+err))
    console.error(makeMsg('Unexpected Exception:'));

  throw err;
}).once('exit', function() {
  assert(t === tests.length - 1,
         makeMsg('Only finished ' + (t + 1) + '/' + tests.length + ' tests',
                 '_exit'));
});


// Determine "primary" IP address
http.get('http://google.com', function(res) {
  localIP = res.socket.address().address;
  console.log('localIP = %j', localIP);
  var interfaces = require('os').networkInterfaces();
  console.log('node interface list:\n%s',
              require('util').inspect(interfaces, false, 6));
  console.log('Cap device list:\n%s',
              require('util').inspect(Cap.deviceList(), false, 6));
  res.on('end', next);
  res.resume();
});
