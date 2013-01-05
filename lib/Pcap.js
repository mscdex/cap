var inherits = require('util').inherits,
    EventEmitter = require('events').EventEmitter;

var addon = require('../build/Release/pcap');

addon.Pcap.prototype.__proto__ = EventEmitter.prototype;
addon.Pcap.findDevice = addon.findDevice;
addon.Pcap.listDevices = addon.listDevices;

module.exports = addon;
