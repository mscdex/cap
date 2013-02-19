var inherits = require('util').inherits,
    EventEmitter = require('events').EventEmitter;

var addon = require('../build/Release/cap');

addon.Cap.prototype.__proto__ = EventEmitter.prototype;
addon.Cap.findDevice = addon.findDevice;
addon.Cap.deviceList = addon.deviceList;

addon.decoders = require('./Decoders');

if(process.getgid() != 0) {
	  throw new Error("Cap requires root permissions.");
}

module.exports = addon;