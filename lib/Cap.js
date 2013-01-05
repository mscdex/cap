var inherits = require('util').inherits,
    EventEmitter = require('events').EventEmitter;

var addon = require('../build/Release/cap');

addon.Cap.prototype.__proto__ = EventEmitter.prototype;
addon.Cap.findDevice = addon.findDevice;
addon.Cap.deviceList = addon.deviceList;

module.exports = addon;
