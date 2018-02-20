var EventEmitter = require('events').EventEmitter;

var addon = require('../build/Release/cap.node');

addon.Cap.prototype.__proto__ = EventEmitter.prototype;
addon.Cap.findDevice = addon.findDevice;
addon.Cap.deviceList = addon.deviceList;

addon.decoders = require('./Decoders');

module.exports = addon;
