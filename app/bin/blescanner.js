'use strict'

// Requires.
var debug = require('../external/noble/node_modules/debug/debug')('blescanner')
var noble = require('../external/noble')
var events = require('events')
var util = require('util')

function BleScanner () {
    this._bleDevices = []
}

util.inherits(BleScanner, events.EventEmitter)

BleScanner.prototype.getDevices = function (scanTime) {
  if (noble.state === 'poweredOn') {
    debug('[BLE-SCANNER] Starting scan...')
    noble.startScanning([], true)
  } else {
    debug('[BLE-SCANNER] Noble interface not up.')
    noble.stopScanning()
  }

  noble.on('stateChange', function (state) {
    if (state === 'poweredOn') {
      debug('[BLE-SCANNER] Noble interface state changed to powered on. Starting scan...')
      noble.startScanning([], true)
    } else {
      debug('[BLE-SCANNER] Noble interface state changed, but not powered on.')
      noble.stopScanning()
    }
  })

  var notifyScanStart = function () { this.emit('bleScanStart') }.bind(this)
  noble.on('scanStart', notifyScanStart)

  var handleNewDiscover = function (peripheral) {
    if (this._bleDevices.find(o => o.address === peripheral.address) === undefined) {
      this._bleDevices.push({name:peripheral.advertisement.localName, id:peripheral.id, address:peripheral.address, connectable: peripheral.connectable})
      this.emit('bleScanDiscover', {name:peripheral.advertisement.localName, id:peripheral.id, address:peripheral.address, connectable: peripheral.connectable})
      debug('[BLE-SCANNER] New peripheral: ' + peripheral.address)
    } else if ((peripheral.advertisement.localName !== undefined) && (this._bleDevices.find(o => ((o.name === undefined) && (o.address === peripheral.address))))) {
      // Takes care of the case where device name may not have been advertised/received correctly the first time.
      var oldPeripheral = this._bleDevices.find(o => ((o.name === undefined) && (o.address === peripheral.address)))
      this._bleDevices.splice(this._bleDevices.indexOf(oldPeripheral, 1))
      this._bleDevices.push({name:peripheral.advertisement.localName, id:peripheral.id, address:peripheral.address, connectable: peripheral.connectable})
      this.emit('bleScanUpdate', {name:peripheral.advertisement.localName, id:peripheral.id, address:peripheral.address, connectable: peripheral.connectable})
      debug('[BLE-SCANNER] Updated parameters for peripheral: ' + peripheral.address)
    }
  }.bind(this)
  noble.on('discover', (peripheral) => handleNewDiscover(peripheral))

  // Stop scanning after a certain amount of time.
  setTimeout(function () {
    noble.stopScanning()
    noble.removeAllListeners()
    this.emit('bleScanComplete', this._bleDevices)
    this._bleDevices = []
  }.bind(this), scanTime)
}

BleScanner.prototype.stopScan = function () {
  noble.stopScanning()
  noble.removeAllListeners('stateChange')
  noble.removeAllListeners('discover')
}

module.exports = BleScanner
