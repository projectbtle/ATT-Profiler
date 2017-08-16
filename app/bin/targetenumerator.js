'use strict'

// Requires.
var debug = require('../external/noble/node_modules/debug/debug')('targetenumerator')
var noble = require('../external/noble')
var events = require('events')
var util = require('util')

function TargetEnumerator (targetDeviceId) {
  this._targetId = targetDeviceId
  this._peripheral = null
  this._connected = false
  this._allCharacteristics = []
  this._enumComplete = false
}

util.inherits(TargetEnumerator, events.EventEmitter)

TargetEnumerator.prototype.scanTarget = function (callback) {
  if (noble.state === 'poweredOn') {
    debug('[TARGET-ENUMERATOR] Starting scan...')
    noble.startScanning()
  } else {
    debug('[TARGET-ENUMERATOR] Noble interface not up.')
    noble.stopScanning()
  }

  noble.on('stateChange', function (state) {
    if (state === 'poweredOn') {
      debug('[TARGET-ENUMERATOR] Noble interface state changed to powered on. Starting scan...')
      noble.startScanning()
    } else {
      debug('[TARGET-ENUMERATOR] Noble interface state changed, but not powered on.')
      noble.stopScanning()
    }
  })

  var handleTargetDiscover = function (peripheral, callback) {
    if (peripheral.id === this._targetId) {
      noble.stopScanning()
      noble.removeAllListeners('discover')
      this.emit('connecting')
      peripheral.connect(function (error) { connectPeripheral(error, peripheral, callback) })

      setTimeout(function () {
        if (this._connected === false) {
          debug('Connection timed out.')
          this.emit('connectStatus', 'Connection timed out.')
        }
      }.bind(this), 10000)

      peripheral.on('disconnect', function (error) {
        if (error === null) {
          console.warn('[TARGET-ENUMERATOR] Disconnected from target: ' + peripheral.id)
          // If service/characteristic read isn't complete, re-connect.
          if (this._enumComplete === false) {
            peripheral.connect(function (error) { connectPeripheral(error, peripheral, callback) })
          }
        }
      }.bind(this))
    }
  }.bind(this)

  var connectPeripheral = function (error, peripheral, callback) {
    this._connected = true
    if (error === null) {
      this._peripheral = peripheral
      debug('[TARGET-ENUMERATOR] Connected to target: ' + peripheral.address)
      this.emit('connectStatus', null, peripheral)
      peripheral.discoverAllServicesAndCharacteristics((serviceError, services, characteristics) => handleDiscoverServices(serviceError, services, characteristics, callback))
    } else {
      debug('[TARGET-ENUMERATOR] Error connecting to target device. ' + error)
      this.emit('connectStatus', error)
    }
  }.bind(this)

  var handleDiscoverServices = function (serviceError, services, allCharacteristics, callback) {
    if (serviceError === null) {
      var numDiscovered = 0
      var allDescriptors = []
      for (var i = 0; i < allCharacteristics.length; i++) {
        allCharacteristics[i].discoverDescriptors(function (descError, descriptors) {
          numDiscovered++
          if (descError === null) {
            for (var j = 0; j < descriptors.length; j++) {
              allDescriptors.push(descriptors[j])
            }
          } else {
            debug('[TARGET-ENUMERATOR] Error getting descriptor list from target. ' + descError)
            if (callback) {
              callback(descError, [], [], [])
            }
          }

          if (numDiscovered === allCharacteristics.length) {
            if (callback) {
              callback(null, services, allCharacteristics, allDescriptors)
            }
          }
        })
      }
    } else {
      debug('[TARGET-ENUMERATOR] Error getting list of services and characteristics from target. ' + serviceError)
      if (callback) {
        callback(serviceError, [], [], [])
      }
    }
  }

  noble.on('discover', (peripheral) => handleTargetDiscover(peripheral, callback))
}

module.exports = TargetEnumerator
