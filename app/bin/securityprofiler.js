'use strict'

// Requires.
var debug = require('../external/noble/node_modules/debug/debug')('securityprofiler')
var events = require('events')
var util = require('util')
var attErrors = require('./att-errors.json')

function SecurityProfiler () {

}

util.inherits(SecurityProfiler, events.EventEmitter)

SecurityProfiler.prototype.checkCharacteristics = function (characteristic, accessType, callback) {
  switch (accessType) {
    case ('read'):
      this.readCharacteristics(characteristic, callback)
      break
    case ('notify'):
      this.subscribeCharacteristics(characteristic, callback)
      break
    case ('write'):
      this.writeCharacteristics(characteristic, callback)
      break
  }
}

SecurityProfiler.prototype.readCharacteristics = function (characteristic, callback) {
  var read = false
  var outputObject = {serviceUuid: characteristic._serviceUuid, characteristicUuid: characteristic.uuid, error: null, value: null}
  console.log('[SECURITY-PROFILER] Attempting to read characteristic ' + characteristic.uuid)
  characteristic.read(function (error, data) {
    read = true
    this.outputHandler('read', characteristic.uuid, error, data, outputObject, callback)
  }.bind(this))

  setTimeout(function () {
    if (read === false) {
      this.timeoutHandler('read', characteristic.uuid, outputObject, callback)
    }
  }.bind(this), 8000)
}

SecurityProfiler.prototype.subscribeCharacteristics = function (characteristic, callback) {
  var notified = false
  var outputObject = {serviceUuid: characteristic._serviceUuid, characteristicUuid: characteristic.uuid, error: null, value: null}
  console.log('[SECURITY-PROFILER] Attempting to subscribe to characteristic ' + characteristic.uuid)
  characteristic.subscribe(function (error, data) {
    notified = true
    this.outputHandler('notify', characteristic.uuid, error, data, outputObject, callback)
  }.bind(this))

  setTimeout(function () {
    if (notified === false) {
      this.timeoutHandler('notify', characteristic.uuid, outputObject, callback)
    }
  }.bind(this), 8000)
}

SecurityProfiler.prototype.writeCharacteristics = function (characteristic, callback) {
  var written = false
  var outputObject = {serviceUuid: characteristic._serviceUuid, characteristicUuid: characteristic.uuid, error: null, value: null}
  console.log('[SECURITY-PROFILER] Attempting to write characteristic ' + characteristic.uuid)
  characteristic.write(new Buffer([0x01]), false, function (error, data) {
    written = true
    this.outputHandler('write', characteristic.uuid, error, data, outputObject, callback)
  }.bind(this))

  setTimeout(function () {
    if (written === false) {
      this.timeoutHandler('write', characteristic.uuid, outputObject, callback)
    }
  }.bind(this), 8000)
}

SecurityProfiler.prototype.outputHandler = function (action, uuid, error, data, outputObject, callback) {
  if (error === null) {
    if (action === 'read') {
      var dataString = data.toString('hex')
      outputObject['value'] = dataString
      console.log('[SECURITY-PROFILER] Read value 0x' + dataString + ' from characteristic ' + uuid)
    } else if (action === 'notify') {
      if (data !== undefined) {
        console.log('[SECURITY-PROFILER] Received notification value ' + data.toString() + ' from characteristic ' + uuid)
      }
    } else if (action === 'write') {
      console.log('[SECURITY-PROFILER] Wrote value to characteristic ' + uuid)
    }
    // Handle callback.
    if (callback) {
      callback(null, outputObject, action)
    }
  } else {
    var strError = error.toString(16)
    var textError = attErrors[strError]
    outputObject['error'] = error
    var actionString = action[0].toUpperCase() + action.substring(1)
    console.log('[SECURITY-PROFILER] ' + actionString + ' attempt for characteristic ' + uuid + ' failed. Error: ' + textError)
    if (callback) {
      callback(outputObject, null, action)
    }
  }
}

SecurityProfiler.prototype.timeoutHandler = function (action, uuid, outputObject, callback) {
  outputObject['error'] = 'Timeout'
  var actionString = action[0].toUpperCase() + action.substring(1)
  console.log('[SECURITY-PROFILER] ' + actionString + ' attempt for characteristic ' + uuid + ' failed. Error: Unknown or timeout')
  if (callback) {
    callback(outputObject, null, action)
  }
}

module.exports = SecurityProfiler
