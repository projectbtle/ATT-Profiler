'use strict'

/*
    Copyright (C) 2017 projectbtle@tutanota.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Requires.
var debug = require('../external/noble/node_modules/debug/debug')('pairinghandler')
var noble = require('../external/noble')
var events = require('events')
var util = require('util')

var smpfail = require('./smp-fail.json')

const SECURITY_LEVEL_NONE = 0
const SECURITY_LEVEL_LOW = 1
const SECURITY_LEVEL_MED = 2
const SECURITY_LEVEL_HIGH = 3

function PairingHandler () {

}

util.inherits(PairingHandler, events.EventEmitter)

PairingHandler.prototype.pair = function (peripheral, targetLevel, passkeyOpt, passkeyVal, callback, pairingTimeout = 8000) {
  debug('[PAIRING HANDLER] Attempting to pair with security level ' + targetLevel)
  // this.deletePairingInfo(peripheral.address)
  var smpBuffer = this.pairingOptions(targetLevel)

  var customCallback = function (error, authType, assocModel) {
    if (error === null) {
      callback(null, authType, assocModel)
    } else if ((error === 'Timeout') || (error === 'Disconnected') || (error === 'Unknown')) {
      callback(error, authType, assocModel)
    } else {
      var textError = smpfail[error]
      if (textError === null) { textError = 'Unmapped error' }
      debug('[PAIRING-HANDLER] Pairing attempt failed at Security Level ' + targetLevel + ' with reason: ' + textError)
      callback(textError, authType, assocModel)
    }
  }.bind(this)

  peripheral.pair(smpBuffer, passkeyOpt, passkeyVal, customCallback)
}

PairingHandler.prototype.pairingOptions = function (securityLevel) {
  var smpRequestBuffer = null
  switch (securityLevel) {
    case (SECURITY_LEVEL_LOW):
      smpRequestBuffer = new Buffer([
        0x01, // SMP pairing request
        0x03, // IO capability: NoInputNoOutput
        0x00, // OOB data: Authentication data not present
        0x01, // Authentication requirement: Bonding - No MITM
        0x08, // Max encryption key size
        0x00, // Initiator key distribution: <none>
        0x01  // Responder key distribution: EncKey
      ])
      break

    case (SECURITY_LEVEL_MED):
      smpRequestBuffer = new Buffer([
        0x01, // SMP pairing request
        0x01, // IO capability: DisplayYesNo
        0x00, // OOB data: Authentication data not present
        0x01, // Authentication requirement: Bonding - No MITM
        0x10, // Max encryption key size
        0x00, // Initiator key distribution: <none>
        0x01  // Responder key distribution: LTK
      ])
      break

    case (SECURITY_LEVEL_HIGH):
      smpRequestBuffer = new Buffer([
        0x01, // SMP pairing request
        0x04, // IO capability: KeyboardDisplay
        0x00, // OOB data: Authentication data not present
        0x05, // Authentication requirement: Bonding - MITM
        0x10, // Max encryption key size
        0x00, // Initiator key distribution: <none>
        0x01  // Responder key distribution: LTK
      ])
      break

    default:
      debug('[PAIRING HANDLER] Requested level of encryption not supported.')
      smpRequestBuffer = null
  }

  return smpRequestBuffer
}

PairingHandler.prototype.deletePairingInfo = function (targetAddress) {
  if (process.platform === 'linux') {
    console.log('Making sure no stored pairing information exists.')
    var spawnSync = require('child_process').spawnSync
    var spawnOut = spawnSync('bt-device', ['-r', targetAddress])
  }
}

module.exports = PairingHandler
