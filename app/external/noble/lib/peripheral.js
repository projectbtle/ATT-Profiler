/* jshint loopfunc: true */
var debug = require('debug')('peripheral')

var events = require('events')
var util = require('util')

function Peripheral (noble, id, address, addressType, connectable, advertisement, rssi) {
  this._noble = noble

  this.id = id
  this.uuid = id // for legacy
  this.address = address
  this.addressType = addressType
  this.connectable = connectable
  this.advertisement = advertisement
  this.rssi = rssi
  this.services = null
  this.state = 'disconnected'
}

util.inherits(Peripheral, events.EventEmitter)

Peripheral.prototype.toString = function () {
  return JSON.stringify({
    id: this.id,
    address: this.address,
    addressType: this.addressType,
    connectable: this.connectable,
    advertisement: this.advertisement,
    rssi: this.rssi,
    state: this.state
  })
};

Peripheral.prototype.connect = function (callback) {
  if (callback) {
    this.once('connect', function (error) {
      callback(error)
    })
  }

  if (this.state === 'connected') {
    this.emit('connect', new Error('Peripheral already connected'))
  } else {
    this.state = 'connecting'
    this._noble.connect(this.id)
  }
}

Peripheral.prototype.disconnect = function (callback) {
  if (callback) {
    this.once('disconnect', function () {
      callback(null)
    })
  }
  this.state = 'disconnecting'
  this._noble.disconnect(this.id)
};

/* Profiler Code BEGIN */
Peripheral.prototype.pair = function (buffSmpReq, passkeyOpt, callbackFn) {
  var pairComplete = false
  var pairResponse = false
  var authType = null
  var assocModel = null
  var tempLtk = null
  if (callbackFn) {
    this.once('pairResult', function (error, retAuthType, retAssocModel) {
      pairResponse = true
      authType = retAuthType
      assocModel = retAssocModel
      if (error !== null) {
        debug('[PERIPHERAL] Pairing ' + error)
        pairComplete = true
        callbackFn(error, authType, assocModel)
        return
      }
    })

    this.once('ltkEdiv', function (ediv, rand, ltk) {
      pairComplete = true
      tempLtk = ltk
      callbackFn(null, authType, assocModel, ediv, rand, ltk)
    })

    // Handle the case where peripheral doesn't respond to pairing request or doesn't send LTK.
    setTimeout(function () {
      this.removeAllListeners('pairResult')
      this.removeAllListeners('ltkEdiv')
      if (pairComplete === false) {
        if (pairResponse === false) {
          console.log('[Peripheral] Executing callback with timeout.')
          callbackFn('Timeout', authType, assocModel)
        } else if (tempLtk === null) {
          if (this.state === 'disconnected') {
            console.log('[Peripheral] Executing callback with disconnect.')
            callbackFn('Disconnected', authType, assocModel)
          } else {
            console.log('[Peripheral] Executing callback with NoLtk. ' + authType + ' ' + assocModel)
            callbackFn(null, authType, assocModel, 'NoLtk')
          }          
        } else {
          console.log('[Peripheral] Executing callback with Unknown.')
          callbackFn('Unknown',authType, assocModel)
        }
      }
    }.bind(this), 5000)
  }

  if (this.state === 'paired') {
    pairComplete = true
    this.emit('pairResult', new Error('Peripheral already paired'))
  } else {
    this.state = 'pairing'
    this._noble.pair(this.id, buffSmpReq, passkeyOpt)
  }
}

Peripheral.prototype.stopPair = function (buffSmpReq, callback) {
  this.removeAllListeners('pairResult')
}
/* Profiler Code END */

Peripheral.prototype.updateRssi = function (callback) {
  if (callback) {
    this.once('rssiUpdate', function (rssi) {
      callback(null, rssi)
    })
  }

  this._noble.updateRssi(this.id)
};

Peripheral.prototype.discoverServices = function (uuids, callback) {
  if (callback) {
    this.once('servicesDiscover', function (services) {
      callback(null, services)
    })
  }

  this._noble.discoverServices(this.id, uuids)
};

Peripheral.prototype.discoverSomeServicesAndCharacteristics = function (serviceUuids, characteristicsUuids, callback) {
  this.discoverServices(serviceUuids, function (err, services) {
    var numDiscovered = 0
    var allCharacteristics = []

    for (var i in services) {
      var service = services[i]

      service.discoverCharacteristics(characteristicsUuids, function (error, characteristics) {
        numDiscovered++

        if (error === null) {
          for (var j in characteristics) {
            var characteristic = characteristics[j]

            allCharacteristics.push(characteristic)
          }
        }

        if (numDiscovered === services.length) {
          if (callback) {
            callback(null, services, allCharacteristics)
          }
        }
      })
    }
  }.bind(this))
};

Peripheral.prototype.discoverAllServicesAndCharacteristics = function (callback) {
  this.discoverSomeServicesAndCharacteristics([], [], callback)
};

Peripheral.prototype.readHandle = function (handle, callback) {
  if (callback) {
    this.once('handleRead' + handle, function (data) {
      callback(null, data)
    })
  }

  this._noble.readHandle(this.id, handle)
};

Peripheral.prototype.writeHandle = function (handle, data, withoutResponse, callback) {
  if (!(data instanceof Buffer)) {
    throw new Error('data must be a Buffer')
  }

  if (callback) {
    this.once('handleWrite' + handle, function () {
      callback(null)
    })
  }

  this._noble.writeHandle(this.id, handle, data, withoutResponse)
};

module.exports = Peripheral
