var debug = require('debug')('characteristic')

var events = require('events')
var util = require('util')

var characteristics = require('./characteristics.json')

function Characteristic (noble, peripheralId, serviceUuid, uuid, properties) {
  this._noble = noble
  this._peripheralId = peripheralId
  this._serviceUuid = serviceUuid

  this.uuid = uuid
  this.name = null
  this.type = null
  this.properties = properties
  this.descriptors = null

  var characteristic = characteristics[uuid]
  if (characteristic) {
    this.name = characteristic.name
    this.type = characteristic.type
  }
}

util.inherits(Characteristic, events.EventEmitter)

Characteristic.prototype.toString = function () {
  return JSON.stringify({
    uuid: this.uuid,
    name: this.name,
    type: this.type,
    properties: this.properties
  })
};

Characteristic.prototype.read = function (callback) {
  if (callback) {
    var onRead = function (data, isNotificaton, isSecurityError) {
      // only call the callback if 'read' event and non-notification
      // 'read' for non-notifications is only present for backwards compatbility
      if (!isNotificaton) {
        // remove the listener
        this.removeListener('read', onRead)

        // call the callback
        /* Profiler Code CHANGE BEGIN */
        if (isSecurityError) {
          callback(data, null)
        } else {
          callback(null, data)
        }
        /* Profiler Code CHANGE END */
      }
    }.bind(this)

    this.on('read', onRead)
  }

  this._noble.read(
    this._peripheralId,
    this._serviceUuid,
    this.uuid
  )
};

Characteristic.prototype.write = function (data, withoutResponse, callback) {
  if (process.title !== 'browser') {
    if (!(data instanceof Buffer)) {
      throw new Error('data must be a Buffer')
    }
  }

  if (callback) {
    this.once('write', function (error, isSecurityError) {
      if (isSecurityError) {
        callback(error)
      } else {
        callback(null)
      }
      
    })
  }

  this._noble.write(
    this._peripheralId,
    this._serviceUuid,
    this.uuid,
    data,
    withoutResponse
  )
};

Characteristic.prototype.broadcast = function (broadcast, callback) {
  if (callback) {
    this.once('broadcast', function () {
      callback(null)
    })
  }

  this._noble.broadcast(
    this._peripheralId,
    this._serviceUuid,
    this.uuid,
    broadcast
  )
};

// deprecated in favour of subscribe/unsubscribe
Characteristic.prototype.notify = function (notify, callback) {
  if (callback) {
    this.once('notify', function (state, isSecurityError) {
      if (isSecurityError) {
        // The argument 'state' will be the error
        callback(state, null)
      } else {
        callback(null, state)
      }
    })
  }

  this._noble.notify(
    this._peripheralId,
    this._serviceUuid,
    this.uuid,
    notify
  )
};

Characteristic.prototype.subscribe = function (callback) {
  this.notify(true, callback)
};

Characteristic.prototype.unsubscribe = function (callback) {
  this.notify(false, callback)
};

Characteristic.prototype.discoverDescriptors = function (callback) {
  if (callback) {
    this.once('descriptorsDiscover', function (descriptors) {
      callback(null, descriptors)
    })
  }

  this._noble.discoverDescriptors(
    this._peripheralId,
    this._serviceUuid,
    this.uuid
  )
};

module.exports = Characteristic
