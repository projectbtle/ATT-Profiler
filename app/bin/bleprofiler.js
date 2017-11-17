// Requires
var readline = require('readline')
var util = require('util')
var events = require('events')
var fs = require('fs')
var BleScanner = require('./blescanner')
var TargetEnumerator = require('./targetenumerator')
var SecurityProfiler = require('./securityprofiler')
var PairingHandler = require('./pairinghandler')
var ObjectHandler = require('./objecthandler')

const INDEX_RESCAN = 98
const INDEX_LONGSCAN = 99
const SECURITY_LEVEL_NONE = 0
const SECURITY_LEVEL_LOW = 1
const SECURITY_LEVEL_MED = 2
const SECURITY_LEVEL_HIGH = 3

// Authentication types.
var SMP_AUTH_LEGACY = 0
var SMP_AUTH_LESC = 1

// Association Models.
var SMP_MODEL_JUSTWORKS = 0
var SMP_MODEL_PASSKEY = 1
var SMP_MODEL_NUMERIC = 2
var SMP_MODEL_OOB = 3

// Passkey pairing - options for PIN.
var passkeyOptions = require('./passkey-options.json')

var SMP_PASSKEY_MANUAL = passkeyOptions["SMP_PASSKEY_MANUAL"][1]     // Fixed passkey.
var SMP_PASSKEY_DYNAMIC= passkeyOptions["SMP_PASSKEY_DYNAMIC"][1]        // Dynamic passkey.
var SMP_PASSKEY_DICTIONARY = passkeyOptions["SMP_PASSKEY_DICTIONARY"][1]  // Try passkey values from dictionary.

// Startup.
var BleProfiler = function (limitToProperty, includeRead, includeWrite, includeNotify, passkeyOpt, passkeyVal, outputFileName) {
  this._bleScanner = new BleScanner()
  this._securityProfiler = new SecurityProfiler()
  this._pairingHandler = new PairingHandler()
  this._objectHandler = new ObjectHandler()
  this._targetEnumerator = null
  this._functionToRun = null
  this._hciInterfaceUp = false
  this._checksComplete = false
  this._limitToProperty = true
  this._passkeyOpt = passkeyOpt
  this._passkeyVal = passkeyVal
  this._outputFileName = outputFileName
  this._targetDevice = null
  this._state = 'disconnected'
  this._services = null
  this._characteristics = null
  this._descriptors = null
  this._outputJsonObject = {}
  this._currentSecLevel = SECURITY_LEVEL_NONE

  this._accessTypes = []
  this._attributeAccess = []

  // Only test for writes if user asks for it.
  if (includeWrite === true) {
    this._accessTypes.push('write')
    this._attributeAccess.push('write')
  }

  if (includeRead === true) {
    this._accessTypes.push('read')
    this._attributeAccess.push('read')
  }

  if (includeNotify === true) {
    this._accessTypes.push('notify')
    this._attributeAccess.push('notify')
  }

  // If the user hasn't specified anything, then default to read.
  if (this._accessTypes.length === 0) {
    this._accessTypes.push('read')
    this._attributeAccess.push('read')
  }
  // If we want to limit checks to only those characteristics
  //   that have the relevant access in their properties list.
  if (limitToProperty === false) {
    this._limitToProperty = false
  }

  this._numCharChecked = {}
  this._numCharCheckable = {}
  for (var x in this._accessTypes) {
    this._numCharChecked[this._accessTypes[x]] = 0
    this._numCharCheckable[this._accessTypes[x]] = 0
  }

  this._totalAccessTypesChecked = 0
  this._checkQueue = []
  this._currentCheck = null
  this._timeoutCount = 0
  this._timeoutQueue = []

  // Read passwords from file if dictionary tries are required.
  if (this._passkeyOpt === SMP_PASSKEY_DICTIONARY) {
    this._dictionary = true
    this._dictionaryCount = 0

    this._pinArray = fs.readFileSync('./app/bin/pins.txt').toString().split("\n")
    for (var x = 0; x < this._pinArray.length; x++) {
      if (this._pinArray[x] === '') {
        this._pinArray.splice(x,1)
        x--
      }
    }
    this._passkeyVal = this._pinArray[this._dictionaryCount]
  }
}

util.inherits(BleProfiler, events.EventEmitter)

BleProfiler.prototype.scanForDevices = function (scanTime) {
  this._bleScanner.getDevices(scanTime)

  this._bleScanner.once('bleScanStart', function () {
    this._hciInterfaceUp = true
    console.log('Scanning for BLE devices...\n')
  }.bind(this))

  // If we don't see a scan start notification within a few seconds,
  //  it probably means the HCI interface is not up.
  setTimeout(function () {
    if (this._hciInterfaceUp === false) {
      console.log('Have not received scanning notification from HCI interface yet.')
      console.log('Please make sure a BLE-interface is available and try again.\n')
      this._bleScanner.removeAllListeners()
      process.exit()
    }
  }.bind(this), 4000)

  this._bleScanner.once('bleScanComplete', function (foundDevices) {
    this._bleScanner.removeAllListeners()
    const chooseTarget = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false
    })

    if (foundDevices.length > 0) {
      console.log('\nThe following BLE devices were found:')
      console.log('\n\t' + 'Option')
      var devIndex, devName, devAddress, devNotConnectable
      for (var i = 0; i < foundDevices.length; i++) {
        devIndex = i + 1
        devName = (foundDevices[i].name === undefined) ? '[Name Unknown]' : foundDevices[i].name
        devAddress = foundDevices[i].address.toUpperCase()
        devNotConnectable = (foundDevices[i].connectable === true) ? '' : '[Not Connectable]'
        console.log('\t' + devIndex + '\t' + devName + '\t' + devAddress + '\t' + devNotConnectable)
      }
    } else {
      console.log('\nNo BLE devices found. Make sure your device is powered up, BLE-capable, and has Bluetooth turned on.')
      console.log('\n\t' + 'Option')
    }
    console.log('\t' + INDEX_RESCAN + '\tRescan' + '\n' + '\t' + INDEX_LONGSCAN + '\tScan for longer')
    chooseTarget.question('\nType in the option number of your choice and hit ENTER: ', (answer) => processUserChoice(answer, foundDevices))
  }.bind(this))

  var processUserChoice = function (userChoice, foundDevices) {
    if ((parseInt(userChoice, 10) >= 0) && ((parseInt(userChoice, 10) === INDEX_RESCAN) || (parseInt(userChoice, 10) === INDEX_LONGSCAN) || ((parseInt(userChoice, 10) - 1) < foundDevices.length))) {
        // Continue
    } else {
      console.log('\nInvalid choice. Exiting...')
      process.exit()
    }

    if (parseInt(userChoice, 10) === INDEX_RESCAN) {
      this.scanForDevices(5000)
    } else if (parseInt(userChoice, 10) === INDEX_LONGSCAN) {
      this.scanForDevices(10000)
    } else if (foundDevices[parseInt(userChoice, 10) - 1].connectable !== true) {
      console.log('\nSelected device is not connectable. Exiting...')
      process.exit()
    } else {
      this._bleScanner.removeAllListeners()
      this._outputJsonObject['deviceDetails'] = foundDevices[parseInt(userChoice, 10) - 1]
      connectToTarget(this._outputJsonObject['deviceDetails'].id, false, startChecks)
    }
  }.bind(this)

  var startChecks = function () {
    var outObj = this._objectHandler.createTargetObject(this._outputJsonObject, this._services, this._characteristics, this._descriptors, this._accessTypes)
    this._outputJsonObject = outObj['json']

    if (this._limitToProperty === true) {
      this._numCharCheckable = outObj['num']
    } else {
      // Check all characteristics.
      for (var m in this._attributeAccess) {
        var access = this._attributeAccess[m]
        // Only check applicable characteristic for notify.
        //   It slows things down too much if we check all.
        if (access === 'notify') {
          this._numCharCheckable[access] = outObj['num'][access]
        } else {
          this._numCharCheckable[access] = this._characteristics.length
        }
      }
    }

    checkAllCharacteristics(false)
  }.bind(this)

  var connectToTarget = function (targetId, reconnect = false, functionToRun) {
    this._reconnect = reconnect
    if (this._reconnect === true) {
      this._targetEnumerator = null
    }
    this._targetEnumerator = new TargetEnumerator(targetId)

    this._targetEnumerator.scanTarget(function (error, services, characteristics, descriptors) {
      if (error === null) {
        if (this._reconnect === false) {
          console.log('Obtained list of services, characteristics and descriptors from target')
        }
        this._services = services
        this._characteristics = characteristics
        this._descriptors = descriptors

        if (functionToRun) {
          functionToRun()
        }
      } else {
        console.log('Error enumerating services/characteristics/descriptors: ' + error)
      }
    }.bind(this))

    this._targetEnumerator.once('connecting', function () {
      if (this._reconnect === false) {
        console.log('\nAttempting to connect')
      } else {
        console.log('\nAttempting to reconnect')
      }
    }.bind(this))

    this._targetEnumerator.once('connectStatus', function (error, device) {
      if (error === null) {
        this._targetDevice = device

        this._targetDevice.once('disconnect', function () {
          console.log('Device disconnected')
          this._targetDevice = null
         /* connectToTarget(this._outputJsonObject['deviceDetails'].id, true, function () {
            this.emit('autoReconnected')
          }.bind(this)) */
        })

        var address = device.address.toUpperCase()
        if (this._reconnect === false) {
          console.log('\nConnected to target: ' + address)
        } else {
          console.log('\nReconnected to target: ' + address)
        }
      } else {
        console.log('\nError connecting to target: ' + error)
        process.exit()
      }
    }.bind(this))
  }.bind(this)

  var checkAllCharacteristics = function (limitToNonNull) {
    for (var x in this._attributeAccess) {
      var accessType = this._attributeAccess[x]
      // If there aren't any attributes to check for a certain access type, then skip to end.
      if (this._numCharCheckable[accessType] === 0) {
        checkAllParams(accessType)
      }
      for (var i in this._services) {
        for (var j in this._characteristics) {
          var currService = this._services[i]
          var currCharacteristic = this._characteristics[j]
          if (currCharacteristic._serviceUuid === currService.uuid) {
            checkCharacteristic(currService, currCharacteristic, accessType, limitToNonNull)
          }
        }
      }
    }
    handleQueue()
  }.bind(this)

  var handleQueue = function () {
    // Check whether the previous request has caused a disconnect.
    if (this._targetDevice.state === 'disconnected') {
      setTimeout(function () {
        connectToTarget(this._outputJsonObject['deviceDetails'].id, true, handleQueue)
      }.bind(this), 3000)
      return
    }
    if (this._currentCheck === null) {
      this._currentCheck = this._checkQueue.shift()
    }

    var currCharacteristic = this._currentCheck.characteristic
    var accessType = this._currentCheck.access
    var callbackFn = this._currentCheck.callback
    this._securityProfiler.checkCharacteristics(currCharacteristic, accessType, function (err, data, access) {
      // Make a note of the number of timeouts.
      if (err) {
        if (err.error === 'Timeout') {
          this._timeoutCount++
          this._timeoutQueue.push(this._currentCheck)
        }
      }

      // TODO: check whether the timeouts are consecutive?
      if (this._timeoutCount > 2) {
        this._currentCheck = null
        // Push the timedout commands to the end of the queue, to reattempt.
        for (var t in this._timeoutQueue) {
          var timeoutCommand = this._timeoutQueue[t]
          this._checkQueue.push(timeoutCommand)
          // Decrement the relevant "access checked" counter.
          this._numCharChecked[timeoutCommand.access]--
        }

        // Reset the values.
        this._timeoutCount = 0
        this._timeoutQueue = []

        // Disconnect the device, as it's probably stopped responding.
        //  TODO: Would need to pair upon reconnect, if security level is not 0.
        console.log('Too many timeouts. Disconnecting and reconnecting.')
        this._targetDevice.disconnect()

        setTimeout(function () {
          connectToTarget(this._outputJsonObject['deviceDetails'].id, true, handleQueue)
        }.bind(this), 3000)
      } else {
        // Execute callback.
        callbackFn(err, data, access)

        // Execute next command in queue.
        if (this._checkQueue.length > 0) {
          this._currentCheck = null
          this._currentCheck = this._checkQueue.shift()
          handleQueue()
        }
      }
    }.bind(this))
  }.bind(this)

  var addToQueue = function (currCharacteristic, accessType, callback) {
    this._checkQueue.push({
      characteristic: currCharacteristic,
      access: accessType,
      callback: callback
    })
  }.bind(this)

  var checkCharacteristic = function (currService, currCharacteristic, accessType, limitToNonNull) {
    var checkObject = this._outputJsonObject['Services'][currService.uuid]['Characteristics'][currCharacteristic.uuid]['security'][accessType]

    // Common callback function.
    var callback = function (err, data, access) {
      handleSecurityProfilerOutput(err, data, access)
    }

    // Only add to command queue if certain conditions are satisfied.
    if (this._limitToProperty === true) {
      // Only try to access characteristic if it actually has the relevant access type set.
      if (checkObject['applicable'] === true) {
        if (limitToNonNull === true) {
          // Only check the characteristic if we previously have not been able to.
          if (checkObject['error'] !== null) {
            addToQueue(currCharacteristic, accessType, callback)
          }
        } else {
          addToQueue(currCharacteristic, accessType, callback)
        }
      }
    } else {
      // Check all characteristics.
      if (limitToNonNull === true) {
        // Only check the characteristic if we previously have not been able to.
        if (checkObject['error'] !== null) {
          if (accessType === 'notify') {
            if (checkObject['applicable'] === true) {
              addToQueue(currCharacteristic, accessType, callback)
            }
          } else {
            addToQueue(currCharacteristic, accessType, callback)
          }
        }
      } else {
        if (accessType === 'notify') {
          if (checkObject['applicable'] === true) {
            addToQueue(currCharacteristic, accessType, callback)
          }
        } else {
          addToQueue(currCharacteristic, accessType, callback)
        }
      }
    }
  }.bind(this)

  var handleSecurityProfilerOutput = function (errorObject, securityObject, access) {
    this._numCharChecked[access]++
    this._outputJsonObject = this._objectHandler.updateJsonObject(this._outputJsonObject, this._services, this._characteristics, access, this._currentSecLevel, errorObject, securityObject, this._currAuthType, this._currAssocModel, this._fixedPIN)
    checkAllParams(access)
  }.bind(this)

  var checkAllParams = function (actionType) {
    // Once all characteristic access types have been checked:
    if (this._numCharChecked[actionType] === this._numCharCheckable[actionType]) {
      this._totalAccessTypesChecked++
      if (this._totalAccessTypesChecked === this._attributeAccess.length) {
        // Reset queues.
        this._checkQueue = []
        this._timeoutQueue = []
        this._currentCheck = null
        this._timeoutCount = 0

        // Check if additional security is required.
        loopCheckSecurity()
      }
    }
  }.bind(this)

  var loopCheckSecurity = function () {
    if (this._currentSecLevel === SECURITY_LEVEL_HIGH) {
      finalOutput()
    } else {
      console.log('Current security Level: ' + this._currentSecLevel)
      // Reset checking values.
      for (var x in this._accessTypes) {
        this._numCharChecked[this._accessTypes[x]] = 0
        this._numCharCheckable[this._accessTypes[x]] = 0
      }
      this._totalAccessTypesChecked = 0

      var securityIncreaseReqd = false
      var securityCheckObj = this._objectHandler.checkSecurityRequired(this._outputJsonObject, this._services, this._characteristics, this._accessTypes)
      securityIncreaseReqd = securityCheckObj.security
      this._numCharCheckable = securityCheckObj.checks

      if (securityIncreaseReqd === true) {
        console.log('Increased security required.')
        increaseSecurity()
      } else {
        if (this._currentSecLevel === SECURITY_LEVEL_NONE) {
          console.log('All characteristics accessed with no security.')
        }
        finalOutput()
      }
    }
  }.bind(this)

  var increaseSecurity = function (increaseSec = true) {
    if (increaseSec === true) {
      this._currentSecLevel++
    }

    var callback = function (error, authType, assocModel) {
      this._currAuthType = authType
      this._currAssocModel = assocModel

      if (error) {
        // If it's to do with passkey entry and we have dictionary tries enabled.
        if ((this._dictionary === true) && (this._dictionaryCount < this._pinArray.length) && ((error === 'Passkey Entry Failed') || (error === 'Confirm Value Failed'))) {
          this._dictionaryCount++
          this._passkeyVal = this._pinArray[this._dictionaryCount]
          increaseSecurity(false)
        } else {
          console.log('Pairing attempt failed at Security Level ' + this._currentSecLevel + '. Pairing error: ' + error)
          if (this._currentSecLevel < SECURITY_LEVEL_HIGH) {
            increaseSecurity()
          } else {
            // No use in re-checking, because pairing at highest level failed.
            this._outputJsonObject = this._objectHandler.updateFinalSecurity(this._outputJsonObject, this._services, this._characteristics, this._accessTypes, this._currentSecLevel, this._currAuthType, this._currAssocModel)
            finalOutput()
          }
        }        
      } else {
        // If a fixed PIN was used.
        if (this._passkeyVal !== null) {
          this._fixedPIN = true
        }
        console.log('Pairing ok')
        this._state = 'paired'
        checkAllCharacteristics(true)
      }
    }.bind(this)

    console.log('Disconnecting from device and re-connecting. please wait...')
    this._targetDevice.disconnect()

    // Wait a few seconds before reconnecting
    setTimeout(function () {
      connectToTarget(this._outputJsonObject['deviceDetails'].id, true, function () {
        this.emit('reconnected')
      }.bind(this))

      this.once('reconnected', function () {
        console.log('Now attempting to pair at Security Level ' + this._currentSecLevel)
        this._pairingHandler.pair(this._targetDevice, this._currentSecLevel, this._passkeyOpt, this._passkeyVal, callback)
      })
    }.bind(this), 3000)
  }.bind(this)

  var finalOutput = function () {
    console.log('Checked security for all characteristics.\nWriting output to file now. Please wait...')
    fs.writeFileSync(this._outputFileName, JSON.stringify(this._outputJsonObject, null, 4))
    console.log('File write complete.')
    process.exit()
  }.bind(this)
}

module.exports = BleProfiler
