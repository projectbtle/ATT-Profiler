'use strict'

// Requires.
var debug = require('../external/noble/node_modules/debug/debug')('objectformatter')
var events = require('events')
var util = require('util')

const SECURITY_LEVEL_NONE = 0
const SECURITY_LEVEL_LOW = 1
const SECURITY_LEVEL_MED = 2
const SECURITY_LEVEL_HIGH = 3

var ATT_ECODE_SUCCESS = 0x00
var ATT_ECODE_INVALID_HANDLE = 0x01
var ATT_ECODE_READ_NOT_PERM = 0x02
var ATT_ECODE_WRITE_NOT_PERM = 0x03
var ATT_ECODE_INVALID_PDU = 0x04
var ATT_ECODE_AUTHENTICATION = 0x05
var ATT_ECODE_REQ_NOT_SUPP = 0x06
var ATT_ECODE_INVALID_OFFSET = 0x07
var ATT_ECODE_AUTHORIZATION = 0x08
var ATT_ECODE_PREP_QUEUE_FULL = 0x09
var ATT_ECODE_ATTR_NOT_FOUND = 0x0a
var ATT_ECODE_ATTR_NOT_LONG = 0x0b
var ATT_ECODE_INSUFF_ENCR_KEY_SIZE = 0x0c
var ATT_ECODE_INVAL_ATTR_VALUE_LEN = 0x0d
var ATT_ECODE_UNLIKELY = 0x0e
var ATT_ECODE_INSUFF_ENC = 0x0f
var ATT_ECODE_UNSUPP_GRP_TYPE = 0x10
var ATT_ECODE_INSUFF_RESOURCES = 0x11

var attErrors = require('./att-errors.json')
var authModels = require('./assoc-model.json')
function ObjectHandler () {
  this._secLevelMapper = {
    '0': 'None',
    '1': 'Low',
    '2': 'Med',
    '3': 'High',
    't': 'Unknown',
    'x': 'Custom'
  }
}

util.inherits(ObjectHandler, events.EventEmitter)

ObjectHandler.prototype.createTargetObject = function (outputJsonObject, services, characteristics, descriptors, accessTypes) {
  var numCharCheckable = {}
  for (var x in accessTypes) {
    numCharCheckable[accessTypes[x]] = 0
  }
  outputJsonObject['Services'] = {}
  for (var i in services) {
    outputJsonObject['Services'][services[i].uuid] = {}
    outputJsonObject['Services'][services[i].uuid]['name'] = services[i].name
    outputJsonObject['Services'][services[i].uuid]['type'] = services[i].type
    outputJsonObject['Services'][services[i].uuid]['Characteristics'] = {}

    for (var j in characteristics) {
      if (characteristics[j]._serviceUuid === services[i].uuid) {
        outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid] = {}
        outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['name'] = characteristics[j].name
        outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['type'] = characteristics[j].type
        outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['properties'] = characteristics[j].properties
        outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['security'] = {}
        outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['Descriptors'] = {}

        // Create security object.
        for (var y in accessTypes) {
          var currentProperty = accessTypes[y]
          outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['security'][currentProperty] = {}
          outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['security'][currentProperty]['error'] = null

          if (characteristics[j].properties.indexOf(currentProperty) >= 0) {
            outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['security'][currentProperty]['applicable'] = true
            if (accessTypes.indexOf(currentProperty) >= 0) {
              numCharCheckable[currentProperty]++
            }
          } else {
            outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['security'][currentProperty]['applicable'] = false
          }
        }

        for (var k in descriptors) {
          if ((descriptors[k]._serviceUuid === services[i].uuid) && (descriptors[k]._characteristicUuid === characteristics[j].uuid)) {
            outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['Descriptors'][descriptors[k].uuid] = {}
            outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['Descriptors'][descriptors[k].uuid]['name'] = descriptors[k].name
            outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['Descriptors'][descriptors[k].uuid]['type'] = descriptors[k].type
            outputJsonObject['Services'][services[i].uuid]['Characteristics'][characteristics[j].uuid]['Descriptors'][descriptors[k].uuid]['security'] = {}
          }
        }
      }
    }
  }

  return {json: outputJsonObject, num: numCharCheckable}
}

ObjectHandler.prototype.updateJsonObject = function (outputJsonObject, services, characteristics, actionType, currentSecurityLevel, errorObject, securityObject, currentAuthType, currentAssocModel, fixedPin) {
  var useObj = (errorObject === null) ? securityObject : errorObject

  var serviceUuid = useObj.serviceUuid
  var characteristicUuid = useObj.characteristicUuid

  // Reset errors.
  outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][actionType]['error'] = null
  outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][actionType]['otherError'] = null
  
  var accessError = useObj.error
  var securityNum = null

  // No errors
  if (accessError === null) {
    var value = useObj.value
    if (value !== null) {
      outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][actionType]['value'] = value
    }
    securityNum = currentSecurityLevel
  // Some error
  } else {
    var textError = ''
    if (accessError === 'Timeout') {
      textError = accessError
    } else {
      var strError = accessError.toString(16)
      textError = attErrors[strError]
      if (textError === undefined) {
        textError = 'Undefined'
      }
    }

    // If the error is security-related.
    if ((accessError === ATT_ECODE_AUTHENTICATION) || (accessError === ATT_ECODE_AUTHORIZATION) || (accessError === ATT_ECODE_INSUFF_ENC) || (accessError === ATT_ECODE_INSUFF_ENCR_KEY_SIZE)) {
      outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][actionType]['error'] = textError
      // If there is an error, and we are already at the highest level,
      //   then it may be some custom security?
      securityNum = (currentSecurityLevel === SECURITY_LEVEL_HIGH) ? 'x' : (currentSecurityLevel + 1)
      // If the error is not security-related, we can't estimate security level.
    } else {
      outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][actionType]['otherError'] = textError
      // If some security was required to get to this point:
      if (currentSecurityLevel > SECURITY_LEVEL_NONE) {
        securityNum = currentSecurityLevel
      } else {
        // Assign custom security level identifier
        securityNum = 't'
      }      
    }
  }

  // Map the security level identifier to discrete text values.
  var securityLevel = this._secLevelMapper[securityNum]
  // Map the authentication type and association model to text values.
  var authType = authModels[currentAuthType]
  var assocModel = authModels[currentAssocModel]
  outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][actionType]['securityLevel'] = securityLevel
  outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][actionType]['authType'] = authType
  // If the model used a fixed PIN.
  if ((assocModel === 'Passkey') && (fixedPin !== null) ){
    assocModel = 'Passkey with Fixed PIN'
  }
  outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][actionType]['assocModel'] = assocModel
  return outputJsonObject
}

ObjectHandler.prototype.checkSecurityRequired = function (jsonObject, services, characteristics, accessTypes) {
  var securityIncreaseReqd = false
  var numCharCheckable = {}
  for (var x in accessTypes) {
    var accessType = accessTypes[x]
    numCharCheckable[accessType] = 0
    for (var i in services) {
      for (var j in characteristics) {
        if (characteristics[j]._serviceUuid === services[i].uuid) {
          var serviceUuid = services[i].uuid
          var characteristicUuid = characteristics[j].uuid
          var charObject = jsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][accessType]
          // if (charObject['applicable'] === true) { // This should not be needed?
          var secError = charObject['error']
          if (secError === null) {
              // Do nothing
          } else {
            securityIncreaseReqd = true
            numCharCheckable[accessType]++
          }
          // }
        }
      }
    }
  }

  return {security: securityIncreaseReqd, checks: numCharCheckable}
}

ObjectHandler.prototype.updateFinalSecurity = function (outputJsonObject, services, characteristics, accessTypes, currentSecurityLevel, currentAuthType, currentAssocModel) {
  for (var x in accessTypes) {
    var accessType = accessTypes[x]
    for (var i in services) {
      for (var j in characteristics) {
        if (characteristics[j]._serviceUuid === services[i].uuid) {
          var serviceUuid = services[i].uuid
          var characteristicUuid = characteristics[j].uuid
          var charObject = outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][accessType]
          var secError = charObject['error']
          if (secError === null) {
              // Do nothing
          } else {
            // Since we are at the highest security level and pairing didn't work, there must be some custom security.
            var securityNum = 'x'
            var securityLevel = this._secLevelMapper[securityNum]
            var authType = authModels[currentAuthType]
            var assocModel = authModels[currentAssocModel]
            outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][accessType]['securityLevel'] = securityLevel
            outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][accessType]['authType'] = authType
            outputJsonObject['Services'][serviceUuid]['Characteristics'][characteristicUuid]['security'][accessType]['assocModel'] = assocModel
          }
        }
      }
    }
  }
  return outputJsonObject
}

module.exports = ObjectHandler
