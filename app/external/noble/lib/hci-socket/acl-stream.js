var debug = require('debug')('acl-att-stream');

var events = require('events');
var util = require('util');

var Smp = require('./smp');

var AclStream = function(hci, handle, localAddressType, localAddress, remoteAddressType, remoteAddress) {
  this._hci = hci;
  this._handle = handle;

  this._smp = new Smp(this, localAddressType, localAddress, remoteAddressType, remoteAddress);

  this.onSmpStkBinded = this.onSmpStk.bind(this);
  this.onSmpEndBinded = this.onSmpEnd.bind(this);
  this.onSmpPairingBinded = this.onSmpPairing.bind(this);
  this.onSmpEdivBinded = this.onSmpEdiv.bind(this);

  this._smp.on('stk', this.onSmpStkBinded);
  this._smp.on('end', this.onSmpEndBinded);
  this._smp.on('pairing', this.onSmpPairingBinded);
  this._smp.on('masterIdent', this.onSmpEdivBinded)
};

util.inherits(AclStream, events.EventEmitter);

AclStream.prototype.encrypt = function() {
  this._smp.sendPairingRequest();
};

AclStream.prototype.pair = function(smpRequestBuffer, passkeyOpt, passkeyVal) {
  this._smp.sendCustomPairingRequest(smpRequestBuffer, passkeyOpt, passkeyVal);
};

AclStream.prototype.write = function(cid, data) {
  this._hci.writeAclDataPkt(this._handle, cid, data);
};

AclStream.prototype.push = function(cid, data) {
  if (data) {
    this.emit('data', cid, data);
  } else {
    this.emit('end');
  }
};

AclStream.prototype.pushEncrypt = function(encrypt) {
  this.emit('encrypt', encrypt);
};

AclStream.prototype.onSmpStk = function(stk) {
  var random = new Buffer('0000000000000000', 'hex');
  var diversifier = new Buffer('0000', 'hex');

  this._hci.startLeEncryption(this._handle, random, diversifier, stk);
};

AclStream.prototype.onSmpPairing = function(error, authType, assocModel) {
  debug('[ACL-STREAM] Pairing ' + error)
  this.emit('smpPairing', error, authType, assocModel, this._handle);
};

AclStream.prototype.onSmpEdiv = function(ediv, rand, ltk) {
  debug('[ACL-STREAM] EDIV ' + ediv + ' rand ' + rand + ' ltk ' + ltk)
  this.emit('ediv', ediv, rand, ltk, this._handle);
};

AclStream.prototype.onSmpEnd = function() {
  this._smp.removeListener('stk', this.onSmpStkBinded);
  this._smp.removeListener('end', this.onSmpEndBinded);
  this._smp.removeListener('pairing', this.onSmpPairingBinded);
  this._smp.removeListener('masterIdent', this.onSmpPairingBinded);
};

module.exports = AclStream;
