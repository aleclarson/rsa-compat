'use strict';

var ursa = require('ursa');

var privateJwkComponents = ['n', 'e', 'p', 'q', 'dp', 'dq', 'qi', 'd'];
var publicJwkComponents = ['n', 'e'];

exports.generateKeyPair = function(bitlen, exp, options) {
  return ursa.generatePrivateKey(bitlen || 2048, exp || 65537);
};

exports.import = function(keyPair) {
  return _ursaImportPem(_ursaImportJwk(keyPair));
};

exports.exportPrivatePem = function(keyPair) {
  if (keyPair.privateKeyPem) {
    return keyPair.privateKeyPem;
  }
  if (keyPair.toPrivatePem) {
    return _pemBinToPem(keyPair.toPrivatePem());
  }
  if (keyPair.privateKeyJwk) {
    return _pemBinToPem(_ursaImportJwk(keyPair).toPrivatePem());
  }
  throw new Error("Failed to export private key .pem");
};

exports.exportPublicPem = function(keyPair) {
  if (keyPair.publicKeyPem) {
    return keyPair.publicKeyPem;
  }
  if (keyPair.toPublicPem) {
    return _pemBinToPem(keyPair.toPublicPem());
  }
  if (keyPair.publicKeyJwk) {
    return _pemBinToPem(_ursaImportPublicJwk(keyPair).toPublicPem());
  }
  if (keyPair.privateKeyJwk) {
    return _pemBinToPem(_ursaImportJwk(keyPair).toPublicPem());
  }
  if (keyPair.privateKeyPem) {
    return _pemBinToPem(_ursaImportPem(keyPair).toPublicPem());
  }
  throw new Error("Failed to export public key .pem")
};

function _privateJwkToComponents(jwk) {
  var components = [];
  privateJwkComponents.forEach(function (key) {
    components.push(new Buffer(jwk[key], 'base64'));
  });
  return components;
}

function _publicJwkToComponents(jwk) {
  var components = [];
  publicJwkComponents.forEach(function (key) {
    components.push(new Buffer(jwk[key], 'base64'));
  });
  return components;
}

function _ursaImportPem(keyPair) {
  if (!keyPair.toPrivatePem) {
    if (keyPair.privateKeyPem) {
      return ursa.createPrivateKey(keyPair.privateKeyPem);
    }
    if (keyPair.publicKeyPem) {
      return ursa.createPublicKey(keyPair.publicKeyPem);
    }
  }
  return keyPair;
}

function _ursaImportJwk(keyPair) {
  var jwk, comps;
  if (!keyPair.toPrivatePem && (jwk = keyPair.privateKeyJwk)) {
    comps = _privateJwkToComponents(jwk);
    keyPair = ursa.createPrivateKeyFromComponents.apply(ursa, comps);
    keyPair.privateKeyJwk = jwk;
  }
  if (!keyPair.toPublicPem && (jwk = keyPair.publicKeyJwk)) {
    comps = _publicJwkToComponents(jwk);
    keyPair = ursa.createPublicKeyFromComponents.apply(ursa, comps);
    keyPair.publicKeyJwk = jwk;
  }
  return keyPair;
}

function _ursaImportPublicJwk(keyPair) {
  var jwk, comps;
  if (!keyPair.toPublicPem && (jwk = keyPair.publicKeyJwk)) {
    comps = _publicJwkToComponents(jwk);
    keyPair = ursa.createPublicKeyFromComponents.apply(ursa, comps);
    keyPair.publicKeyJwk = jwk;
  }
  return keyPair;
}

function _pemBinToPem(pem) {
  return pem.toString('ascii').replace(/[\n\r]+/g, '\r\n');
}
