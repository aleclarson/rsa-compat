/*!
 * rsa-compat
 * Copyright(c) 2016 AJ ONeal <aj@daplie.com> https://daplie.com
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
*/
'use strict';

var crypto = require('crypto');
var ursa = require('ursa');

var utils = require('./lib/utils');
var ursa = require('./lib/ursa');

var RSA = exports;

RSA.import = function(keyPair) {
  var kp = ursa.import(keyPair);

  if (!kp.privateKeyJwk) {
    if (!kp.privateKeyPem) {
      kp.privateKeyPem = ursa.exportPrivatePem(kp);
    }
    if (kp.privateKeyPem) {
      kp.privateKeyJwk = utils.exportPrivateJwk(kp);
    }
  }
  if (kp.privateKeyJwk) {
    return kp;
  }

  if (!kp.publicKeyJwk) {
    if (!kp.publicKeyPem) {
      kp.publicKeyPem = ursa.exportPublicPem(kp);
    }
    if (kp.publicKeyPem) {
      kp.publicKeyJwk = utils.exportPublicJwk(kp);
    }
  }
  if (kp.publicKeyJwk) {
    return kp;
  }

  throw new Error("Found neither private nor public keypair in any supported format");
};

RSA.generateKeyPair = function(length, exponent, options) {
  if (options == null) {
    options = {};
  }

  var kp = ursa.generateKeyPair(length, exponent, options);

  if (options.jwk || options.thumbprint) {
    kp.privateKeyJwk = utils.exportPrivateJwk(kp);
    if (options.public) {
      kp.publicKeyJwk = utils.exportPublicJwk(kp);
    }
  }

  if (options.pem) {
    kp.privateKeyPem = ursa.exportPrivatePem(kp);
    if (options.public) {
      kp.publicKeyPem = ursa.exportPublicPem(kp);
    }
  }

  if (options.thumprint) {
    kp.thumbprint = RSA.thumbprint(kp);
  }

  return kp;
};

RSA.thumbprint = function(keyPair) {
  var publicKeyJwk = RSA.exportPublicJwk(keyPair);

  if (!publicKeyJwk.e || !publicKeyJwk.n) {
    throw new Error("You must provide an RSA jwk with 'e' and 'n' (the public components)");
  }

  var input = thumbprintInput(publicKeyJwk.n, publicKeyJwk.e);
  var base64Digest = crypto.createHash('sha256').update(input).digest('base64');
  return toWebsafeBase64(base64Digest);
};

RSA.signJws = function(keyPair, payload, nonce) {
  var kp = ursa.import(keyPair);
  kp.publicKeyJwk = utils.exportPublicJwk(kp);

  // Compute JWS signature
  var protectedHeader = '';
  if (nonce) {
    protectedHeader = JSON.stringify({nonce: nonce});
  }
  var protected64 = toWebsafeBase64(new Buffer(protectedHeader).toString('base64'));
  var payload64 = toWebsafeBase64(payload.toString('base64'));
  var raw = protected64 + '.' + payload64;
  var sha256Buf = crypto.createHash('sha256').update(raw).digest();
  var sig64 = kp.sign('sha256', sha256Buf).toString('base64');

  return {
    header: {
      alg: 'RS256',
      jwk: kp.publicKeyJwk,
    },
    protected: protected64,
    payload: payload64,
    signature: toWebsafeBase64(sig64),
  };
};

RSA.exportPrivatePem = ursa.exportPrivatePem;
RSA.exportPublicPem = ursa.exportPublicPem;

RSA.exportPrivateJwk = utils.exportPrivateJwk;
RSA.exportPublicJwk = utils.exportPublicJwk;

RSA.toWebsafeBase64 = toWebsafeBase64;

function toWebsafeBase64(b64) {
  return b64.replace(/[+]/g, "-").replace(/\//g, "_").replace(/=/g,"");
}

function thumbprintInput(n, e) {
  // #L147 const rsaThumbprintTemplate = `{"e":"%s","kty":"RSA","n":"%s"}`
  return new Buffer('{"e":"' + e + '","kty":"RSA","n":"'+ n +'"}', 'ascii');
}
