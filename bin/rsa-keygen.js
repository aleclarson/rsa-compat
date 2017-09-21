#!/usr/bin/env node
'use strict';

var RSA = require('..');
var path = require('path');
var fs = require('fs');

var bitlen = 2048;
var exp = 65537;
var opts = { public: true, pem: true };
var cwd = process.cwd();
var privkeyPath = path.join(cwd, 'privkey.pem');
var pubkeyPath = path.join(cwd, 'pubkey.pem');

if (fs.existsSync(privkeyPath)) {
  console.error(privkeyPath, "already exists");
  process.exit(1);
}

RSA.generateKeyPair(bitlen, exp, opts).then(function(keyPair) {
  console.info('');
  console.info('');

  fs.writeFileSync(privkeyPath, keyPair.privateKeyPem, 'ascii');
  console.info(privkeyPath + ':');
  console.info('');
  console.info(keyPair.privateKeyPem);

  console.info('');

  fs.writeFileSync(pubkeyPath, keyPair.publicKeyPem, 'ascii');
  console.info(pubkeyPath + ':');
  console.info('');
  console.info(keyPair.publicKeyPem);
}, console.error);
