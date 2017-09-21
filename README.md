# rsa-compat

JavaScript RSA utils that work on Windows, Mac, and Linux with or without C compiler

In order to provide a module that "just works" everywhere, we mix and match methods
from `node.js` core, `ursa`, `forge`, and others.

This is useful for **certbot** and **letsencrypt**.

Forked from [Daplie/rsa-compat.js](https://www.npmjs.com/package/rsa-compat).

## CLI

You can generate keypairs on Windows, Mac, and Linux using rsa-keygen-js:

```bash
# generates a new keypair in the current directory
rsa-keypiar-js
```

## Examples

Generate an RSA Keypair:

```javascript
var RSA = require('rsa-compat').RSA;

var bitlen = 1024;
var exp = 65537;
var options = { public: true, pem: true, internal: true };

RSA.generateKeypair(bitlen, exp, options, function (err, keypair) {
  console.log(keypair);
});
```

Here's what the object might look like:

`console.log(keypair)`:
```javascript

{ publicKeyPem: '-----BEGIN RSA PUBLIC KEY-----\n/*base64 pem-encoded string*/'
, privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n/*base64 pem-encoded string*/'
, privateKeyJwk: {
    kty: "RSA"
  , n: '/*base64 modulus n = pq*/'
  , e: '/*base64 exponent (usually 65537)*/'
  , d: '/*base64 private exponent (d = e^−1 (mod ϕ(n))/'
  , p: '/*base64 first prime*/'
  , q: '/*base64 second prime*/'
  , dp: '/*base64 first exponent for Chinese remainder theorem (dP = d (mod p−1))*/'
  , dq: '/*base64 Second exponent, used for CRT (dQ = d (mod q−1))/'
  , qi: '/*base64 Coefficient, used for CRT (qinv = q^−1 (mod p))*/'
  }
, publicKeyJwk: {
    kty: "RSA"
  , n: '/*base64 modulus n = pq*/'
  , e: '/*base64 exponent (usually 65537)*/'
  }

, _ursa: '/*undefined or intermediate ursa object*/'
, _ursaPublic: '/*undefined or intermediate ursa object*/'
, _forge: '/*undefined or intermediate forge object*/'
, _forgePublic: '/*undefined or intermediate forge object*/'
}
```

NOTE: this object is JSON safe as _ursa and _forge will be ignored

See http://crypto.stackexchange.com/questions/6593/what-data-is-saved-in-rsa-private-key to learn a little more about the meaning of the specific fields in the JWK.

## API

* `RSA.generateKeypair(bitlen, exp, options, cb)`
* `RSA.import(keypair, options)`
* `RSA.exportPrivatePem(keypair)`
* `RSA.exportPublicPem(keypair)`
* `RSA.exportPrivateJwk(keypair)`
* `RSA.exportPublicJwk(keypair)`
* `RSA.signJws(keypair, payload, nonce)`
* `RSA.generateCsrPem(keypair, names)`
* `RSA.generateCsrDerWeb64(keypair, names)`

`keypair` can be any object with any of these keys `publicKeyPem, privateKeyPem, publicKeyJwk, privateKeyJwk`

### RSA.generateKeypair(bitlen, exp, options, cb)

Create a private keypair and export it as PEM, JWK, and/or internal formats

```javascript
RSA.generateKeypair(null, null, null, function (keypair) { /*...*/ });

RSA.generateKeypair(1024, 65537, { pem: false, public: false, internal: false }, function (keypair) { /*...*/ });
```

`bitlen`: *1024* (default), 2048, or 4096

`exp`: *65537* (default)

`options`:
```javascript
{ public: false       // export public keys
, pem: false          // export pems
, jwk: true           // export jwks
, internal: false     // preserve internal intermediate formats (_ursa, _forge)
, thumbprint: false   // JWK sha256 thumbprint
, fingerprint: false  // NOT IMPLEMENTED (RSA key fingerprint)
}
```

### RSA.import(keypair, options)

Imports keypair as JWKs and internal values `_ursa` and `_forge`.

```javascript
var keypair = RSA.import({ privateKeyPem: '...'});

console.log(keypair);
```

```javascript
{ privateKeyPem: ..., privateKeyJwk: ..., _ursa: ..., _forge: ... }
```

### RSA.export*(keypair)

You put in an object like `{ privateKeyPem: '...' }` or `{ publicKeyJwk: {} }`
and you get back the keys in the format you requested.

Note:

* Private keys **can** be used to export both private and public keys
* Public keys can **NOT** be used to generate private keys

Example:

```javascript
var keypair = { privateKeyPem: '...' };

keypair.publicKeyJwk = RSA.exportPublicJwk(keypair);

console.log(keypair);
```

### RSA.signJws(keypair, payload, nonce)

Generates a signature in JWS format (necessary for **certbot**/**letsencrypt**).

```javascript
var message = "Hello, World!"
var nonce = crypto.randomBytes(16).toString('hex');
var jws = RSA.signJws(keypair, message, nonce);

console.log(jws);
```

The result looks like this:

```javascript
{ "header": {
    "alg": "RS256",
    "jwk": {
      "kty": "RSA",
      "n": "AMJubTfOtAarnJytLE8fhNsEI8wnpjRvBXGK/Kp0675J10ORzxyMLqzIZF3tcrUkKBrtdc79u4X0GocDUgukpfkY+2UPUS/GxehUYbYrJYWOLkoJWzxn7wfoo9X1JgvBMY6wHQnTKvnzZdkom2FMhGxkLaEUGDSfsNznTTZNBBg9",
      "e": "AQAB"
    }
  },
  "protected": "eyJub25jZSI6IjhlZjU2MjRmNWVjOWQzZWYifQ",
  "payload": "JLzF1NBNCV3kfbJ5sFaFyX94fJuL2H-IzaoBN-ciiHk",
  "signature": "Wb2al5SDyh5gjmkV79MK9m3sfNBBPjntSKor-34BBoGwr6n8qEnBmqB1Y4zbo-5rmvsoPmJsnRlP_hRiUY86zSAQyfbisTGrGBl0IQ7ditpkfYVm0rBWJ8WnYNqYNp8K3qcD7NW72tsy-XoWEjNlz4lWJeRdEG2Nt4CJgnREH4Y"
}
```

### RSA.generateCsr*(keypair, names)

You can generate the CSR in human-readable or binary / base64 formats:

`RSA.generateCsrPem(keypair, names)`:
```javascript
var pem = RSA.generateCsrPem(keypair, [ 'example.com', 'www.example.com' ]);

console.log(pem);
```

web-safe base64 for **certbot**/**letsencrypt**:

`RSA.generateCsrDerWeb64(keypair, names)`:
```javascript
var web64 = RSA.generateCsrDerWeb64(keypair, [ 'example.com', 'www.example.com' ]);

console.log(web64);
```