
# rsa-utils v1.3.0

RSA utilities useful for **certbot** and **letsencrypt**.

Forked from [Daplie/rsa-compat.js](https://www.npmjs.com/package/rsa-compat).

```sh
# Install C compiler
apt-get install build-essential

npm install aleclarson/rsa#1.3.0
```

## CLI

```sh
# Generate a new keyPair in the current directory.
rsa-keygen-js
```

## Examples

```js
var RSA = require('rsa');

var bitlen = 1024;
var exp = 65537;
var options = { public: true, pem: true, internal: true };

RSA.generateKeyPair(bitlen, exp, options).then(function(keyPair) {
  console.log(keyPair);
});
```

The returned promise resolves into this object:

```js
{
  publicKeyPem: '-----BEGIN RSA PUBLIC KEY-----\n/*base64 pem-encoded string*/',
  privateKeyPem: '-----BEGIN RSA PRIVATE KEY-----\n/*base64 pem-encoded string*/',
  privateKeyJwk: {,
    kty: 'RSA',
    n: '/*base64 modulus n = pq*/',
    e: '/*base64 exponent (usually 65537)*/',
    d: '/*base64 private exponent (d = e^−1 (mod ϕ(n))/',
    p: '/*base64 first prime*/',
    q: '/*base64 second prime*/',
    dp: '/*base64 first exponent for Chinese remainder theorem (dP = d (mod p−1))*/',
    dq: '/*base64 Second exponent, used for CRT (dQ = d (mod q−1))/',
    qi: '/*base64 Coefficient, used for CRT (qinv = q^−1 (mod p))*/',
  },
  publicKeyJwk: {,
    kty: 'RSA',
    n: '/*base64 modulus n = pq*/',
    e: '/*base64 exponent (usually 65537)*/',
  },

  _ursa: '/*undefined or intermediate ursa object*/',
  _ursaPublic: '/*undefined or intermediate ursa object*/',
  _forge: '/*undefined or intermediate forge object*/',
  _forgePublic: '/*undefined or intermediate forge object*/',
}
````

NOTE: this object is JSON safe as _ursa and _forge will be ignored

See http://crypto.stackexchange.com/questions/6593/what-data-is-saved-in-rsa-private-key to learn a little more about the meaning of the specific fields in the JWK.

## API

* `RSA.generateKeyPair(bitlen, exp, options)`
* `RSA.import(keypair, options)`
* `RSA.exportPrivatePem(keypair)`
* `RSA.exportPublicPem(keypair)`
* `RSA.exportPrivateJwk(keypair)`
* `RSA.exportPublicJwk(keypair)`
* `RSA.signJws(keypair, payload, nonce)`
* `RSA.generateCsrPem(keypair, names)`
* `RSA.generateCsrDerWeb64(keypair, names)`

`keypair` can be any object with any of these keys `publicKeyPem, privateKeyPem, publicKeyJwk, privateKeyJwk`

### RSA.generateKeyPair(bitlen, exp, options, cb)

Create a private keypair and export it as PEM, JWK, and/or internal formats

```js
promise = RSA.generateKeyPair();
promise = RSA.generateKeyPair(1024, 65537, { pem: false, public: false });
```

`bitlen`: *1024* (default), 2048, or 4096

`exp`: *65537* (default)

`options`:
```js
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

```js
var keypair = RSA.import({ privateKeyPem: '...'});

console.log(keypair);
```

```js
{ privateKeyPem: ..., privateKeyJwk: ..., _ursa: ..., _forge: ... }
```

### RSA.export*(keypair)

You put in an object like `{ privateKeyPem: '...' }` or `{ publicKeyJwk: {} }`
and you get back the keys in the format you requested.

Note:

* Private keys **can** be used to export both private and public keys
* Public keys can **NOT** be used to generate private keys

Example:

```js
var keypair = { privateKeyPem: '...' };

keypair.publicKeyJwk = RSA.exportPublicJwk(keypair);

console.log(keypair);
```

### RSA.signJws(keypair, payload, nonce)

Generates a signature in JWS format (necessary for **certbot**/**letsencrypt**).

```js
var message = "Hello, World!"
var nonce = crypto.randomBytes(16).toString('hex');
var jws = RSA.signJws(keypair, message, nonce);

console.log(jws);
```

The result looks like this:

```js
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
```js
var pem = RSA.generateCsrPem(keypair, [ 'example.com', 'www.example.com' ]);

console.log(pem);
```

web-safe base64 for **certbot**/**letsencrypt**:

`RSA.generateCsrDerWeb64(keypair, names)`:
```js
var web64 = RSA.generateCsrDerWeb64(keypair, [ 'example.com', 'www.example.com' ]);

console.log(web64);
```
