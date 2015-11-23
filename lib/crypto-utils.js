// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/**
 * Crypto Utilities
 * @module crypto-utils
 * @requires crypto
 * @requires node-forge
 * @requires ./utils
 */
'use strict';

var bb         = require('bluebird');
var crypto     = require('crypto');
var forge      = require('node-forge');
var util       = require('./utils');

var TOKEN_SIZE = 16;
var NONCE_SIZE = 16;

var rsaGenerateKeyPair = bb.promisify(forge.pki.rsa.generateKeyPair);

function getSigAlg(alg) {
  switch (alg) {
    case 'RS1':   return forge.md.sha1.create();
    case 'RS256': return forge.md.sha256.create();
    case 'RS384': return forge.md.sha384.create();
    case 'RS512': return forge.md.sha512.create();
    default: return undefined;
  }
}

// A note on formats:
// * Keys are always represented as JWKs
// * Signature objects are in ACME format
// * Certs and CSRs are base64-encoded
module.exports = {
  ///// Internals, exposed for testing

  /** @private */
  bytesToBuffer: function(bytes) {
    return new Buffer(forge.util.bytesToHex(bytes), 'hex');
  },

  /** @private */
  bufferToBytes: function(buf) {
    return forge.util.hexToBytes(buf.toString('hex'));
  },

  /** @private */
  bytesToBase64: function(bytes) {
    return util.b64enc(this.bytesToBuffer(bytes));
  },

  /** @private */
  bnToBase64: function(bn) {
    var hex = bn.toString(16);
    if (hex.length % 2 === 1) { hex = '0' + hex; }
    return util.b64enc(new Buffer(hex, 'hex'));
  },

  /** @private */
  base64ToBn: function(base64) {
    return new forge.jsbn.BigInteger(util.b64dec(base64).toString('hex'), 16);
  },

  /** @private */
  importPrivateKey: function(privateKey) {
    return forge.pki.rsa.setPrivateKey(
               this.base64ToBn(privateKey.n),
               this.base64ToBn(privateKey.e),  this.base64ToBn(privateKey.d),
               this.base64ToBn(privateKey.p),  this.base64ToBn(privateKey.q),
               this.base64ToBn(privateKey.dp), this.base64ToBn(privateKey.dq),
               this.base64ToBn(privateKey.qi));
  },

  /** @private */
  importPublicKey: function(publicKey) {
    return forge.pki.rsa.setPublicKey(
               this.base64ToBn(publicKey.n),
               this.base64ToBn(publicKey.e));
  },

  /** @private */
  exportPrivateKey: function(privateKey) {
    return {
      'kty': 'RSA',
      'n':   this.bnToBase64(privateKey.n),
      'e':   this.bnToBase64(privateKey.e),
      'd':   this.bnToBase64(privateKey.d),
      'p':   this.bnToBase64(privateKey.p),
      'q':   this.bnToBase64(privateKey.q),
      'dp':  this.bnToBase64(privateKey.dP),
      'dq':  this.bnToBase64(privateKey.dQ),
      'qi':  this.bnToBase64(privateKey.qInv)
    };
  },

  /** @private */
  exportPublicKey: function(publicKey) {
    return {
      'kty': 'RSA',
      'n':   this.bnToBase64(publicKey.n),
      'e':   this.bnToBase64(publicKey.e)
    };
  },

  ///// RANDOM STRINGS

  /**
   * Generate a base64-encoded random string of the given length
   *
   * @param  {Integer} nBytes Number of bytes to generate
   *                          (base64 will be longer)
   * @return {String}         Base64-encoded random bytes
   */
  randomString: function(nBytes) {
    return this.bytesToBase64(forge.random.getBytesSync(nBytes));
  },

  /**
   * Random 4 bytes, hex-encoded
   *
   * @return {String}
   */
  randomSerialNumber: function() {
    return forge.util.bytesToHex(forge.random.getBytesSync(4));
  },

  /**
   * A 16-byte random string, Base64-encoded.
   *
   * @return {String}
   */
  newToken: function() {
    return this.randomString(TOKEN_SIZE);
  },

  /**
   * Hex-encoded SHA-256 hash of the given buffer
   *
   * @param  {Buffer} buf hash this
   * @return {String}
   */
  sha256: function(buf) {
    return crypto.createHash('sha256').update(buf).digest('hex');
  },

  ///// KEY PAIR MANAGEMENT

  /**
   * Generate a public/private key pair.
   *
   * @param  {Integer} bits Number of bits in the key
   * @return {Promise}      Promise of {privateKey, publicKey}
   */
  generateKeyPair: function(bits) {
    var self = this;
    return rsaGenerateKeyPair({bits: bits, e: 0x10001})
    .then(function(keyPair){
      return {
        privateKey: self.exportPrivateKey(keyPair.privateKey),
        publicKey:  self.exportPublicKey(keyPair.publicKey)
      };
    });
  },

  /**
   * Parse PEM-encoded private key.
   *
   * @param  {String} pem decode this
   * @return {Object}     privateKey, publicKey
   */
  importPemPrivateKey: function(pem) {
    var key = forge.pki.privateKeyFromPem(pem);
    return {
      privateKey: this.exportPrivateKey(key),
      publicKey:  this.exportPublicKey(key)
    };
  },

  /**
   * Convert a private key object to a PEM-encoded string.
   *
   * @param  {Object} privateKey kty, etc.
   * @return {String}
   */
  privateKeyToPem: function(privateKey) {
    var priv = this.importPrivateKey(privateKey);
    return forge.pki.privateKeyToPem(priv);
  },

  ///// SIGNATURE GENERATION / VERIFICATION

  generateSignature: function(keyPair, payload, alg) {
    alg = alg || 'RS256';
    var nonce      = this.bytesToBuffer(forge.random.getBytesSync(NONCE_SIZE));
    var privateKey = this.importPrivateKey(keyPair.privateKey);

    // Compute JWS signature
    var protectedHeader = JSON.stringify({
      nonce: util.b64enc(nonce)
    });
    var protected64       = util.b64enc(new Buffer(protectedHeader));
    var payload64         = util.b64enc(payload);
    var signatureInputBuf = new Buffer(protected64 + '.' + payload64);
    var signatureInput    = this.bufferToBytes(signatureInputBuf);
    var md                = getSigAlg(alg);
    md.update(signatureInput);
    var sig               = privateKey.sign(md);

    return {
      header: {
        alg: alg,
        jwk: keyPair.publicKey,
      },
      protected: protected64,
      payload:   payload64,
      signature: util.b64enc(this.bytesToBuffer(sig)),
    };
  },

  verifySignature: function(jws) {
    if (jws.protected) {
      if (!jws.header) {
        jws.header = {};
      }
      try {
        var protectedJSON = util.b64dec(jws.protected).toString();
        var protectedObj = JSON.parse(protectedJSON);
        util.extend(jws.header, protectedObj);
      } catch (e) {
        return false;
      }
    }

    // Assumes validSignature(sig)
    if (!jws.header.jwk || (jws.header.jwk.kty !== 'RSA')) {
      // Unsupported key type
      return false;
    } else if (!jws.header.alg || !jws.header.alg.match(/^RS/)) {
      // Unsupported algorithm
      return false;
    }

    // Compute signature input
    var protected64 = (jws.protected)? jws.protected : '';
    var payload64 = (jws.payload)? jws.payload : '';
    var signatureInputBuf = new Buffer(protected64 + '.' + payload64);
    var signatureInput = this.bufferToBytes(signatureInputBuf);

    // Compute message digest
    var md = getSigAlg(jws.header.alg);
    if (!md) { return(false); }
    md.update(signatureInput);

    // Import the key and signature
    var publicKey = this.importPublicKey(jws.header.jwk);
    var sig = this.bufferToBytes(util.b64dec(jws.signature));

    if (!publicKey.verify(md.digest().bytes(), sig)) {
      return false;
    }
    return util.b64dec(payload64);
  },

  ///// CSR GENERATION / VERIFICATION

  /**
   * Generate a Certificate Signing Request
   *
   * @param  {Ojbect} keyPair    {privateKey, publicKey}
   * @param  {String} identifier Common Name (CN) for the certificate
   * @return {String}            Base64-encoded CSR
   */
  generateCSR: function(keyPair, identifier) {
    var privateKey = this.importPrivateKey(keyPair.privateKey);
    var publicKey  = this.importPublicKey(keyPair.publicKey);

    // Create and sign the CSR
    var csr = forge.pki.createCertificationRequest();
    csr.publicKey = publicKey;
    csr.setSubject([{ name: 'commonName', value: identifier }]);
    csr.sign(privateKey);

    // Convert CSR -> DER -> Base64
    var der = forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr));
    return util.b64enc(this.bytesToBuffer(der));
  },

  /**
   * Verify a CSR, and extract the common name from it.
   *
   * @param  {String} csr_b64 Base64-encoded CSR
   * @return {String}         Common Name (CN) or false on error
   */
  verifiedCommonName: function(csr_b64) {
    var der = this.bufferToBytes(util.b64dec(csr_b64));
    var csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(der));

    if (!csr.verify()) {
      return false;
    }

    for (var i=0; i<csr.subject.attributes.length; ++i) {
      if (csr.subject.attributes[i].name === 'commonName') {
        return csr.subject.attributes[i].value;
      }
    }
    return false;
  },
};
