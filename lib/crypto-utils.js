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

var crypto = require('crypto');
var forge  = require('node-forge');
var jose   = require('node-jose');
var util   = require('./utils');

// A note on formats:
// * Keys are always represented as JWKs
// * Signature objects are in ACME format
// * Certs and CSRs are base64-encoded
module.exports = {
  /**
   * Compute the SHA-256 digest of a buffer.
   *
   * @param  {Buffer} input Buffer to be digested
   * @return {Buffer}       The digest value
   */
  sha256: function(input) {
    return crypto.createHash('sha256').update(input).digest();
  },

  /**
   * Generate a public/private key pair.
   *
   * @param  {Integer} bits Number of bits in the key
   * @return {Promise}      Promise(privateKey)
   */
  generateKey: function(bits) {
    var ks = jose.JWK.createKeyStore();
    return ks.generate('RSA', bits);
  },

  /**
   * Parse PEM-encoded private key.
   *
   * @param  {String} pem decode this
   * @return {Promise}     Promise(privateKey)
   */
  importPemPrivateKey: function(pem) {
    return jose.JWK.asKey(pem, 'pem');
  },

  /**
   * Convert a private key object to a PEM-encoded string.
   *
   * @param  {Object} key kty, etc.
   * @return {String} PEM-encoded key
   */
  privateKeyToPem: function(key) {
    return key.toPEM(true);
  },

  generateSignature: function(priv, nonce, payload) {
    return jose.JWS.createSign({format: 'flattened'}, {
      reference: 'jwk',
      key:       priv,
      header:    {
        nonce: nonce
      }
    })
    .update(JSON.stringify(payload))
    .final();
  },

  verifySignature: function(jws) {
    var obj = jose.parse(jws);
    return jose.JWK.asKeyStore(obj.all.map(function(o) {
      return o.jwk;
    }))
    .then(function(ks) {
      return obj.perform(ks);
    })
    .then(function(v) {
      v.payload = JSON.parse(v.payload);
      return v;
    });
  },

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

  /**
   * Create a self-signed certificate with a given name and public key
   *
   * @param  {String} name    Domain name to included in the cert
   * @param  {Object} keyPair JWK key pair.  Public key will be put in
   *                          the cert; the private key will be used to
   *                          sign it.
   * @return {String}         PEM-encoded certificate
   */
  selfSigned: function(name, keyPair) {
    var privKey = this.importPrivateKey(keyPair.privateKey);
    var pubKey = this.importPublicKey(keyPair.publicKey);

    var cert = forge.pki.createCertificate();

    // Constants that shouldn't matter
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();

    // Specifics of this certificate
    cert.publicKey = pubKey;
    var attrs = [{ name: 'commonName', value: name }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([{
      name:     'subjectAltName',
      altNames: [{type: 2, value: name}]
    }]);

    cert.sign(privKey, forge.md.sha256.create());
    return forge.pki.certificateToPem(cert);
  }
};
