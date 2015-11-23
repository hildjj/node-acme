// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var assert = require('chai').assert;
var forge  = require('node-forge');
var cutils = require('../lib/crypto-utils');
var utils  = require('../lib/utils');

describe('crypto utilities', function(){
  it('randomString', function(){
    var s = cutils.randomString(16);
    assert.equal(s.length, 22);
    assert.ok(utils.isB64String(s));
  });

  it('randomSerialNumber', function(){
    var s = cutils.randomSerialNumber();
    assert.equal(s.length, 8);
  });

  it('newToken', function(){
    var s = cutils.newToken();
    assert.equal(s.length, 22);
  });

  it('sha256', function(){
    var s = cutils.sha256(new Buffer('foo'));
    assert.equal(s,
      '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae');
  });

  it('keys', function(){
    cutils.generateKeyPair(256).then(function(kp){
      assert.ok(utils.fieldsPresent(['privateKey', 'publicKey'], kp));
      var priv_pem = cutils.privateKeyToPem(kp.privateKey);
      assert.match(priv_pem, /^-----BEGIN RSA PRIVATE KEY-----$/m);
      var priv = cutils.importPemPrivateKey(priv_pem);
      assert.ok(utils.fieldsPresent(['privateKey', 'publicKey'], priv));
    });
  });

  it('csr and signs', function(){
    cutils.generateKeyPair(512).then(function(kp){
      var csr = cutils.generateCSR(kp, 'testing');
      assert.ok(csr);
      assert.ok(csr.length > 0);
      var name = cutils.verifiedCommonName(csr);
      assert.equal(name, 'testing');

      // s/testing/tasting/ in order to make the sig fail
      var bad = utils.b64dec(csr);
      bad[bad.indexOf('testing')+1] = 'a';
      bad = utils.b64enc(bad);
      assert.equal(cutils.verifiedCommonName(bad), false);

      var privateKey = cutils.importPrivateKey(kp.privateKey);
      var publicKey  = cutils.importPublicKey(kp.publicKey);

      // Create and sign the CSR
      var anon_csr = forge.pki.createCertificationRequest();
      anon_csr.publicKey = publicKey;
      anon_csr.setSubject([{ name: 'countryName', value: 'US' }]);
      anon_csr.sign(privateKey);

      // Convert CSR -> DER -> Base64
      var der = forge.asn1.toDer(forge.pki.certificationRequestToAsn1(anon_csr));
      anon_csr = utils.b64enc(cutils.bytesToBuffer(der));
      assert.equal(cutils.verifiedCommonName(anon_csr), false);

      var sig = cutils.generateSignature(kp, Buffer('foo'));
      assert.ok(utils.fieldsPresent(['header', 'protected', 'payload', 'signature'], sig));
      assert.ok(utils.fieldsPresent(['alg', 'jwk'], sig.header));
      assert.ok(utils.fieldsPresent(['kty', 'n', 'e'], sig.header.jwk));

      assert.ok(cutils.verifySignature(sig));
    });
  });
});
