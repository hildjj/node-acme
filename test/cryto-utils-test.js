// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var assert = require('chai').assert;
var forge  = require('node-forge');
var cutils = require('../lib/crypto-utils');
var utils  = require('../lib/utils');

describe('crypto utilities', function() {
  it('keys', function() {
    return cutils.generateKey(256).then(function(priv){
      assert.ok(utils.fieldsPresent([
        'kty', 'kid',
        'e', 'n', 'd',
        'p', 'q', 'dp', 'dq', 'qi'], priv.toJSON(true)));
      var priv_pem = priv.toPEM(true);
      assert.match(priv_pem, /^-----BEGIN RSA PRIVATE KEY-----$/m);
      return cutils.importPemPrivateKey(priv_pem)
      .then(function(ipriv) {
        assert.ok(ipriv);
      });
    });
  });

  it('csr and signs', function() {
    cutils.generateKey(512).then(function(kp){
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

      return cutils.generateSignature(kp.privateKey, 'foo')
      .then(function(sig) {
        assert.ok(utils.fieldsPresent(['payload', 'protected', 'signature'], sig));
        return cutils.verifySignature(sig);
      })
      .then(function(v) {
        assert.ok(v);
        assert.equal(v.payload, 'foo');
      });
    });
  });
});
