// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var assert = require('chai').assert;
var utils = require('../lib/utils');

describe('utilities', function() {
  it('fromStandardB64', function() {
    assert.equal(utils.fromStandardB64('Zm9vCg=='), 'Zm9vCg');
  });

  it('toStandardB64', function() {
    assert.equal(utils.toStandardB64('Zm9vCg'), 'Zm9vCg==');
    assert.equal(utils.toStandardB64('Zm8'),    'Zm8=');
    assert.equal(utils.toStandardB64('Zm9v'),   'Zm9v');
  });

  it('b64enc', function() {
    assert.equal(utils.b64enc(new Buffer('foo\n')), 'Zm9vCg');
  });

  it('b64dec', function() {
    assert.deepEqual(utils.b64dec('Zm9vCg'), new Buffer('foo\n'));
  });

  it('isB64String', function() {
    assert.ok(!utils.isB64String(null));
    assert.ok(!utils.isB64String('=='));
    assert.ok(utils.isB64String('Zm9v'));
  });

  it('fieldsPresent', function() {
    assert.ok(!utils.fieldsPresent());
    assert.ok(!utils.fieldsPresent([]));
    assert.ok(utils.fieldsPresent([], {}));
    assert.ok(!utils.fieldsPresent(['foo'], {}));
    assert.ok(utils.fieldsPresent(['foo', 'bar'], {foo: 1, bar: 2, baz: 3}));
  });

  it('validJWK', function() {
    assert.ok(!utils.validJWK());
    assert.ok(!utils.validJWK({}));
    assert.ok(!utils.validJWK({kty: null}));
    assert.ok(!utils.validJWK({kty: 'RSA', d: null}));
    assert.ok(!utils.validJWK({kty: 'RSA'}));
    assert.ok(!utils.validJWK({kty: 'RSA', n: null}));
    assert.ok(!utils.validJWK({kty: 'RSA', n: '=='}));
    assert.ok(!utils.validJWK({kty: 'RSA', n: 'Zm9v', e: null}));
    assert.ok(utils.validJWK({kty: 'RSA', n: 'Zm9v', e: 'Zm9v'}));
    assert.ok(!utils.validJWK({kty: 'EC', crv: 'foo', x: null}));
    assert.ok(!utils.validJWK({kty: 'EC', crv: 'foo', x: 'Zm9v', y: null}));
    assert.ok(utils.validJWK({kty: 'EC', crv: 'foo', x: 'Zm9v', y: 'Zm9v'}));
  });

  it('validSignature', function() {
    assert.ok(!utils.validSignature());
    assert.ok(!utils.validSignature({}));
    assert.ok(!utils.validSignature({alg: null}));
    assert.ok(!utils.validSignature({alg: 'foo'}));
    assert.ok(!utils.validSignature({alg: 'foo', nonce: null}));
    assert.ok(!utils.validSignature({alg: 'foo', nonce: '=='}));
    assert.ok(!utils.validSignature({alg: 'foo', nonce: 'Zm9vCg'}));
    assert.ok(!utils.validSignature({alg: 'foo', nonce: 'Zm9vCg', sig: null}));
    assert.ok(!utils.validSignature({alg: 'foo', nonce: 'Zm9vCg', sig: '=='}));
    assert.ok(!utils.validSignature({alg: 'foo', nonce: 'Zm9vCg', sig: 'Zm9vCg'}));
    assert.ok(!utils.validSignature({alg: 'foo', nonce: 'Zm9vCg', sig: 'Zm9vCg', jwk: null}));
    assert.ok(utils.validSignature({alg: 'foo', nonce: 'Zm9vCg', sig: 'Zm9vCg', jwk: {kty: 'EC', crv: 'foo', x: 'Zm9v', y: 'Zm9v'}}));
  });

  it('keyFingerprint', function() {
    assert.throw(function(){ utils.keyFingerprint(); });
    assert.throw(function(){ utils.keyFingerprint(''); });
    assert.throw(function(){ utils.keyFingerprint({}); });
    assert.throw(function(){ utils.keyFingerprint({kty: null}); });
    assert.equal(utils.keyFingerprint({kty: 'RSA'}), 'undefined');
    assert.equal(utils.keyFingerprint({kty: 'RSA', n: 'Zm9v'}), 'Zm9v');
    assert.equal(utils.keyFingerprint({kty: 'EC', crv: 'foo', x: 'Zm9v', y: 'Zm9v'}), 'foo|Zm9v|Zm9v');
  });

  it('extend', function() {
    var a = {b: 1};
    var c = utils.extend(a, {c: 2, d: 3});
    assert.deepEqual(c, {b: 1, c: 2, d: 3});
    utils.extend(a, {b: 4});
    assert.deepEqual(c, {b: 4, c: 2, d: 3});
  });

  it('extract', function() {
    var a = { b: 1, c: 2, d: 3};
    assert.deepEqual(utils.extract(['b', 'c', 'e'], a), { b: 1, c: 2});
  });
});
