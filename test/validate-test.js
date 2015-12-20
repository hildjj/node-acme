// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var assert = require('chai').assert;
var dns    = require('native-dns');
var crypto = require('../lib/crypto-utils');
var rp     = require('request-promise');

var DNS01Validator = require('../lib/validate-dns');
var HTTP01Validator = require('../lib/validate-http');

var DOMAIN = 'not-example.com';
var TOKEN = 'gZZT1sMhGgH2qHdURBtguKKfc7VgBbph9VZgnq-Kurk';
var KEY_AUTHZ = TOKEN + '.oLynG5-VrkDKgblLWgGL4u5eS5GrliOfS38WMw4Yk7I';
var PORT = 5300;

function makeChallenge(type) {
  return {
    type:             type,
    token:            TOKEN,
    keyAuthorization: KEY_AUTHZ
  };
}

describe('validation servers', function() {
  it('http-01', function(done) {
    var challenge = makeChallenge('http-01');
    var uri = 'http://localhost:' + PORT + '/.well-known/acme-challenge/' + TOKEN;
    var validator = new HTTP01Validator(DOMAIN, challenge, PORT);

    validator.start();
    rp.get({
      uri: uri,
      headers: { 'Host': DOMAIN }
    })
    .then((response) => {
      assert.equal(response, KEY_AUTHZ);
    })
    .finally(() => {
      validator.stop();
      done();
    });
  });

  it('dns-01', function(done) {
    var challenge = makeChallenge('dns-01');
    var validator = new DNS01Validator(DOMAIN, challenge, PORT);

    var validationValue = crypto.sha256(new Buffer(challenge.keyAuthorization))
                                .toString('base64')
                                .replace(/=*$/, '');

    var req = dns.Request({
      question: dns.Question({
        name: '_acme-challenge.' + DOMAIN,
        type: 'TXT'
      }),
      server: { address: '127.0.0.1', port: PORT }
    });

    req.on('message', function(err, answer) {
      if (err) {
        done(err);
      }

      var foundValidationRecord = false;
      answer.answer.forEach(function(txt) {
        if (txt.data.join('') === validationValue) {
          foundValidationRecord = true;
        }
      });

      assert.isTrue(foundValidationRecord);
      validator.stop();
      done();
    });

    validator.start();
    req.send();
  });
});
