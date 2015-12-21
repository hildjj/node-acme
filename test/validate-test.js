// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var assert = require('chai').assert;
var dns    = require('native-dns');
var crypto = require('../lib/crypto-utils');
var rp     = require('request-promise');
var tls    = require('tls');

var DNS01Validator = require('../lib/validate-dns');
var HTTP01Validator = require('../lib/validate-http');
var TLSSNI01Validator = require('../lib/validate-tls');

var DOMAIN = 'not-example.com';
var TOKEN = 'gZZT1sMhGgH2qHdURBtguKKfc7VgBbph9VZgnq-Kurk';
var KEY_AUTHZ = TOKEN + '.oLynG5-VrkDKgblLWgGL4u5eS5GrliOfS38WMw4Yk7I';
var TLS_SNI_N = 20;
var PORT = 5300;

function makeChallenge(type) {
  return {
    type:             type,
    token:            TOKEN,
    keyAuthorization: KEY_AUTHZ
  };
}

function tlsConnectAsync(opts) {
  return new Promise((resolve, reject) => {
    var conn = tls.connect(opts, () => {
      resolve(conn);
    });

    conn.on('error', (err) => {
      reject(err);
    });
  });
}

describe('validation servers', function() {
  it('http-01', function(done) {
    var challenge = makeChallenge('http-01');
    var uri = 'http://localhost:' + PORT + '/.well-known/acme-challenge/' + TOKEN;
    var validator = new HTTP01Validator(DOMAIN, challenge, PORT);

    validator.start();
    rp.get({
      uri:     uri,
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

  it('tls-sni-01', function(done) {
    var challenge = makeChallenge('tls-sni-01');
    challenge.n = TLS_SNI_N;
    var validator = new TLSSNI01Validator(DOMAIN, challenge, PORT);

    var zNames = [];
    var z = challenge.keyAuthorization;
    for (var i=0; i<challenge.n; ++i) {
      z = crypto.sha256(new Buffer(z)).toString('hex').toLowerCase();
      zNames.push(z.substr(0, 32) + '.' + z.substr(32) + '.acme.invalid');
    }

    var opts = {
      host:               'localhost',
      port:               PORT,
      rejectUnauthorized: false
    };
    var testAll = function() {
      if (zNames.length === 0) {
        return true;
      }

      opts.servername = zNames.pop();
      return tlsConnectAsync(opts)
      .then((conn) => {
        var san = conn.getPeerCertificate().subjectaltname;
        conn.end();

        assert.ok(san);
        assert.equal(san, 'DNS:' + opts.servername);
      })
      .then(testAll);
    };

    validator.ready
    .then(() => {
      validator.start();
      validator.server.on('error', (err) => {
        done(err);
      });
      return testAll();
    })
    .then(() => {
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
