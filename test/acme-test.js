// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var express      = require('express');
var bodyParser   = require('body-parser');
var assert       = require('chai').assert;
var crypto       = require('../lib/crypto-utils');
var AcmeProtocol = require('../lib/acme');

var PORT = 4567;
var BASE = 'http://localhost:' + PORT;
var PATHS = {
  directory:       '/directory',
  termsOfService:  '/terms-of-service',
  newRegistration: '/new-reg'
};
var DIRECTORY = {
  'terms-of-service': BASE + PATHS.termsOfService,
  'new-reg':          BASE + PATHS.newRegistration
};
var DIRECTORY_URL = BASE + PATHS.directory;
var NONCE = 'random';

function directoryLink(rel) {
  return '<' + DIRECTORY[rel] + '>;rel=' + rel;
}

// TODO: Test nonce behavior
var mockServer = express();
mockServer.use(bodyParser.json());
mockServer.use(function(req, res, next) {
  res.append('Replay-Nonce', NONCE);
  next();
});
mockServer.head('/*', function(req, res) {
  res.end();
});
mockServer.post('/*', function(req, res, next) {
  crypto.verifySignature(req.body)
  .then((sig) => {
    if (sig.header['nonce'] !== NONCE) {
      throw new Error('Missing or incorrect nonce');
    }

    req.body = sig.payload;
  })
  .then(next);
});

mockServer.get(PATHS.directory, function(req, res) {
  res.send(DIRECTORY);
});

mockServer.post(PATHS.newRegistration, function(req, res) {
  res.append('Link', directoryLink('terms-of-service'));
  var reg = {'field': 'thing'};
  if (req.body.contact) {
    reg.contact = req.body.contact;
  }
  res.send(reg);
});

var mockServerInstance;
before(() => { mockServerInstance = mockServer.listen(PORT); });
after(() => { mockServerInstance.close(); });

var privateKey = crypto.generateKey(2048);

describe('ACME protocol', function() {
  it('creates', function() {
    var a = new AcmeProtocol(privateKey, DIRECTORY_URL);
    assert.ok(a);
  });

  it('gets the directory', function() {
    var a = new AcmeProtocol(privateKey, DIRECTORY_URL);
    return a.directory()
    .then(dir => {
      assert.deepEqual(dir, DIRECTORY);
    });
  });

  it('creates a registration', function() {
    var badContact = 'not an array';
    var goodContact = ['mailto:alpha@bravo.com'];

    var a = new AcmeProtocol(privateKey, DIRECTORY_URL);

    assert.throws(() => { a.newRegistration(badContact); });

    return a.newRegistration(goodContact)
    .then((reg) => {
      assert.isObject(reg);
      assert.deepEquals(reg.contact, goodContact);
    }, () => { throw new Error('wtf'); });
  });

  it('creates an authorization', function() {
    // TODO
  });

});
