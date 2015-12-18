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
  directory:        '/directory',
  termsOfService:   '/terms-of-service',
  newRegistration:  '/new-reg',
  registration:     '/reg/asdf',
  newAuthorization: '/new-authz',
  authorization:    '/authz/asdf',
};
var DIRECTORY = {
  'terms-of-service': BASE + PATHS.termsOfService,
  'new-reg':          BASE + PATHS.newRegistration
};
var DIRECTORY_URL = BASE + PATHS.directory;
var NONCE = 'random';
var KEY_SIZE = 512;

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
  mockServer.registration = req.body;

  res.append('Link', directoryLink('terms-of-service'));
  res.append('Location', BASE + PATHS.registration);
  var reg = {'field': 'thing'};
  if (req.body.contact) {
    reg.contact = req.body.contact;
  }
  res.send(reg);
});

mockServer.post(PATHS.registration, function(req, res) {
  mockServer.registration['contact'] = req.body['contact'];
  mockServer.registration['agreement'] = req.body['agreement'];
  res.send(mockServer.registration);
});

mockServer.post(PATHS.newAuthorization, function(req, res) {
  // TODO
});

mockServer.post(PATHS.authorization, function(req, res) {
  // TODO
});

var privateKey;
var mockServerInstance;
before(() => {
  mockServerInstance = mockServer.listen(PORT);
  return crypto.generateKey(KEY_SIZE)
  .then((key) => { privateKey = key; });
});
after(() => { mockServerInstance.close(); });

describe('ACME protocol', function() {
  it('creates', function() {
    assert.throws(() => { var a = new AcmeProtocol(); });

    var a = new AcmeProtocol(privateKey, DIRECTORY_URL);
    assert.equal(a.privateKey, privateKey);
    assert.equal(a.directoryURI, DIRECTORY_URL);
  });

  it('gets the directory', function() {
    var a = new AcmeProtocol(privateKey, DIRECTORY_URL);
    return a.directory()
    .then(dir => {
      assert.deepEqual(dir, DIRECTORY);
    });
  });

  it('creates and updates a registration', function() {
    var badContact = 'not an array';
    var goodContact = ['mailto:alpha@zulu.com'];
    var secondContact = ['mailto:bravo@zulu.com'];

    var a = new AcmeProtocol(privateKey, DIRECTORY_URL);

    assert.throws(() => { a.newRegistration(badContact); });

    return a.newRegistration(goodContact)
    .then((reg) => {
      assert.isObject(reg);
      assert.deepEqual(reg.contact, goodContact);

      // Clear the nonces to cause auto-refresh
      a.nonces = [];

      assert.throws(() => { a.updateRegistration(null, reg); });

      var url = AcmeProtocol.getLocation(reg);
      reg.agreement = AcmeProtocol.getLink(reg, 'terms-of-service');
      reg.contact = secondContact;
      return a.updateRegistration(url, reg);
    })
    .then((reg) => {
      assert.isObject(reg);
      assert.deepEqual(reg.contact, secondContact);
    });
  });

  it('creates an authorization and responds to a challenge', function() {
    var badName = "not!a!name";
    var goodName = "not-example.com";
    var a = new AcmeProtocol(privateKey, DIRECTORY_URL);

    assert.throws(() => { a.newAuthorization(badName); });

    return a.newAuthorization(goodName)
    .then((authz) => {
      assert.isObject(authz);
      assert.equal(authz.identifier.value, goodName);

      assert.deepEqual(reg.contact, goodContact);

      // Clear the nonces to cause auto-refresh
      a.nonces = [];

      assert.throws(() => { a.updateRegistration(null, reg); });

    })
  });

});
