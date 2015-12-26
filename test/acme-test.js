// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var assert       = require('chai').assert;
var crypto       = require('../lib/crypto-utils');
var AcmeProtocol = require('../lib/acme');
var server       = require('./fixtures/server');

const PORT = 4567;
const BASE = 'http://localhost:' + PORT;
const PATHS = {
  directory:        '/directory',
  termsOfService:   '/terms-of-service',
  newRegistration:  '/new-reg',
  registration:     '/reg/asdf',
  newAuthorization: '/new-authz',
  authorization:    '/authz/asdf'
};
const DIRECTORY_URL = BASE + PATHS.directory;
const KEY_SIZE = 512;

var privateKey;
var mockServerInstance;

describe('ACME protocol', function() {
  before(() => {
    mockServerInstance = new server(PORT).start();
    return crypto.generateKey(KEY_SIZE)
    .then((key) => { privateKey = key; });
  });

  after(() => { mockServerInstance.stop(); });

  it('creates', function() {
    assert.throws(() => { new AcmeProtocol(); });

    var a = new AcmeProtocol(privateKey, DIRECTORY_URL);
    assert.equal(a.privateKey, privateKey);
    assert.equal(a.directoryURI, DIRECTORY_URL);
  });

  it('gets the directory', function() {
    var a = new AcmeProtocol(privateKey, DIRECTORY_URL);
    return a.directory()
    .then(dir => {
      assert.property(dir, 'new-reg');
      assert.property(dir, 'terms-of-service');
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
    var badName = 'not!a!name';
    var goodName = 'not-example.com';
    var a = new AcmeProtocol(privateKey, DIRECTORY_URL);

    assert.throws(() => { a.newAuthorization(badName); });

    var url;
    var selectedChallenge;
    return a.newAuthorization(goodName)
    .then((authz) => {
      url = AcmeProtocol.getLocation(authz);
      assert.isObject(authz);
      assert.equal(authz.identifier.value, goodName);
      assert.isTrue(authz.challenges.length > 0);

      selectedChallenge = authz.challenges[0];
      return a.respondToChallenge(selectedChallenge);
    })
    .then((challenge) => {
      assert.deepEqual(challenge, selectedChallenge);
      return a.checkAuthorizationStatus(url);
    })
    .then(status => {
      assert.equal(status, 'valid');
    });
  });

  it('issues a certificate', function() {
    var a = new AcmeProtocol(privateKey, DIRECTORY_URL);

    var csr = new Buffer('3000', 'hex');
    return a.newCertificate(csr)
    .then((cert) => {
      assert.ok(Buffer.isBuffer(cert.body));
    });
  });

});
