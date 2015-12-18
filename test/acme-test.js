// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var assert       = require('chai').assert;
var crypto       = require('../lib/crypto-utils');
var AcmeProtocol = require('../lib/acme');
var server       = require('./fixtures/server');

var PORT = 4567;
var BASE = 'http://localhost:' + PORT;
var PATHS = {
  directory:        '/directory',
  termsOfService:   '/terms-of-service',
  newRegistration:  '/new-reg',
  registration:     '/reg/asdf',
  newAuthorization: '/new-authz',
  authorization:    '/authz/asdf'
};
var DIRECTORY_URL = BASE + PATHS.directory;
var KEY_SIZE = 512;

var privateKey;
var mockServerInstance;
before(() => {
  mockServerInstance = new server(PORT).start();
  return crypto.generateKey(KEY_SIZE)
  .then((key) => { privateKey = key; });
});
after(() => { mockServerInstance.stop(); });

describe('ACME protocol', function() {
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

    return a.newAuthorization(goodName)
    .then((authz) => {
      assert.isObject(authz);
      assert.equal(authz.identifier.value, goodName);

      // TODO: 'reg' not defined
      // assert.deepEqual(reg.contact, goodContact);

      // Clear the nonces to cause auto-refresh
      a.nonces = [];

      // assert.throws(() => { a.updateRegistration(null, reg); });

    });
  });

});
