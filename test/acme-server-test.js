// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert     = require('chai').assert;
const request    = require('supertest');
const MockClient = require('./tools/mock-client');
const ACMEServer = require('../lib/acme-server');

//let fakeClient = new FakeClient();
let serverConfig = {
  host:     '0.0.0.0'
};
let mockClient = new MockClient();

describe('ACME server', function() {
  it('responds to a directory request', function(done) {
    let server = new ACMEServer(serverConfig);
    let termsURL = 'https://example.com/terms';

    server.terms = termsURL;

    request(server.app)
      .get('/directory')
      .expect(200)
      .expect(function(res) {
        assert.property(res, 'meta');
        assert.isObject(res.meta);
        assert.property(res.meta, 'terms-of-service');
        assert.equal(res.meta['terms-of-service'], termsURL);
        assert.property(res, 'new-reg');
        // TODO Add things here as they get added to the directory
      }, done);
  });

  it('answers a valid fetch', function(done) {
    let server = new ACMEServer(serverConfig);
    let reg = {
      type:    function() { return 'foo'; },
      id:      'bar',
      marshal: function() { return {baz: 42}; }
    };

    server.db.put(reg);
    request(server.app)
      .get('/foo/bar')
      .expect(200)
      .expect(function(res) {
        assert.deepEqual(res, reg.marshal());
      }, done);
  });

  it('rejects a fetch for a registration object', function(done) {
    let server = new ACMEServer(serverConfig);
    request(server.app)
      .get('/reg/foo')
      .expect(401, done);
  });

  it('rejects a fetch for a non-existent object', function(done) {
    let server = new ACMEServer(serverConfig);
    request(server.app)
      .get('/foo/bar')
      .expect(404, done);
  });

  it('creates a new registration', function(done) {
    let server = new ACMEServer(serverConfig);
    let termsURL = 'https://example.com/terms';
    server.terms = termsURL;

    let nonce = server.transport.nonces.get();
    let url = server.baseURL + 'new-reg';
    let reg = {contact: ['mailto:anonymous@example.com']};

    mockClient.makeJWS(nonce, url, reg)
      .then(jws => {
        request(server.app)
          .post('/new-reg')
          .send(jws)
          .expect(201)
          .expect('location', /.*/)
          .expect('link', /.*/)
          .expect(function(body) {
            assert.property(body, 'key');
            assert.property(body, 'contact');
            assert.deepEqual(body.key, mockClient._key.toJSON());
            assert.deepEqual(body.contact, reg.contact);
          }, done);
      });
  });

  it('rejects a new registration for an existing key', function(done) {
    let server = new ACMEServer(serverConfig);
    let termsURL = 'https://example.com/terms';
    server.terms = termsURL;

    let nonce = server.transport.nonces.get();
    let url = server.baseURL + 'new-reg';
    let reg = {contact: ['mailto:anonymous@example.com']};
    let jws;

    mockClient.makeJWS(nonce, url, reg)
      .then(signed => {
        jws = signed;
        return mockClient._key.thumbprint();
      })
      .then(tpBuffer => {
        let reg = {
          id:   tpBuffer.toString('hex'),
          type: function() { return 'reg'; }
        };
        server.db.put(reg);

        request(server.app)
          .post('/new-reg')
          .send(jws)
          .expect(409)
          .expect('location', /.*/, done);
      });
  });
});
