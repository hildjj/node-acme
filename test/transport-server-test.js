// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert          = require('chai').assert;
const request         = require('supertest');
const jose            = require('../lib/jose');
const TransportServer = require('../lib/transport-server');

let NONCE_RE = /^[a-zA-Z0-9-_]+$/;
let FAKE_CLIENT = {
  payload: {'fnord': true},

  key: function() {
    if (this._key) {
      return Promise.resolve(this._key);
    }
    return jose.newkey()
      .then(k => {
        this._key = k;
        return k;
      });
  },

  makeJWS: function(nonce, url) {
    return this.key()
      .then(k => jose.sign(k, this.payload, {
        nonce: nonce,
        url:   url
      }));
  }
};

describe('transport-level server', function() {
  it('responds to a valid POST request', function(done) {
    let server = new TransportServer();
    let nonce = server.nonces.get();

    let gotPOST = false;
    let result = {'bar': 2};
    server.app.post('/foo', (req, res) => {
      gotPOST = true;

      try {
        assert.deepEqual(req.payload, FAKE_CLIENT.payload);
      } catch (e) {
        res.status(418);
      }

      res.json(result);
    });

    FAKE_CLIENT.makeJWS(nonce, 'http://0.0.0.0/foo')
    .then(jws => {
      request(server.app)
        .post('/foo')
        .send(jws)
        .expect(200)
        .expect('replay-nonce', NONCE_RE, done)
        .expect(body => {
          assert.isTrue(gotPOST);
          assert.deepEqual(body, result);
        });
    });
  });

  it('rejects a POST with a bad nonce', function(done) {
    let server = new TransportServer();

    FAKE_CLIENT.makeJWS('asdf', 'http://0.0.0.0/foo?bar=baz')
    .then(jws => {
      request(server.app)
        .post('/foo?bar=baz')
        .send(jws)
        .expect(400, done);
    });
  });

  it('rejects a POST with a bad url', function(done) {
    let server = new TransportServer();
    let nonce = server.nonces.get();

    FAKE_CLIENT.makeJWS(nonce, 'http://example.com/foo?bar=baz')
    .then(jws => {
      request(server.app)
        .post('/foo?bar=baz')
        .send(jws)
        .expect(400, done);
    });
  });

  it('provides a nonce for GET requests', function(done) {
    let server = new TransportServer();
    request(server.app)
      .get('/')
      .expect(404)
      .expect('replay-nonce', NONCE_RE, done);
  });

  it('provides a nonce for HEAD requests', function(done) {
    let server = new TransportServer();
    request(server.app)
      .head('/')
      .expect(404)
      .expect('replay-nonce', NONCE_RE)
      .end(done);
  });
});
