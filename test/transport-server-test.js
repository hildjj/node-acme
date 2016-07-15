// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert          = require('chai').assert;
const request         = require('supertest');
const MockClient      = require('./tools/mock-client');
const promisify       = require('./tools/promisify');
const TransportServer = require('../lib/transport-server');

let nonceRE = /^[a-zA-Z0-9-_]+$/;
let mockClient = new MockClient();

describe('transport-level server', function() {
  it('responds to a valid POST request', function(done) {
    let server = new TransportServer();
    let nonce = server.nonces.get();
    let payload = {'fnord': 42};

    let gotPOST = false;
    let result = {'bar': 2};
    server.app.post('/foo', (req, res) => {
      gotPOST = true;

      try {
        assert.deepEqual(req.payload, payload);
      } catch (e) {
        res.status(418);
      }

      res.json(result);
    });

    mockClient.makeJWS(nonce, 'http://0.0.0.0/foo', payload)
      .then(jws => promisify(request(server.app).post('/foo').send(jws)))
      .then(res => {
        assert.equal(res.status, 200);

        assert.property(res.headers, 'replay-nonce');
        assert.ok(res.headers['replay-nonce'].match(nonceRE));

        assert.isTrue(gotPOST);
        assert.deepEqual(res.body, result);
        done();
      })
      .catch(done);
  });

  it('rejects a POST with a bad nonce', function(done) {
    let server = new TransportServer();

    mockClient.makeJWS('asdf', 'http://0.0.0.0/foo?bar=baz')
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

    mockClient.makeJWS(nonce, 'http://example.com/foo?bar=baz')
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
      .expect('replay-nonce', nonceRE, done);
  });

  it('provides a nonce for HEAD requests', function(done) {
    let server = new TransportServer();
    request(server.app)
      .head('/')
      .expect(404)
      .expect('replay-nonce', nonceRE)
      .end(done);
  });
});
