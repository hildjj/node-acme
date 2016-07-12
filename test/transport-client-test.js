// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert          = require('chai').assert;
const nock            = require('nock');
const jose            = require('../lib/jose');
const TransportClient = require('../lib/transport-client');

describe('transport-level client', function() {
  afterEach(() => {
    nock.cleanAll();
  });

  it('fails if no account key if is provided', function() {
    try {
      new TransportClient({});
      assert.ok(false);
    } catch (e) {
      assert.ok(true);
    }
  });

  it('performs a JSON GET request', function(done) {
    let content = {'result': true};
    nock('http://example.com')
      .get('/foo').reply(200, content);

    TransportClient.get('http://example.com/foo')
      .then(body => {
        assert.deepEqual(body, content);
        done();
      })
      .catch(done);
  });

  it('performs a binary GET request', function(done) {
    let content = 'asdf';
    nock('http://example.com')
      .get('/foo').reply(200, content);

    TransportClient.get('http://example.com/foo', true)
      .then(body => {
        assert.isTrue(body instanceof Buffer);
        assert.equal(body.toString(), content);
        done();
      })
      .catch(done);
  });

  it('polls until completion or timeout', function(done) {
    let test = (body => body.foo);
    nock('http://example.com')
      .get('/foo').reply(200, {})
      .get('/foo').reply(200, {'foo': 'bar'});

    TransportClient.poll('http://example.com/foo', test)
      .then(body => {
        assert.ok(test(body));
      })
      .catch(err => assert.ok(false, err.message))
      .then(() => {
        nock('http://example.com')
          .get('/foo').reply(200, {})
          .get('/foo').reply(200, {})
          .get('/foo').reply(200, {'foo': 'bar'});
        return TransportClient.poll('http://example.com/foo', test, 2, 10);
      })
      .then(() => { done(new Error('should have failed')); })
      .catch(() => { done(); });
  });

  it('sends a POST with no preflight', function(done) {
    let gotHEAD = false;
    let gotPOST = false;
    let nonce = 'foo';
    nock('http://example.com')
      .head('/foo').reply((uri, requestBody, cb) => {
        gotHEAD = true;
        cb(null, [200, '', {'replay-nonce': nonce}]);
      })
      .post('/foo').reply((uri, jws, cb) => {
        gotPOST = true;
        jose.verify(jws)
        .then(result => {
          assert.equal(result.header.nonce, nonce);
          assert.ok(result.header.url);
          cb(null, [200, '']);
        })
        .catch(err => {
          cb(null, [400, err.message]);
        });
      });

    jose.newkey()
      .then(k => {
        let client = new TransportClient({accountKey: k});
        client.nonces.push(nonce);
        return client.post('http://example.com/foo', {'foo': 'bar'});
      })
      .then(() => {
        assert.isFalse(gotHEAD);
        assert.isTrue(gotPOST);
        done();
      })
      .catch(done);
  });

  it('sends a POST with preflight', function(done) {
    let gotHEAD = false;
    let gotPOST = false;
    let nonce = 'foo';
    nock('http://example.com')
      .head('/foo').reply((uri, requestBody, cb) => {
        gotHEAD = true;
        cb(null, [200, '', {'replay-nonce': nonce}]);
      })
      .post('/foo').reply((uri, jws, cb) => {
        gotPOST = true;
        jose.verify(jws)
        .then(result => {
          assert.equal(result.header.nonce, nonce);
          assert.ok(result.header.url);
          cb(null, [200, '', {'replay-nonce': nonce}]);
        })
        .catch(err => {
          cb(null, [400, err.message]);
        });
      });

    jose.newkey()
      .then(k => {
        let client = new TransportClient({accountKey: k});
        return client.post('http://example.com/foo', {'foo': 'bar'});
      })
      .then(() => {
        assert.isTrue(gotHEAD);
        assert.isTrue(gotPOST);
        done();
      })
      .catch(done);
  });

  it('fails POST if preflight fails', function(done) {
    nock('http://example.com')
      .head('/foo').reply(200);

    jose.newkey()
      .then(k => {
        let client = new TransportClient({accountKey: k});
        return client.post('http://example.com/foo', {'foo': 'bar'});
      })
      .then(() => { done(new Error('should have failed')); })
      .catch(() => { done(); });
  });
});
