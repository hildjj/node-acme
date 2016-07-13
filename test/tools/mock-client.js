'use strict';

const jose = require('../../lib/jose');

class MockClient {
  key() {
    if (this._key) {
      return Promise.resolve(this._key);
    }
    return jose.newkey()
      .then(k => {
        this._key = k;
        return k;
      });
  }

  makeJWS(nonce, url, payload) {
    return this.key()
      .then(k => jose.sign(k, payload, {
        nonce: nonce,
        url:   url
      }));
  }
};

module.exports = MockClient;
