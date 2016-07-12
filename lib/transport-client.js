'use strict';

const jose        = require('./jose');
const rp          = require('request-promise');
const Promise     = require('bluebird');

const DEFAULT_POLL_LIMIT = 4;
const DEFAULT_POLL_DELAY = 500;

class TransportClient {
  constructor(options) {
    if (!options.accountKey) {
      throw new TypeError('Account key required');
    }

    this.accountKey = options.accountKey;
    this.nonces = [];
  }

  static get(url, binary) {
    let options = {uri: url};

    if (binary) {
      options.encoding = null;
    } else {
      options.json = true;
    }

    return rp.get(options);
  }

  static poll(url, test, limit, delay) {
    if (limit <= 0) {
      throw new Error('Polling limit exceeded');
    }

    limit = limit || DEFAULT_POLL_LIMIT;
    delay = delay || DEFAULT_POLL_DELAY;

    return this.get(url)
    .then(obj => {
      if (test(obj)) {
        return obj;
      }

      return Promise.delay(delay)
        .then(() => this.poll(url, test, limit - 1, delay));
    });
  }

  _nonce(url) {
    let nonce = this.nonces.shift();

    if (nonce) {
      return Promise.resolve(nonce);
    }

    return rp.head({
      uri:                     url,
      json:                    true,
      resolveWithFullResponse: true
    })
    .then(resp => {
      if (resp.headers['replay-nonce']) {
        return resp.headers['replay-nonce'];
      }
      throw new Error('No nonce available');
    });
  }

  post(url, body) {
    return this._nonce(url)
    .then(nonce => {
      let header = {
        nonce: nonce,
        url:   url
      };
      return jose.sign(this.accountKey, body, header);
    })
    .then(jws => {
      return rp.post({
        uri:                     url,
        resolveWithFullResponse: true,
        json:                    true,
        body:                    jws
      });
    })
    .then(resp => {
      let out = resp.body;
      // TODO capture link, location headers
      if (resp.headers['replay-nonce']) {
        this.nonces.push(resp.headers['replay-nonce']);
      }
      return out;
    });
  }
}

module.exports = TransportClient;
