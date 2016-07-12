'use strict';

const jose        = require('./jose');
const nonceSource = require('./nonce-source');
const express     = require('express');
const bodyParser  = require('body-parser');
const urlParse    = require('url');

class TransportServer {
  constructor() {
    this.app = express();
    this.nonces = new nonceSource();

    // Every POST should have a JSON (JWS) body
    this.app.use(bodyParser.json());

    // Send a replay nonce on all responses
    this.app.all('/*', (req, res, next) => {
      res.set('replay-nonce', this.nonces.get());
      next();
    });

    this.app.post('/*', (req, res, next) => {
      jose.verify(req.body)
      .then(result => {
        let nonce = result.header.nonce;
        let url = result.header.url;

        if (!this.nonces.use(nonce)) {
          throw new Error('Invalid nonce');
        }

        if (!this._checkURL(req, url)) {
          throw new Error('Incorrect url value');
        }

        req.accountKey = result.header.jwk;
        req.payload = result.payload;

        next();
      })
      .catch(err => {
        res.status(400);
        res.json({
          'type':   'urn:ietf:params:acme:error:malformed',
          'title':  'Request failed transport-level validation',
          'detail': err.message
        });
      });
    });
  }

  _checkURL(req, url) {
    let parsed = urlParse.parse(url);

    // XXX: This just compares the 'url' field to the request parameters.
    // It thus assumes that routing is working correctly.
    return (parsed.host === req.hostname) &&
      (parsed.path === req.originalUrl);
  }
}

module.exports = TransportServer;
