// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var express    = require('express');
var bodyParser = require('body-parser');
var jose       = require('node-jose');
var crypto     = require('../lib/crypto-utils');

var PORT       = 3900;
var BASE       = 'http://localhost:' + PORT + '/';
var NONCE_SIZE = 16;

var nonces = new Set();

var app = express();
app.use(bodyParser.json());
app.use(function(req, res, next) {
  var nonce = jose.util.randomBytes(NONCE_SIZE).toString('hex');
  nonces.add(nonce);
  res.append('Replay-Nonce', nonce);
  next();
});
app.post('/*', function(req, res, next) {
  crypto.verifySignature(req.body)
  .then((sig) => {
    req.sig = sig;
    var nonce = req.sig.header.nonce;

    if (!nonces.delete(nonce)) {
      return res.status(401).send({
        type:   'urn:acme:badNonce',
        detail: 'Unknown nonce'
      });
    }
    next();
  }, (er) => {
     // I'm a teapot.
    return res.status(418).send({
      type:    'urn:acme:malformed',
      detail:  'Invalid signature',
      message: er.message
    });
  });
});

app.head('/*', function(req, res) {
  res.end();
});

app.get('/', function(req, res) {
  res.links({
    test:  'testing',
    test2: 'foo'
  });
  res.send({
    'new-reg':     BASE + 'new-reg',
    'recover-reg': BASE + 'recover-reg',
    'new-authz':   BASE + 'new-authz',
    'new-cert':    BASE + 'new-cert',
    'revoke-cert': BASE + 'revoke-cert'
  });
});

app.get('/terms', function(req, res) {
  res.send('BOILERPLATE LEGALESE\n');
});

app.post('/new-reg', function(req, res) {
  res.links({
    next:               BASE + 'new-authz',
    recover:            BASE + 'recover-reg',
    'terms-of-service': BASE + 'terms'
  });
  res.statusCode = 201;
  res.send({
    key:     req.sig.header.jwk,
    contact: req.sig.payload.contact
  });

});

app.listen(PORT);
