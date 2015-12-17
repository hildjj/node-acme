// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var express = require('express');
var crypto = require('../lib/crypto-utils');

var app = express();

var PORT = 4001;
var BASE = 'http://localhost:' + PORT + '/';

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
  var bufs = [];
  req.on('data', function(buf) {
    bufs.push(buf);
  });
  req.on('end', function() {
    var buf = Buffer.concat(bufs);
    var signed = JSON.parse(buf);
    crypto.verifySignature(signed)
    .then((payload) => {
      res.links({
        next:               BASE + 'new-authz',
        recover:            BASE + 'recover-reg',
        'terms-of-service': BASE + 'terms'
      });
      res.statusCode = 201;
      res.send({
        key:     payload.header.jwk,
        contact: payload.contact
      });
    })
    .catch((er) => {
      res.statusCode = 418; // I'm a teapot.
      res.send({
        type:    'urn:acme:malformed',
        detail:  'Invalid signature',
        message: er.message
      });
    });
  });
});

app.listen(PORT);
