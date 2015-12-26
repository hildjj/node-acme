// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var express    = require('express');
var bodyParser = require('body-parser');
var jose       = require('node-jose');
var crypto     = require('../../lib/crypto-utils');
var utils      = require('../../lib/utils');

const PORT       = 3900;
const NONCE_SIZE = 16;

function _setup(app, server) {
  app.use(bodyParser.json());
  app.use(function(req, res, next) {
    var nonce = jose.util.randomBytes(NONCE_SIZE).toString('hex');
    server.nonces.add(nonce);
    res.append('Replay-Nonce', nonce);
    next();
  });
  app.post('/*', function(req, res, next) {
    crypto.verifySignature(req.body)
    .then((sig) => {
      req.sig = sig;
      var nonce = req.sig.header.nonce;

      if (!server.nonces.delete(nonce)) {
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
    res.send(server.directory);
  });

  app.get('/directory', function(req, res) {
    res.send(server.directory);
  });

  app.get('/terms', function(req, res) {
    res.send('BOILERPLATE LEGALESE\n');
  });

  app.post('/new-reg', function(req, res) {
    res.links({
      next:               server.base + 'new-authz',
      recover:            server.base + 'recover-reg',
      'terms-of-service': server.base + 'terms'
    });
    var c = server.count++;
    server.registrations[c] = utils.extract(['contact', 'agreement'], req.sig.payload);
    res.location(server.base + 'reg/' + c);
    res.status(201).send({
      contact: req.sig.payload.contact
    });
  });

  app.post('/reg/:id', function(req, res) {
    var reg = server.registrations[req.params.id];
    if (reg == null) {
      return res.status(404).send({
        type:   'urn:acme:notFound',
        detail: 'Unknown registration'
      });
    }
    // TODO: check jwk for match
    reg = utils.extend(reg, utils.extract(['contact', 'agreement'], req.sig.payload));
    server.registrations[req.params.id] = reg;
    return res.status(200).send(reg);
  });

  app.get('/reg/:id', function(req, res) {
    var reg = server.registrations[req.params.id];
    if (reg == null) {
      return res.status(404).send({
        type:   'urn:acme:notFound',
        detail: 'Unknown registration'
      });
    }
    return res.status(200).send(reg);
  });

  var authz;
  app.post('/new-authz', function(req, res) {
    authz = req.sig.payload;
    authz.status = 'pending';
    authz.challenges = [{
      uri:   server.base + 'challenge',
      token: jose.util.randomBytes(NONCE_SIZE).toString('hex')
    }];
    res.location(server.base + 'authz/asdf');
    return res.status(201).send(authz);
  });

  app.get('/authz/asdf', function(req, res) {
    return res.status(200).send(authz);
  });

  app.post('/challenge', function(req, res) {
    authz.status = 'valid';
    res.status(200).send(req.sig.payload);
  });

  app.post('/new-cert', function(req, res) {
    var cert = new Buffer('3000', 'hex');
    res.status(201)
       .append('content-type', 'application/pkix-cert')
       .send(cert);
  })
}

class AcmeServer {
  constructor(port) {
    this.port = port;
    this.base = 'http://localhost:' + port + '/';

    this.nonces = new Set();
    this.count  = 0;
    this.registrations = {};
    this.app = express();
    this.directory = {
      'new-reg':          this.base + 'new-reg',
      'terms-of-service': this.base + 'tos',
      'new-authz':        this.base + 'new-authz',
      'new-cert':         this.base + 'new-cert'
    };
    _setup(this.app, this);
  }
  start() {
    this.server = this.app.listen(this.port);
    return this;
  }
  stop() {
    this.server.close();
    return this;
  }
}
module.exports = AcmeServer;

if (require.main === module) {
  new AcmeServer(PORT).start();
}
