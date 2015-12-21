// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var Promise = require('bluebird');
var http    = require('http');           // https://nodejs.org/api/http.html
var tls     = require('tls');            // https://nodejs.org/api/tls.html
var util    = require('./utils');
var crypto  = require('./crypto-utils');

// The fields that should be present in a completed challenge
const CHALLENGE_FIELDS = ['type', 'token', 'keyAuthorization'];

/**
 * Create a server to respond to the 'http-01' challenge.  All validation
 * servers have listen(port) and close() methods.
 *
 * XXX(rlb): Should turn this into a class.
 *
 * @param  {string} domain Domain name being validated
 * @param  {object} challenge ACME challenge object being used for validation
 * @return {object} A server object
 * @throws {TypeError} Invalid challenge
 */
module.exports.HTTP01Server = function(domain, challenge) {
  if (!util.fieldsPresent(CHALLENGE_FIELDS, challenge) ||
      (challenge.type !== 'http-01')) {
    throw new TypeError('Mal-formed challenge');
  }

  function http01_serve(req, response) {
    var host = req.headers['host'];
    if ((host.split(/:/)[0] === domain) &&
        (req.method === 'GET') &&
        (req.url === '/.well-known/acme-challenge/' + challenge.token)) {
      response.writeHead(200, {'Content-Type': 'text/plain'});
      response.end(challenge.keyAuthorization);
    } else {
      response.writeHead(404);
      response.end('');
    }
  }
  var server = http.createServer(http01_serve);

  this.listen = function http01_listen(port) {
    return new Promise.resolve(server.listen(port));
  };

  this.close = function http01_close() {
    return server.close();
  };

  return this;
};

/**
 * Create a server to respond to the 'tls-sni-01' challenge.  All validation
 * servers have listen(port) and close() methods.
 *
 * XXX(rlb): Should turn this into a class.
 *
 * @param  {string} domain Domain name being validated
 * @param  {object} challenge ACME challenge object being used for validation
 * @return {object} A server object
 * @throws {TypeError} Invalid challenge
 */
module.exports.TLSSNI01Server = function(domain, challenge) {
  if (!util.fieldsPresent(CHALLENGE_FIELDS, challenge) ||
      (challenge.type !== 'tls-sni-01')) {
    throw new TypeError('Mal-formed challenge');
  }

  var server;
  var getReady = crypto.generateKeyPair(2048)
    .then(function(keyPair) {
      var privateKeyPEM = crypto.privateKeyToPem(keyPair.privateKey);
      var defaultCertPEM = crypto.selfSigned('acme.invalid', keyPair);

      var opts = {
        key:  privateKeyPEM,
        cert: defaultCertPEM
      };
      var closeImmediately = function(socket) { socket.end(); };
      server = tls.createServer(opts, closeImmediately);

      var n = challenge.n || 1;
      var z = challenge.keyAuthorization;
      for (var i=0; i<n; ++i) {
        // Z(i) = lowercase_hexadecimal(SHA256(Z(i-1)))
        z = crypto.sha256(new Buffer(z)).toString('hex').toLowerCase();
        var zName = z.substr(0, 32) + '.' + z.substr(32) + '.acme.invalid';

        var certPEM = crypto.selfSigned(zName, keyPair);
        server.addContext(zName, {
          key:  privateKeyPEM,
          cert: certPEM
        });
      }
    });

  this.listen = function tlssni01_listen(port) {
    return getReady.then(function() {
      server.listen(port);
    });
  };

  this.close = function tlssni01_close() {
    return server.close();
  };

  return this;
};
