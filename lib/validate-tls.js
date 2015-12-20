// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var util   = require('./utils');
var crypto = require('./crypto-utils');
var dns    = require('native-dns');

// The fields that should be present in a completed challenge
const CHALLENGE_FIELDS = ['type', 'token', 'keyAuthorization'];

/**
 * A TLSSNI01Validator performs the client-side half of the ACME 'tls-sni-01'
 * validation.  Based on a challenge, it creates a sequence of hashes values and
 * responds in the correct way to TLS queries to server names based on those
 * hash values.
 */
class TLSSNI01Validator {
  /**
   * Create a DNS validation server.
   *
   * @param  {string}  domain    Domain name being validated
   * @param  {object}  challenge ACME challenge object being used for validation
   * @param  {integer} port      Port number on which to listen
   * @return {TLSSNI01Validator} The created server object
   * @throws {TypeError}         Invalid challenge
   */
  constructor(domain, challenge, port) {
    if (!util.fieldsPresent(CHALLENGE_FIELDS, challenge) ||
        (challenge.type !== 'tls-sni-01')) {
      throw new TypeError('Mal-formed challenge');
    }

    this.ready = crypto.generateKeyPair(2048)
    .then((keyPair) => {
      var privateKeyPEM = crypto.privateKeyToPem(keyPair.privateKey);
      var defaultCertPEM = crypto.selfSigned('acme.invalid', keyPair);

      var opts = {
        key:  privateKeyPEM,
        cert: defaultCertPEM
      };
      var closeImmediately = function(socket) { socket.end(); };
      this.server = tls.createServer(opts, closeImmediately);

      var n = challenge.n || 1;
      var z = challenge.keyAuthorization;
      for (var i=0; i<n; ++i) {
        // Z(i) = lowercase_hexadecimal(SHA256(Z(i-1)))
        z = crypto.sha256(new Buffer(z)).toString('hex').toLowerCase();
        var zName = z.substr(0, 32) + '.' + z.substr(32) + '.acme.invalid';

        var certPEM = crypto.selfSigned(zName, keyPair);
        this.server.addContext(zName, {
          key:  privateKeyPEM,
          cert: certPEM
        });
      }
    });
  }

  /**
   * Start the server
   *
   * @return {TLSSNI01Validator} Object instance
   */
  start() {
    this.server.listen(this.port);
    return this;
  }

  /**
   * Stop the server
   *
   * @return {TLSSNI01Validator} Object instance
   */
  stop() {
    this.server.close();
    return this;
  }
}

module.exports = TLSSNI01Validator;
