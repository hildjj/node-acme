// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var express    = require('express');
var bodyParser = require('body-parser');

/**
 * HTTP01 ACME validation
 */
class HTTP01validator {
  /**
   * Create a validator
   *
   * @param  {string}  domain    The domain to listen for
   * @param  {object}  challenge The challenge returned from an authz request
   * @param  {number=} port      Port to listen on (default: 80)
   * @return {HTTP01validator}   Created object
   */
  constructor(domain, challenge, port) {
    this.port = port || 80;
    this.app = express();
    this.app.use(bodyParser.json());
    this.app.get('/.well-known/acme-challenge/:token', (req, res) => {
      var host = req.headers['host'];
      if ((host.split(/:/)[0] === domain) &&
          (req.params.token === challenge.token)) {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end(challenge.keyAuthorization);
      } else {
        res.writeHead(404);
        res.end('');
      }
    });
  }

  /**
   * Start the server
   *
   * @return {HTTP01validator} Object instance
   */
  start() {
    this.server = this.app.listen(this.port);
    return this;
  }

  /**
   * Start the server
   *
   * @return {HTTP01validator} Object instance
   */
  stop() {
    this.server.close();
    return this;
  }
}

module.exports = HTTP01validator;
