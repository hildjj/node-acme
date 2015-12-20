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
 * A DNS01Validator performs the client-side half of the ACME 'dns-01'
 * validation.  Based on a challenge, it creates the TXT record specified by the
 * protocol and returns it in response to a query for the proper domain name.
 */
class DNS01Validator {
  /**
   * Create a DNS validation server.
   *
   * @param  {string}  domain    Domain name being validated
   * @param  {object}  challenge ACME challenge object being used for validation
   * @param  {integer} port      Port number on which to listen
   * @return {object}            A server object
   * @throws {TypeError} Invalid challenge
   */
  constructor(domain, challenge, port) {
    if (!util.fieldsPresent(CHALLENGE_FIELDS, challenge) ||
        (challenge.type !== 'dns-01')) {
      throw new TypeError('Mal-formed challenge');
    }

    this.port = port;

    var recordName = '_acme-challenge.' + domain;
    var recordValue = crypto.sha256(new Buffer(challenge.keyAuthorization))
                            .toString('base64')
                            .replace(/=*$/, '');
    var record = dns.TXT({
      name: recordName,
      data: [recordValue],
      ttl:  600
    });

    this.server = dns.createServer();
    this.server.on('request', function dns01_serve(request, response) {
      if (request.question.length === 0) {
        response.header.rcode = dns.consts.NAME_TO_RCODE.FORMERR;
      } else if ((request.question[0].class !== dns.consts.NAME_TO_QCLASS.IN) ||
          (request.question[0].type !== dns.consts.NAME_TO_QTYPE.TXT) ||
          (request.question[0].name !== recordName)) {
        response.header.rcode = dns.consts.NAME_TO_RCODE.NOTFOUND;
      } else {
        response.answer.push(record);
      }
      response.send();
    });
  }

  /**
   * Start the server
   *
   * @return {DNS01Validator} Object instance
   */
  start() {
    this.server.serve(this.port);
    return this;
  }

  /**
   * Stop the server
   *
   * @return {DNS01Validator} Object instance
   */
  stop() {
    this.server.close();
    return this;
  }
}

module.exports = DNS01Validator;
