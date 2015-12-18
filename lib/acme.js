// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var rp     = require('request-promise');
var log    = require('npmlog');
var jose   = require('node-jose');
var crypto = require('./crypto-utils');
var pkg    = require('../package');

require('request-debug')(rp, function(type, data) {
  // TODO: undo the JOSE and show the payload in the request.
  log.http('acme', '%j: %j', type, data);
});

var DEFAULTS = {
  // TODO: change to staging
  directoryURI: 'https://acme-v01.api.letsencrypt.org/directory'
};
var LINKS = Symbol('links');
var LOCATION = Symbol('location');

function _parseLink(link) {
  // TODO: Send this as a PR to
  //   https://github.com/ileri/http-header-link
  // and expand using:
  //   https://github.com/ileri/rfc-5987-encoding
  // to get more of the edge cases
  //
  // <testing>; rel="test", <foo>; rel="test2"; title="a test"
  try {
    // NB: Takes last among links with the same 'rel' value
    var links = link.split(',').map(function(lnk) {
      var parts = lnk.trim().split(';');
      var url = parts.shift().replace(/^<([^>]*)>$/, '$1');
      var info = parts.reduce(function(acc, p) {
        var m = p.trim().match(/^([^= ]+) *= *"([^"]+)"$/);
        if (m) { acc[m[1]] = m[2]; }
        return acc;
      }, {});
      info['url'] = url;
      return info;
    }).reduce(function(acc, info) {
      if ('rel' in info) {
        acc[info['rel']] = info['url'];
      }
      return acc;
    }, {});
    return links;
  } catch (e) {
    return null;
  }
}

/**
 * An AcmeProtocol represents the interactions of a single key pair with a single
 * ACME server.  The the methods to map fairly directly to the endpoints that an
 * ACME server exposes.
 */
class AcmeProtocol {
  /**
   * Create an AcmeClient
   * @param {jose.JWK.BaseKey} privateKey The private key for ACME account
   * @param {string=} directoryURI The URI for the ACME directory JSON
   * @return {AcmeProtocol} created object
   */
  constructor(privateKey, directoryURI) {
    if (!privateKey) {
      throw new TypeError('privateKey required');
    }
    this.nonces       = [];
    this.privateKey   = privateKey;
    this.directoryURI = directoryURI || DEFAULTS.directoryURI;
  }

  /**
   * Get the link relation of the given name from the object returned from
   * an AcmeProtocol request.
   *
   * @param  {object} obj  Object to query
   * @param {string=} name Name of the relation to retrieve, defaults to all
   * @return {string|object} property value if name specified, otherwise
   *                         object with all relations
   * @throws {TypeError} Invalid object
   */
  static getLink(obj, name) {
    if (!obj || !obj[LINKS]) {
      throw new TypeError('Invalid object, no links');
    }
    if (!name) {
      return obj[LINKS];
    }
    return obj[LINKS][name];
  }

  _nonce(uri) {
    var nonce = this.nonces.shift();
    if (nonce) {
      return Promise.resolve(nonce);
    }
    return rp.head({
      uri:                     uri,
      json:                    true,
      resolveWithFullResponse: true,
      headers:                 {
        'User-Agent': pkg.homepage
      }
    })
    .then((resp) => {
      if (resp.headers['replay-nonce']) {
        return resp.headers['replay-nonce'];
      }
      throw new Error('No nonce available');
    });
  }

  /**
   * Sign a JSON object with JOSE, then POST the signed object.
   *
   * @private
   * @param  {string} uri  URI to post
   * @param  {JSON} body   body to sign
   * @return {Promise<body,links>} returned document
   */
  _post(uri, body) {
    return this._nonce(uri)
    .then((nonce) => {
      return crypto.generateSignature(this.privateKey, nonce, body);
    })
    .then(function(jws) {
      return rp.post({
        uri:                     uri,
        json:                    true,
        body:                    jws,
        resolveWithFullResponse: true,
        headers:                 {
          'User-Agent': pkg.homepage
        }
      });
    })
    .then((resp) => {
      resp.body[LINKS]    = _parseLink(resp.headers.link);
      resp.body[LOCATION] = resp.headers.location;
      if (resp.headers['replay-nonce']) {
        this.nonces.push(resp.headers['replay-nonce']);
      }
      return resp.body;
    });
  }

  /**
   * Get the ACME directory object.
   *
   * @return {Promise<JSON>}        Fulfilled when directory available
   */
  directory() {
    if (!this.dirPromise) {
      this.dirPromise = rp.get({
        uri:                     this.directoryURI,
        json:                    true,
        resolveWithFullResponse: true
      })
      .then((resp) => {
        if (resp.headers['replay-nonce']) {
          this.nonces.push(resp.headers['replay-nonce']);
        }
        return resp.body;
      });
    }
    return this.dirPromise;
  }

  /**
   * Call `new-reg`
   *
   * @param  {Array<string>} contacts URIs of one or more contact methods
   * @param  {string=} agreement The URI for the contact terms
   * @return {Promise<registration>} The new registration
   */
  newRegistration(contacts, agreement) {
    if (!Array.isArray(contacts) || (contacts.length < 1)) {
      throw new TypeError('contacts must be non-empty array of URIs');
    }
    return this.directory()
    .then((dir) => {
      if (!dir['new-reg']) {
        throw new Error('No new-registration endpoint available');
      }

      var payload = {
        resource: 'new-reg',
        contact:  contacts
      };
      if (agreement) {
        payload.agreement = agreement;
      }
      return this._post(dir['new-reg'], payload);
    });
  }

  /**
   * Update a registration with new information.
   *
   * @param  {registration}   registration Updated registration object
   * @param  {Array<string>=} registration.contact Contact array
   * @param  {string=}        registration.agreement Terms of Service URI
   * @return {Promise<registration>} the new registration
   */
  updateRegistration(registration) {
    var uri = registration[LOCATION];
    if (!uri) {
      throw new TypeError('Invalid registration object');
    }
    registration.resource = 'reg';
    return this._post(uri, registration);
  }

  /**
   * Call `new-authz`
   *
   * @param  {string} domain Domain name to be authorized
   * @return {Promise<authorization>} The new authorization
   */
  newAuthorization(domain) {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      throw new TypeError('Authorization can only be done for domain names');
    }

    return this.directory()
    .then((dir) => {
      if (!dir['new-authz']) {
        throw new Error('No new-authorization endpoint available');
      }

      var payload = {
        resource:   'new-authz',
        identifier: {
          type:  'dns',
          value: domain
        }
      };
      return this._post(dir['new-authz'], payload);
    });
  }

  /**
   * Respond to a challenge.
   *
   * @param  {challenge}   challenge Updated registration object
   * @return {Promise<registration>} the new registration
   */
  updateRegistration(challenge) {
    if (!challenge.uri) {
      throw new TypeError('Invalid registration object');
    }

    challenge.resource = 'challenge';
    challenge.keyAuthorization = challenge.token + '.' +
                                 crypto.thumbprint(this.privateKey);

    return this._post(challenge.uri, challenge);
  }

  /**
   * Call `new-cert`
   *
   * @param  {Buffer} csr The DER-encoded certificate signing request
   * @return {Promise<certificate>} The new certificate
   */
  newCertificate(csr) {
    return this.directory()
    .then((dir) => {
      if (!dir['new-cert']) {
        throw new Error('No new-certificate endpoint available');
      }

      var payload = {
        resource: 'new-cert',
        csr:      jose.util.base64url.encode(csr)
      };
      return this._post(dir['new-authz'], payload);
    });
  }
}

module.exports = AcmeProtocol;
