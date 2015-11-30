// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var rp  = require('request-promise');
var bb  = require('bluebird');
var log = require('npmlog');
var fs  = bb.promisifyAll(require('fs'));

var crypto = require('./crypto-utils');
var utils = require('./utils');

var SAVE_FIELDS = ['account', 'uri', 'contact', 'terms'];
var DEFAULTS = {
  uri:  'https://acme-v01.api.letsencrypt.org/directory',
  bits: 1024
};

require('request-debug')(rp, function(type, data, r) {
  // TODO: undo the JOSE and show the payload in the request.
  log.http('acme', '%j: %j', type, data);
});

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

function ACME(opts) {
  this.opts = opts || {};
}

ACME.prototype.init = function init() {
  var self = this;
  return utils.readJSON(self.opts.config)
  .then(function(json) {
    self.opts = utils.extend(DEFAULTS, json, self.opts);
  }, function(er) {
    log.warn('acme', 'Error reading file: %j', self.opts.config);
    self.opts = utils.extend(DEFAULTS, self.opts);
  })
  .then(function() {
    if (!self.opts.uri) {
      return bb.reject(new Error('No base URI specified'));
    }
    return rp.get({
      uri:  self.opts.uri,
      json: true
    });
  })
  .then(function(dir) {
    self.dir = dir;
  })
  .return(self);
};

ACME.prototype.save = function save() {
  var s = utils.extract(SAVE_FIELDS, this.opts);
  if (this.opts.config == null) {
    return bb.resolve(s);
  }
  return utils.writeJSON(this.opts.config, s);
};

ACME.prototype._post = function _post(uri, body) {
  if (!this.opts.account) {
    throw new Error('Invalid state, no account keypair');
  }
  var payload = JSON.stringify(body, null, 2);
  var jws = crypto.generateSignature(this.opts.account, new Buffer(payload));
  return rp.post({
    uri:                     uri,
    json:                    true,
    body:                    jws,
    resolveWithFullResponse: true
  }).then(function(resp) {
    return {
      body:  resp.body,
      links: _parseLink(resp.headers.link)
    };
  });
};

ACME.prototype.generateKeypair = function generateKeypair(bits) {
  var self = this;
  if (bits == null) {
    bits = self.opts.bits;
  }
  return crypto.generateKeyPair(bits).then(function(kp) {
    self.opts.account = kp;
    return self.save();
  });
};

ACME.prototype.importKey = function importKey(filename) {
  var self = this;
  return fs.readFileAsync(filename, 'utf8').then(function(s) {
    self.opts.account = crypto.importPemPrivateKey(s);
    return self.save();
  });
};

ACME.prototype.hasKey = function hasKey() {
  return (this.opts.account !== null);
};

ACME.prototype.register = function register() {
  var self = this;
  if (!self.dir) {
    throw new Error('Must wait for init to finish before calling');
  }
  if (!self.opts.contact || (self.opts.contact.length === 0)) {
    throw new Error('At least one contact is required');
  }
  var payload = {
    resource: 'new-reg',
    contact:  self.opts.contact
  };
  if (self.opts.terms) {
    payload.agreement = this.opts.terms;
  }
  return self._post(self.dir['new-reg'], payload)
  .then(function(res) {
    var tos = res.links['terms-of-service'];

    // No need to agree to terms?
    if (!tos || (self.opts.terms === tos)) {
      return res;
    }
    return rp.get(tos)
    .then(function(res2) {
      console.log(res2 + '\n');

      // TODO: fire event?  This seems too tightly bound to implementation.
      return utils.prompt('Do you accept the Terms of Service', ['y', 'N']);
    })
    .then(function(ch) {
      if (ch !== 'y') {
        return bb.reject(new Error('ToS not accepted'));
      }
      self.opts.terms = tos;
      return self.register();
    });
  });
};

module.exports = ACME;
