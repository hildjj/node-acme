// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var rp = require('request-promise');

var crypto = require('./crypto-utils');

module.exports = {
  post: function(state, uri, body) {
    var payload = JSON.stringify(body, null, 2);
    var jws = crypto.generateSignature(state.account, new Buffer(payload));
    return rp.post({
      uri:                     uri,
      json:                    true,
      body:                    jws,
      resolveWithFullResponse: true
    }).then(function(resp) {
      return {
        body:  resp.body,
        links: module.exports.parseLink(resp.headers.link)
      };
    });
  },
  directory: function(state) {
    if (state.dir != null) {
      return state.dir;
    }
    state.dir = rp.get({
      uri:  state.uri,
      json: true
    });
    return state.dir;
  },
  register: function(state) {
    return module.exports.directory(state)
    .then(function(dir) {
      var payload = {
        resource: 'new-reg',
        contact:  [
          'mailto:cert-admin@example.com',
          'tel:+12025551212'
        ]
      };
      if (state.terms) {
        payload.agreement = state.terms;
      }
      return module.exports.post(state, dir['new-reg'], payload)
      .then(function(res) {
        if (state.terms || !res.links['terms-of-service']) {
          return res;
        }
        state.terms = res.links['terms-of-service'];
        rp.get(state.terms)
        .then(function(res) {
          console.log(res + '\n');
        });
      });
    });
  },
  parseLink: function(link) {
    // TODO: look for a library that parses *all* of RFC 5988, or at least
    // doesn't barf on anything valid.
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
  },
};
