'use strict';

let jose = require('node-jose');

// Implements ACME's additional requirements on JWS
// https://ietf-wg-acme.github.io/acme/#request-authentication

module.exports = {
  newkey: function() {
    return jose.JWK.createKeyStore().generate('EC', 'P-256');
  },

  sign: function(key, obj, header) {
    header.jwk = key.toJSON();

    if (!header.url || !header.url) {
      throw new Error('Header must provide nonce and url');
    }

    let payload = JSON.stringify(obj);
    let opts = {
      format: 'flattened',
      fields: header
    };
    return jose.JWS.createSign(opts, key)
      .update(payload)
      .final();
  },

  verify: function(jws) {
    return new Promise((res, rej) => {
      if (!jws.protected || !jws.payload || !jws.signature) {
        rej(new Error('Non-flattened JWS'));
      }

      let header = {};
      let headerBytes = jose.util.base64url.decode(jws.protected);
      let headerJSON = jose.util.utf8.encode(headerBytes);
      header = JSON.parse(headerJSON);

      if (!header.alg || !header.jwk || !header.nonce || !header.url) {
        rej(new Error('Missing field in protected header'));
      }

      res(jose.JWK.asKey(header.jwk));
    })
    .then(key2 => jose.JWS.createVerify(key2).verify(jws))
    .then(result => {
      result.payload = JSON.parse(result.payload);
      return result;
    });
    // TODO: Groom the return value?
  }
};
