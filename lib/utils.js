// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

/**
 * Utilities
 * @module utils
 */
module.exports = {

  /**
   * Translate to Base64url
   *
   * @param  {String} x Base64
   * @return {String}   Base64url
   */
  fromStandardB64: function(x) {
    return x.replace(/[+]/g, '-').replace(/\//g, '_').replace(/=/g,'');
  },

  /**
   * Translate from Base64url
   * @param  {String} x Base64url
   * @return {String}   Base64
   */
  toStandardB64: function(x) {
    var b64 = x.replace(/-/g, '+').replace(/_/g, '/').replace(/=/g, '');

    switch (b64.length % 4) {
      case 2: b64 += '=='; break;
      case 3: b64 += '=';  break;
    }

    return b64;
  },

  /**
   * Base64url encode a buffer
   * @param  {Buffer} buffer Encode these bytes
   * @return {String}        Base64url
   */
  b64enc: function(buffer) {
    return this.fromStandardB64(buffer.toString('base64'));
  },

  /**
   * Base64url decode a string
   *
   * @param  {Base64} str Base64url
   * @return {Buffer}     Bytes decoded
   */
  b64dec: function(str) {
    return new Buffer(str, 'base64');
  },

  /**
   * Is the string valid Base64url?
   * @param  {String} x Check this
   * @return {Boolean}  true if valid
   */
  isB64String: function(x) {
    return (typeof(x) === 'string') && !x.match(/[^a-zA-Z0-9_-]/);
  },

  /**
   * Are the given fields set on the given object?
   * @param  {Array} fields Fields to check
   * @param  {Object} object check this
   * @return {Boolean}       Are all of the fields there?
   */
  fieldsPresent: function(fields, object) {
    if (!Array.isArray(fields) || !object || (typeof(object) !== 'object')) {
      return false;
    }
    for (var i in fields) {
      if (!object.hasOwnProperty(fields[i])) {
        return false;
      }
    }
    return true;
  },

  /**
   * Is the given object a valid JSON Web Key (JWK)?
   *
   * @param  {Object} jwk The key to check
   * @return {Boolean}    true if valid
   */
  validJWK: function(jwk) {
    if (!this.fieldsPresent(['kty'], jwk) || ('d' in jwk)) {
      return false;
    }
    switch (jwk.kty) {
      case 'RSA':
        return this.isB64String(jwk.n) && this.isB64String(jwk.e);
      case 'EC':
        return (typeof(jwk.crv) === 'string') &&
          this.isB64String(jwk.x) &&
          this.isB64String(jwk.y);
    }
    return false;
  },

  /**
   * Is the signature valid?
   *
   * @param  {Object} sig Object to check
   * @return {Boolean}    true if valid
   */
  validSignature: function(sig) {
    if (!this.fieldsPresent(['alg', 'nonce', 'sig', 'jwk'], sig)) {
      return false;
    }
    return (typeof(sig.alg) === 'string') &&
      this.isB64String(sig.nonce) &&
      this.isB64String(sig.sig) &&
      this.validJWK(sig.jwk);
  },

  /**
   * A simple, non-standard fingerprint for a JWK,
   * just so that we don't have to store objects
   *
   * @param  {Object} jwk Key
   * @return {String}     [description]
   */
  keyFingerprint: function(jwk) {
    if (!this.fieldsPresent(['kty'], jwk)) {
      throw new Error('Invalid key');
    }
    switch (jwk.kty) {
      case 'RSA': return '' + jwk.n;
      case 'EC':  return '' + jwk.crv + '|' + jwk.x + '|' + jwk.y;
    }
    throw new Error('Unrecognized key type');
  }
};
