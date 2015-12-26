// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var log     = require('npmlog');
var Promise = require('bluebird');
var fs      = Promise.promisifyAll(require('fs'));
var crypto  = require('./crypto-utils');
var utils   = require('./utils');

const SAVE_FIELDS = [
  'agreement',
  'contact',
  'directoryURI',
  'domain',
  'privateKey',
  'registrationURI'
];
const DEFAULTS = {
  bits: 1024
};

/**
 * Configuration file for ACME.
 */
class AcmeConfig {
  /**
   * Create a config, with the given filename.  Make sure to call read, and
   * wait for its promise before using any of the other methods!
   *
   * @return {AcmeConfig}      Config manager
   */
  constructor() {
    this.opts = {};
    this.filename = null;
  }

  /**
   * Read the file.  Safe to call with a non-existant file or null.  The
   * last filename read is held on to in order to be the default for write.
   *
   * @param {string=} filename The name of the file to manage
   * @return {Promise<object>} Promise for the values read
   */
  read(filename) {
    log.verbose('config', 'reading file: %j', filename);
    this.filename = filename; // just save the last filename

    return utils.readJSON(this.filename)
    .then(json => this.add(json));
  }

  /**
   * Write the file.
   *
   * @return {Promise<object>} Promise for the object that was written
   */
  write() {
    var s = utils.extract(SAVE_FIELDS, this.opts);
    if (!this.filename) {
      log.verbose('config', 'no filename, no write');
      return Promise.resolve(s);
    }
    log.verbose('config', 'writing file: %j', this.filename);
    return utils.writeJSON(this.filename, s);
  }

  add(obj) {
    // store anything; the non-canonical stuff will be stripped out later
    this.opts = utils.extend(this.opts, utils.filter(obj, (k, v) => {
      return obj.hasOwnProperty(k) &&
              ((SAVE_FIELDS.indexOf(k) >= 0) ||
                ((k[0] !== '_') && (typeof(v) !== 'object')));
    }));
    return this.opts;
  }

  /**
   * Import a private key from a PEM file. Saves the config file on success.
   *
   * @param  {string} filename File to read
   * @return {Promise<jose.JWK.BaseKey>} Fulfilled with key
   */
  importPrivateKey(filename) {
    return fs.readFileAsync(filename, 'utf8')
    .then((s) => {
      return crypto.importPemPrivateKey(s);
    })
    .then((k) => {
      this.opts.privateKey = k;
      return this.write();
    });
  }

  /**
   * Generate a new private key.  Saves the config file on success.
   *
   * @param  {number=} bits number of bits in the key.  Defaults to 1024.
   * @return {Promise<jose.JWK.BaseKey>} Fulfilled with key
   */
  generatePrivateKey(bits) {
    return crypto.generateKey(bits || DEFAULTS.bits)
    .then((kp) => {
      this.opts.privateKey = kp;
      return this.write().return(kp);
    });
  }

  hasKey() {
    return (this.opts.privateKey != null);
  }
}

SAVE_FIELDS.forEach(f => {
  Object.defineProperty(AcmeConfig.prototype, f, {
    // NOTE: no fat arrow here!  It would rebind `this`.
    get: function()  { return this.opts[f]; },
    set: function(u) { this.opts[f] = u; }
  });
});

module.exports = AcmeConfig;
