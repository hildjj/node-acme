'use strict';

var Promise = require('bluebird');
var fs      = Promise.promisifyAll(require('fs'));
var crypto  = require('./crypto-utils');
var utils   = require('./utils');

var SAVE_FIELDS = ['privateKey', 'uri', 'contact', 'agreement'];
var DEFAULTS = {
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
   * @param  {string} filename The name of the file to manage
   * @param  {object=} override Override the file read with these values
   * @return {AcmeConfig}      Config manager
   */
  constructor(filename, override) {
    this.filename = filename;
    this.opts = {};
    this.override = utils.extract(SAVE_FIELDS, override);
  }

  /**
   * Read the file.  Safe to call with a non-existant file or null.
   *
   * @return {Promise<object>} Promise for the values read
   */
  read() {
    return utils.readJSON(this.filename)
    .then((json) => {
      this.opts = utils.extend(json, this.override);
      return this.opts;
    });
  }

  /**
   * Write the file.
   *
   * @return {Promise<object>} Promise for the object that was written
   */
  write() {
    var s = utils.extract(SAVE_FIELDS, this.opts);
    if (!this.filename) {
      return Promise.resolve(s);
    }
    return utils.writeJSON(this.filename, s);
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
    return (this.opts.privateKey !== null);
  }
}

SAVE_FIELDS.forEach(function(f) {
  Object.defineProperty(AcmeConfig.prototype, f, {
    get: function() { return this.opts[f]; },
    set: function(u) { this.opts[f] = u; }
  });
});

module.exports = AcmeConfig;
