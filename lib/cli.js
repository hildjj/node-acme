// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var Promise   = require('bluebird');
var log       = require('npmlog');
var commander = require('commander');

var acme   = require('./acme');
var config = require('./config');
var pkg    = require('../package.json');

process.on('uncaughtException', err => {
  log.error('global', 'Uncaught Exception', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, p) => {
  log.error('global', 'Unhandled Rejection at: Promise %j, %j', p, reason);
  process.exit(1);
});

function _getLevel(argv) {
  if (argv.quiet) {
    return 'error';
  }
  switch(argv.verbose) {
    case 0:  return 'warn';
    case 1:  return 'http';
    case 2:  return 'info';
    case 3:  return 'verbose';
    default: return 'silly';
  }
}

function _gather(val, cur) {
  cur.push(val);
  return cur;
}

/**
 * A Command Line Interface for the ACME protocol.
 */
class CLI {
  /**
   * Create a CLI.
   *
   * @param  {Array<string>=} args Arguments from the command line, uses
   *                               process.argv if none specified.
   *                               Note: if used, pass in two unused parameters
   *                               at the beginning of the array, to match
   *                               process.argv.
   * @return {CLI}                 Created object
   */
  constructor() {
    this.cmd = null;
    this.config = new config();
  }

  exec(args) {
    // Reset the command line each time
    var program = new commander.Command();
    program
      .version(pkg.version)
      .usage('<command> [options]')
      .allowUnknownOption(false)
      .option('-v, --verbose', 'verbose output (http, info, verbose)', (val, cur) => {
        log.level = _getLevel(++cur);
        return cur;
      }, 0)
      .option('-q, --quiet', 'turn off all logging', () => log.level = 'error')
      .option('-f, --config <file.json>', 'configuration .json file',
              (val, cur) => cur.then(() => this.config.read(val)),
              Promise.resolve(null))
      .option('-d, --directory <URI>', 'API directory URI', uri => {
        this.config.directoryURI = uri;
      });

    var _config_then = (opts, next) => {
      return (this.cmd = program.config.then(() => {
        this.config.add(opts);
        log.verbose('cli', 'Config: %j', this.config.opts);
        return next();
      }));
    };

    program
      .command('init')
      .alias('i')
      .description('Initialize the ACME system with a private key')
      .option('-n, --newkey [bits]',
              'generate a new key with the given bits (default: 1024)',
              val => parseInt(val))
      .option('-k, --key <file.pem>',
              'read a PEM-encoded key from the given file')
      .action(opts => _config_then(opts, () => this.generate()));

    program
      .command('register')
      .alias('r')
      .description('register for an ACME account')
      .option('-o, --keyout <file.pem>', 'file to output key into')
      .option('-c, --contact <URI>', 'contact URI', _gather, [])
      .option('-a, --agreement <URI>', 'accept this Terms-of-Service URI')
      .action(opts => _config_then(opts, () => this.register()));

    program
      .command('update [reg_uri]')
      .alias('u')
      .description('update a created registration')
      .option('-c, --contact <URI>', 'contact URI', _gather, [])
      .option('-a, --agreement <URI>', 'accept this Terms-of-Service URI')
      .action((uri, opts) => _config_then(opts, () => this.update(uri)));

    program
      .command('auth <domain>')
      .alias('a')
      .description('authorize a domain')
      .action((domain, opts) => _config_then(opts, () => this.authz(domain)));

    program.parse(args || process.argv);
    if (this.cmd) {
      return this.cmd.then(() => this.config.write());
    }
    return Promise.reject(new Error('Invalid command'));
  }

  _proto() {
    return new acme(this.config.privateKey, this.config.directoryURI);
  }

  generate() {
    if (this.config.opts.newkey != null) {
      var bits = (typeof(this.config.opts.newkey) === 'number') ?
        this.config.opts.newkey : 1024;
      return this.config.generatePrivateKey(bits);
    } else if (this.config.key != null) {
      return this.config.importPrivateKey(this.config.key);
    } else if (this.config.hasKey()) {
      return Promise.resolve(this.config.privateKey);
    }
    return Promise.reject('No key specified');
  }

  register() {
    return this._proto()
    .newRegistration(this.config.contact, this.config.agreement)
    .then(reg => {
      this.config.registrationURI = acme.getLocation(reg);
      log.info('cli', 'Registration URI: %j', this.config.registrationURI);
      if (!this.config.agreement) {
        var tos = acme.getLink(reg, 'terms-of-service');
        if (tos) {
          log.error('cli', 'Terms of Service:\n', tos);
        }
      }
      return reg;
    });
  }

  update(uri) {
    var protocol = this._proto();
    uri = uri || this.config.registrationURI;
    if (!uri) {
      return Promise.reject(new TypeError('No registration URI'));
    }
    return protocol.get(uri)
    .then(reg => {
      reg.contact = this.config.contact;
      reg.agreement = this.config.agreement;
      return protocol.updateRegistration(uri, reg);
    });
  }

  authz(domain) {
    return this._proto()
    .newAuthorization(domain);
  }
}

module.exports = CLI;
