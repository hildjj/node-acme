// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var Promise = require('bluebird');
var log = require('npmlog');

var utils  = require('./utils');
var acme   = require('./acme');
var config = require('./config');

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

/**
 * A Command Line Interface for the ACME protocol.
 */
class CLI {
  /**
   * Create a CLI.
   *
   * @param  {Array<string>=} args Arguments from the command line, uses
   *                               process.argv if none specified.
   * @return {CLI}                 Created object
   */
  constructor(args) {
    if (args == null) {
      args = process.argv.slice(2);
    }
    var yargs = require('yargs')
    .usage('Usage: $0 <command> [options]')
    .version(() => {
      return require('../package.json').version;
    })
    .options({
      verbose: {
        description: 'Verbose output (http, info, verbose)',
        count:       true,
        alias:       'v'
      },
      quiet: {
        desription: 'Turn off all logging',
        boolean:    true,
        alias:      'q'
      },
      config: {
        description: 'Configuration .json file',
        alias:       'c',
        string:      true
      },
      directoryURI: {
        description: 'API directory URI',
        alias:       'u',
        string:      true
      },
      terms: {
        description: 'Terms of Service URI (implies acceptance)',
        alias:       't',
        string:      true
      }
    })
    .demand(1, '<command> REQUIRED');

    this.argv = yargs.parse(args);
    this.cmd = this.argv._[0];
    log.level = _getLevel(this.argv);

    switch (this.cmd) {
      case 'register':
      case 'r':
      case 'reg':
        this._registerOpts(yargs);
        break;
      case 'init':
      case 'initialize':
      case 'i':
        this._initOpts(yargs);
        break;
      case 'update':
      case 'up':
      case 'u':
        this._updateOpts(yargs);
        break;
      default:
        yargs.showHelp();
        process.exit(64);
    }
  }

  _initOpts(yargs) {
    this.cmd = 'init';
    this.argv = utils.extend(this.argv,
      yargs.reset()
      .usage('$0 initialize [options]')
      .options({
        newkey: {
          description: 'Generate a new key',
          boolean:     true
        },
        bits: {
          description: 'The number of bits in the generated key',
          alias:       'b',
          'default':   1024
        },
        key: {
          description: 'Read a PEM-encoded key from the given file',
          requiresArg: true
        }
      })
      .help('help').alias('help', 'h')
      .argv);
  }

  _registerOpts(yargs) {
    this.cmd = 'reg';
    this.argv = utils.extend(this.argv,
      yargs.reset()
      .usage('$0 register [options]')
      .options({
        keyout: {
          description: 'File to output key into',
          requiresArg: true
        },
        contact: {
          description: 'Contact URI',
          type:        'array',
          requiresArg: true
        }
      })
      .help('help').alias('help', 'h')
      .argv);
  }

  _updateOpts(yargs) {
    this.cmd = 'update';
    this.argv = utils.extend(this.argv,
      yargs.reset()
      .usage('$0 update [options]')
      .options({
        registrationURI: {
          description: 'The URI of the created registration',
          string:      true,
          requiresArg: true,
          alias:       'r'
        },
        contact: {
          description: 'Contact URI',
          type:        'array',
          requiresArg: true
        },
        agreement: {
          description: 'Terms of service URI',
          string:      true,
          requiresArg: true,
          alias:       'a'
        }
      })
      .help('help').alias('help', 'h')
      .argv);
  }

  exec() {
    this.config = new config(this.argv.config, this.argv);
    this.config.read()
    .then(() => {
      log.verbose('cli', 'Arguments: %j', this.argv);
      switch (this.cmd) {
        case 'init':
          return this.generate();
        case 'reg':
          return this.register();
        case 'update':
          return this.update();
        default:
          return Promise.reject('Unknown command: ' + this.cmd);
      }
    })
    .then(() => {
      return this.config.write();
    }, er => {
      log.error('cli', er);
    });
  }

  generate() {
    if (this.argv.newkey) {
      return this.config.generatePrivateKey(this.argv.bits);
    } else if (this.config.key != null) {
      return this.config.importPrivateKey(this.argv.key);
    } else if (!this.config.hasKey()) {
      return Promise.resolve(this.config.privateKey);
    }
    return Promise.reject('No key specified');
  }

  register() {
    var protocol = new acme(this.config.privateKey, this.config.directoryURI);
    return protocol.newRegistration(this.config.contact,
                                    this.config.agreement)
    .then(reg => {
      this.config.registrationURI = acme.getLocation(reg);
      log.info('Registration URI:', this.config.registrationURI);
      if (!this.config.agreement) {
        var tos = acme.getLink(reg, 'terms-of-service');
        if (tos) {
          log.error('Terms of Service:', tos);
        }
      }
      return reg;
    });
  }

  update() {
    var protocol = new acme(this.config.privateKey, this.config.directoryURI);
    protocol.get(this.config.registrationURI)
    .then(reg => {
      reg.contact = this.config.contact;
      reg.agreement = this.config.agreement;
      return protocol.updateRegistration(this.config.registrationURI, reg);
    });
  }
}

module.exports = CLI;
