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

process.on('uncaughtException', function(err) {
  log.error('global', 'Uncaught Exception', err);
  process.exit(1);
});

process.on('unhandledRejection', function(reason, p) {
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

function CLI(args) {
  if (args == null) {
    args = process.argv.slice(2);
  }
  var yargs = require('yargs')
  .usage('Usage: $0 <command> [options]')
  .version(function() {
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
    uri: {
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
        .help('help')
        .alias('help', 'h')
        .argv);
      break;
    case 'init':
    case 'initialize':
    case 'i':
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
        .help('help')
        .alias('help', 'h')
        .argv);
      break;
    default:
      yargs.showHelp();
      process.exit(64);
  }
}

CLI.prototype.exec = function exec() {
  log.verbose('cli', 'Arguments: %j', this.argv);
  this.config = new config(this.argv.config, this.argv);
  this.config.read()
  .then(() => {
    switch (this.cmd) {
      case 'init':
        return this.generate();
      case 'reg':
        var protocol = new acme(this.config.privateKey, this.config.uri);
        return protocol.newRegistration(this.config.contact,
                                        this.config.agreement);
      default:
        return Promise.reject('Unknown command: ' + this.cmd);
    }
  })
  .then(() => {
    return this.config.write();
  }, function(er) {
    log.error('cli', er);
  });
};

CLI.prototype.generate = function generate() {
  if (this.argv.newkey) {
    return this.config.generatePrivateKey(this.argv.bits);
  } else if (this.config.key != null) {
    return this.config.importPrivateKey(this.argv.key);
  } else if (!this.config.hasKey()) {
    return Promise.resolve(this.config.privateKey);
  }
  return Promise.reject('No key specified');
};

module.exports = CLI;
