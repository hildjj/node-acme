// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var bb = require('bluebird');

var utils  = require('./utils');
var acme   = require('./acme');

function CLI(args) {
  if (args == null) {
    args = process.argv.slice(2);
  }
  var yargs = require('yargs')
  .usage('Usage: $0 <command> [options]')
  .version(function() {
    return require('../package').version;
  })
  .options({
    verbose: {
      description: 'Verbose protocol output',
      boolean:     true,
      alias:       'v'
    },
    config: {
      description: 'Configuration .json file',
      alias:       'c',
      string:      true,
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
  var self = this;
  self.acme = new acme(self.argv);
  return self.acme.init()
  .then(function() {
    switch (self.cmd) {
      case 'init':
        return self.generate();
      case 'reg':
        return self.acme.register();
      default:
        return bb.reject('Unknown command: ' + self.cmd);
    }
  })
  .then(function() {
    return self.acme.save();
  });
};

CLI.prototype.generate = function generate() {
  if (this.argv.newkey) {
    return this.acme.generateKeypair(self.argv.bits);
  } else if (this.argv.key != null) {
    return this.acme.importKey(self.argv.key);
  } else if (!this.acme.hasKey()) {
    return bb.reject('No key specified');
  }
  return bb.resolve();
};

module.exports = CLI;
