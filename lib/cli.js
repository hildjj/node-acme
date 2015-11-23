// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var bb = require('bluebird');
var fs = bb.promisifyAll(require('fs'));

var crypto = require('./crypto-utils');
var utils  = require('./utils');
//var acme   = require('./acme');

module.exports = {
  save: function(argv) {
    var s = utils.extract(['account', 'uri', 'contact'], argv);
    if (argv.config == null) {
      return bb.resolve(s);
    }
    var ss = JSON.stringify(s, null, 2);
    return fs.writeFileAsync(argv.config, ss, 'utf-8').return(s);
  },
  initialize: function(argv) {
    return (function() {
      if (argv.newkey) {
        return crypto.generateKeyPair(argv.bits);
      } else if (argv.key != null) {
        return fs.readFileAsync(argv.key, 'utf8').then(function(s) {
          return crypto.importPemPrivateKey(s);
        });
      } else if (argv.account != null) {
        return bb.resolve(argv.account);
      }
      return bb.reject('No key specified');
    })().then(function(pk) {
      argv.account = pk;
      return module.exports.save(argv);
    });
  },
  register: function(argv) {
    console.log('REG!!', argv);
  },
  parse: function(args) {
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
          config:      true,
          alias:       'c'
        },
        uri: {
          description: 'API URI',
          default:     'https://example.com/v1/',
          alias:       'u',
          string:      true
        }
      })
      .demand(1, '<command> REQUIRED');

    var argv = yargs.parse(args);
    var cmd = argv._[0];
    switch (cmd) {
      case 'register':
      case 'r':
      case 'reg':
        utils.extend(argv,
          yargs
            .reset()
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
        module.exports.register(argv);
        break;
      case 'init':
      case 'initialize':
      case 'i':
        utils.extend(argv,
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
        module.exports.initialize(argv).catch(function(msg) {
          console.error('ERROR:', msg);
        });
        break;
      default:
        yargs.showHelp();
        process.exit(64);
    }
    console.log(argv);
  }
};
