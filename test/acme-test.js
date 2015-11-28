// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

var assert = require('chai').assert;
var acme   = require('../lib/acme');

describe('ACME protocol', function() {
  it('creates and initializes', function(done) {
    var a = new acme();
    a.init().then(function(b){
      assert.equal(a, b);
      done();
    });
  });
});
