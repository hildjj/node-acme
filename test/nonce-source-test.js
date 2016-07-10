'use strict';

const assert = require('chai').assert;
const nonceSource  = require('../lib/nonce-source');

describe('nonce-source', function() {
  it('rejects bad nonces', function() {
    let src = new nonceSource();

    let x = src.get();
    assert.isTrue(src.use(x));
    assert.isFalse(src.use(x));

    assert.isFalse(src.use('fnord'));
    assert.isFalse(src.use('2.3'));
  });

  it('ages off nonces when too many have been used', function() {
    let start = 42;
    let bufferSize = 10;
    let src = new nonceSource(start, bufferSize);

    let old = src.get();
    for (let i = 0; i < bufferSize + 1; i += 1) {
      assert.isTrue(src.use(src.get()));
    }

    assert.isFalse(src.use(old));
  });
});
