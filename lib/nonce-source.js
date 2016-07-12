'use strict';

const DEFAULT_START = 0x8af2;
const DEFAULT_BUFFER_SIZE = 10;

class Source {
  constructor(start, bufferSize) {
    start = start || DEFAULT_START;
    bufferSize = bufferSize || DEFAULT_BUFFER_SIZE;

    this.min = start;
    this.counter = start;
    this.used = new Array(bufferSize);
    for (let i = 0; i < this.used.length; i += 1) {
      this.used[i] = start;
    }
  }

  get() {
    this.counter += 1;
    return this.counter.toString();
  }

  use(nonce) {
    if (!nonce.match(/^[0-9]+$/)) {
      return false;
    }

    let value = parseInt(nonce);
    if ((value <= this.min) || (value > this.counter) ||
        (this.used.indexOf(value) > -1)) {
      return false;
    }

    this.min = this.used.shift();
    this.used.push(value);
    return true;
  }
}

module.exports = Source;
