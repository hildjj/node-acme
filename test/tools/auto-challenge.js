'use strict';

class AutoChallenge {
  constructor(name) {
    this.status = 'pending';
    this.token = Math.random().toString().substring(2);
  }

  update(response) {
    if (!response.type || (response.type !== AutoChallenge.type) ||
        !response.token || (response.token !== this.token)) {
      this.status = 'invalid';
    } else {
      this.status = 'valid';
    }

    return Promise.resolve();
  }

  toJSON() {
    return {
      type:   AutoChallenge.type,
      status: this.status,
      token:  this.token
    };
  }
}

AutoChallenge.type = 'auto';

module.exports = AutoChallenge;
