'use strict';

function promisify(supertest) {
  return new Promise((resolve, reject) => {
    supertest.end((err, res) => {
      if (err) {
        reject(err);
      }
      resolve(res);
    });
  });
}

module.exports = promisify;
