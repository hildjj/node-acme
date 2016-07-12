// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

'use strict';

const assert          = require('chai').assert;
const jose            = require('../lib/jose');
const TransportClient = require('../lib/transport-client');
const TransportServer = require('../lib/transport-server');

const PORT = 4430;

describe('transport-level client/server integration', function() {
  it('performs a POST request with preflight', function(done) {
    let server = new TransportServer();

    let url = `http://localhost:${PORT}/foo`;
    let gotPOST = false;
    let query = {'foo': 'bar'};
    let result = {'bar': 2};

    server.app.locals.port = PORT;
    server.app.post('/foo', (req, res) => {
      gotPOST = true;
      assert.deepEqual(req.payload, query);
      res.json(result);
    });

    let httpServer;
    let p = new Promise(res => {
      httpServer = server.app.listen(PORT, () => res());
    });
    p.then(() => { return jose.newkey(); })
      .then(k => {
        let client = new TransportClient({accountKey: k});
        return client.post(url, query);
      })
      .then(body => {
        assert.isTrue(gotPOST);
        assert.deepEqual(body, result);
      })
      .then(() => {
        httpServer.close();
        done();
      })
      .catch(done);
  });
});
