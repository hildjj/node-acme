'use strict';

const uuid = require('node-uuid');
const pki = require('./pki');
const TransportServer = require('./transport-server');

const DIRECTORY_TEMPLATE = {
  'directory': '/directory',
  'new-reg':   '/new-reg',
  'new-app':   '/new-app'
};

// * Class per object type
// * Each object has static type() method
// * Each object has an ID field.
//  * For registrations, this is thumbprint of the acct key
// * Format of URLs is $BASE/$TYPE/$ID

function select(obj, fields) {
  let out = {};
  for (let field of fields) {
    if (obj[field]) {
      out[field] = obj[field];
    }
  }
  return out;
}

class Registration {
  constructor(id, jwk, contact) {
    this.id = id;
    this.status = 'good';
    this.key = jwk;
    this.contact = contact;
  }

  type() {
    return Registration.type;
  }

  marshal() {
    return select(this, Registration.publicFields);
  }
}

Registration.type = 'reg';
Registration.publicFields = [
  'key',
  'status',
  'contact',
  'agreement'
];

class Application {
  constructor(server, thumbprint) {
    this.server = server;
    this.id = uuid.v4();
    this.status = 'pending';
    this.url = server.makeURL(this);
    this.thumbprint = thumbprint;
    this.requirements = [];
  }

  type() {
    return Application.type;
  }

  issueIfReady() {
    let unfulfilled = this.requirements.filter(req => (req.status !== 'valid'));
    if (unfulfilled.length === 0) {
      this.status = 'valid'; // XXX: Should probably move this to updateAppsFor()
      return this.server.CA.issue(/* application */)
        .then(cert => {
          this.certificate = cert.url;
          return this;
        });
    }
    return Promise.resolve(this);
  }

  marshal() {
    return select(this, Application.publicFields);
  }
}

Application.type = 'app';
Application.publicFields = [
  'status',
  'expires',
  'csr',
  'notBefore',
  'notAfter',
  'requirements',
  'certificate'
];

class Authorization {
  constructor(server, thumbprint, name, scope) {
    this.id = uuid.v4();
    this.status = 'pending';
    this.url = server.makeURL(this);
    this.thumbprint = thumbprint;
    this.identifier = {
      type:  'dns',
      value: name
    };
    this.scope = scope;

    let offset = server.policy.authzExpirySeconds * 1000;
    let expires = new Date();
    expires.setTime(expires.getTime() + offset);
    this.expires = expires;

    this.challengeObj = [];
    for (let challengeType of server.challengeTypes) {
      this.challengeObj.push(new challengeType());
    }

    this.update();
  }

  update() {
    this.challenges = this.challengeObj.map((x, i) => {
      let obj = x.toJSON();
      obj.url = this.url + '/' + i.toString();
      return obj;
    });

    let now = new Date();
    let validChallenges = this.challenges.filter(x => (x.status === 'valid'));
    if (this.expires < now) {
      this.status = 'invalid';
    } else if (validChallenges.length > 0) {
      this.status = 'valid';
    }
  }

  type() {
    return Authorization.type;
  }

  marshal() {
    this.update();
    return select(this, Authorization.publicFields);
  }

  asRequirement() {
    return {
      type:   'authorization',
      status: this.status,
      url:    this.url
    };
  }
}

Authorization.type = 'authz';
Authorization.publicFields = [
  'identifier',
  'status',
  'expires',
  'scope',
  'challenges',
  'combinations'
];

/*
class Certificate {}
*/

class DB {
  constructor() {
    this.store = {};
  }

  put(obj) {
    let type = obj.type();
    if (!this.store[type]) {
      this.store[type] = {};
    }
    this.store[type][obj.id] = obj;
  }

  get(type, id) {
    if (!this.store[type]) {
      return null;
    }
    return this.store[type][id];
  }

  authzFor(thumbprint, name) {
    for (let key in this.store['authz']) {
      if (!this.store['authz'].hasOwnProperty(key)) {
        continue;
      }

      let authz = this.store['authz'][key];
      if ((authz.thumbprint === thumbprint) &&
          (authz.identifier.value === name)) {
        return authz;
      }
    }
    return null;
  }

  updateAppsFor(authz) {
    let dependencies = [];
    for (let key in this.store['app']) {
      if (!this.store['app'].hasOwnProperty(key)) {
        continue;
      }

      let app = this.store['app'][key];
      if (app.thumbprint !== authz.thumbprint) {
        continue;
      }

      app.requirements.map(req => {
        if (req.type === 'authorization' && req.url === authz.url) {
          req.status = authz.status;
        }
      });
      this.put(app);
      dependencies.push(app);
    }

    return Promise.all(dependencies.map(app => app.issueIfReady()));
  }
}

class CA {
  issue(/* application */) {
    // XXX: Stub
    return Promise.resolve({url: 'this-is-not-a-url'});
  }
}

function problem(type, title, description) {
  return {
    type:        'urn:ietf:params:acme:error:' + type,
    title:       title,
    description: description
  };
}

class ACMEServer {
  // Options:
  // * hostname
  // * port
  // * basePath
  constructor(options) {
    options = options || {};
    let host = options.host || 'localhost';
    let port = options.port || 80;
    let basePath = options.basePath || '';

    // Set policy preferences
    this.policy = {
      authzExpirySeconds:   options.authzExpirySeconds,
      maxValiditySeconds:   options.maxValiditySeconds,
      allowedExtensions:    options.allowedExtensions,
      scopedAuthorizations: options.scopedAuthorizations,
      requireOOB:           options.requireOOB,
      challenges:           {
        dns:    options.dnsChallenge,
        http:   options.httpChallenge,
        tlssni: options.tlssniChallenge,
        auto:   options.autoChallenge
      }
    };

    // Import challenges from caller preferences
    this.challengeTypes = [];
    for (let challengeType of options.challengeTypes) {
      if ((typeof(challengeType.prototype.update) !== 'function') ||
          (typeof(challengeType.prototype.toJSON) !== 'function')) {
        throw new Error('ChallengeType does not required methods');
      }

      this.challengeTypes.push(challengeType);
    }

    // Set up a CA
    // XXX: Stub
    this.CA = new CA();

    // Set the base URL, so we can construct others
    switch (port) {
      case 80:  this.baseURL = `http://${host}/${basePath}`; break;
      case 443: this.baseURL = `https://${host}/${basePath}`; break;
      default: this.baseURL = `http://${host}:${port}/${basePath}`; break;
    }

    // Set up a database
    this.db = new DB();

    // Initialize the directory object
    this._directory = {'meta': {}};
    for (let name in DIRECTORY_TEMPLATE) {
      if (DIRECTORY_TEMPLATE.hasOwnProperty(name)) {
        this._directory[name] = this.baseURL + DIRECTORY_TEMPLATE[name];
      }
    }

    // Create a transport-level server
    this.transport = new TransportServer();
    this.app.get('/:type/:id', (req, res) => this.fetch(req, res));
    this.app.get('/authz/:id/:index', (req, res) => this.fetchChallenge(req, res));
    this.app.get(DIRECTORY_TEMPLATE['directory'], (req, res) => this.directory(req, res));
    this.app.post(DIRECTORY_TEMPLATE['new-reg'], (req, res) => this.newReg(req, res));
    this.app.post('/reg/:id', (req, res) => this.updateReg(req, res));
    this.app.post(DIRECTORY_TEMPLATE['new-app'], (req, res) => this.newApp(req, res));
    this.app.post('/authz/:id/:index', (req, res) => this.updateAuthz(req, res));
    // TODO others
  }

  get app() {
    return this.transport.app;
  }

  get terms() {
    return this._directory.meta['terms-of-service'];
  }

  set terms(url) {
    this._directory.meta['terms-of-service'] = url;
  }

  // GET request handlers

  directory(req, res) {
    res.json(this._directory);
  }

  fetch(req, res) {
    let type = req.params.type;
    let id = req.params.id;

    // Attempt to fetch
    let status = 200;
    let body = this.db.get(type, id);
    if (body) {
      body = body.marshal();
    }

    // Overwrite with errors if necessary
    if (type === Registration.type) {
      status = 401;
      body = problem('unauthorized', 'GET requests not allowed for registrations');
    } else if (!body) {
      status = 404;
      body = '';
    }

    res.status(status);
    res.send(body);
    res.end();
  }

  fetchChallenge(req, res) {
    let authz = this.db.get(Authorization.type, req.params.id);
    let index = parseInt(req.params.index);
    if (!authz || isNaN(index) || !(index in authz.challenges)) {
      res.status(404);
      res.end();
      return;
    }

    authz.update();
    this.db.put(authz);

    res.status(200);
    res.send(authz.challenges[index]);
  }

  // POST request handlers

  makeURL(obj) {
    let type = obj.type();
    let id = obj.id;
    return `${this.baseURL}${type}/${id}`;
  }

  newReg(req, res) {
    let jwk = req.accountKey;
    let contact = req.payload.contact;
    let thumbprint = req.accountKeyThumbprint;

    // Check for existing registrations
    let existing = this.db.get(Registration.type, thumbprint);
    if (existing) {
      res.status(409);
      res.set('location', this.makeURL(existing));
      res.end();
      return;
    }

    // Store a new registration
    let reg = new Registration(thumbprint, jwk, contact);
    this.db.put(reg);
    res.status(201);
    res.set('location', this.makeURL(reg));
    if (this.terms) {
      res.links({'terms-of-service': this.terms});
    }
    res.send(reg.marshal());
  }

  updateReg(req, res) {
    // Check that account key is registered
    let thumbprint = req.accountKeyThumbprint;
    let reg = this.db.get(Registration.type, thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      return;
    }
    if (req.params.id !== thumbprint) {
      res.status(401);
      res.send(problem('unauthorized', 'Unauthorized account key'));
      return;
    }

    if (req.payload.contact) {
      reg.contact = req.payload.contact;
    }
    if (req.payload.agreement) {
      if (req.payload.agreement !== this.terms) {
        res.status(400);
        res.send(problem('malformed', 'Incorrect agreement URL'));
        return;
      }
      reg.agreement = req.payload.agreement;
    }
    this.db.put(reg);

    res.status(200);
    if (this.terms) {
      res.links({'terms-of-service': this.terms});
    }
    res.send(reg.marshal());
  }

  newApp(req, res) {
    // Check that account key is registered
    let thumbprint = req.accountKeyThumbprint;
    let reg = this.db.get(Registration.type, thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      return;
    }

    // Create a stub application
    let app = new Application(this, thumbprint);
    let scope = (this.policy.scopedAuthorizations)? app.url : undefined;

    // Parse the request elements, determine if it's acceptable
    let names;
    try {
      if (!req.payload.csr) {
        throw new Error('CSR must be provided');
      }

      let csr = pki.checkCSR(req.payload.csr, this.policy);
      if (csr.error) {
        throw new Error(csr.error);
      }
      names = csr.names;
      app.csr = req.payload.csr;

      if (req.payload.notBefore) {
        let notBefore = new Date(req.payload.notBefore);
        if (isNaN(notBefore.getTime())) {
          throw new Error('Invalid notBefore format');
        }
        app.notBefore = req.payload.notBefore;
      }

      if (req.payload.notAfter) {
        let notAfter = new Date(req.payload.notAfter);
        if (isNaN(notAfter.getTime())) {
          throw new Error('Invalid notAfter format');
        }
        app.notAfter = req.payload.notAfter;
      }
    } catch (e) {
      res.status(400);
      res.send(problem('malformed', 'Invalid new application', e.message));
      return;
    }

    // Assemble authorization requirements
    for (let name of names) {
      let authz = this.db.authzFor(thumbprint, name);
      if (!authz) {
        authz = new Authorization(this, thumbprint, name, scope);
      }
      this.db.put(authz);
      app.requirements.push(authz.asRequirement());
    }

    // TODO: Set OOB if required by policy

    // Return the application
    this.db.put(app);
    res.status(201);
    res.set('location', app.url);
    res.send(app.marshal());
  }

  updateAuthz(req, res) {
    // Check that the requested authorization and challenge exist
    let authz = this.db.get(Authorization.type, req.params.id);
    let index = parseInt(req.params.index);
    if (!authz || isNaN(index) || !(index in authz.challenges)) {
      res.status(404);
      res.end();
      return;
    }

    // Check that account key is registered and appropriate
    let thumbprint = req.accountKeyThumbprint;
    let reg = this.db.get(Registration.type, thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      res.end();
      return;
    }
    if (reg.id !== authz.thumbprint) {
      res.status(401);
      res.send(problem('unauthorized', 'Unauthorized account key'));
      res.end();
      return;
    }

    // Asynchronously update the challenge, the authorization, and any
    // applications that depend on the authorization.
    //
    // NB: It's nice for testing to have the response only go back after
    // everything is updated, since then you know that anything that's going to
    // be issued has been.  However, updates are slow, so we might want to go
    // async ultimately.
    authz.challengeObj[index].update(req.payload)
      .then(() => {
        authz.update();
      })
      .then(() => {
        this.db.updateAppsFor(authz);
      })
      .then(() => {
        res.status(200);
        res.send(authz.challenges[index]);
        res.end();
      });
  }
}

module.exports = ACMEServer;
