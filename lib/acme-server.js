'use strict';

let uuid = require('node-uuid');
let CSR = require('./CSR');
let TransportServer = require('./transport-server');

const DIRECTORY_TEMPLATE = {
  'directory': '/directory',
  'new-reg':   '/new-reg'
};

// * Class per object type
// * Each object has static type() method
// * Each object has an ID field.
//  * For registrations, this is thumbprint of the acct key
// * Format of URLs is $BASE/$TYPE/$ID
//
// * Class for DB
// * get(type, id)
// * put(obj)

function select(obj, fields) {
  let out = {};
  for (field of fields) {
    if (obj[field]) {
      out[field] = obj[field];
    }
  }
  return out;
}

class Registration {
  constructor(id, jwk, contacts) {
    this.id = id;
    this.status = 'good';
    this.key = jwk;
    this.contacts = contacts;
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
  constructor(server) {
    this.id = uuid.v2();
    this.status = 'pending';
    this.url = server.makeURL(this);
  }

  type() {
    return Application.type;
  }

  marshal() {
    return {
      key:       this.key.toJSON(),
      status:    this.status,
      contact:   this.contact,
      agreement: this.agreement
    };
  }
}

Application.type = 'app';
Application.publicFields = [
  'key',
  'status',
  'contact',
  'agreement'
];

/*
class Authorization {};
class Challenge {};
class Certificate {};
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
      maxValiditySeconds:   options.maxValiditySeconds,
      allowedExtensions:    options.allowedExtensions,
      scopedAuthorizations: options.scopedAuthorizations,
      requireOOB:           options.requireOOB
    };

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
    this.app.get(DIRECTORY_TEMPLATE['directory'], (req, res) => this.directory(req, res));
    this.app.post(DIRECTORY_TEMPLATE['new-reg'], (req, res) => this.newReg(req, res));
    this.app.post('/reg/:id', (req, res) => this.updateReg(req, res));
    this.app.post(DIRECTORY_TEMPLATE['new-app'], (req, res) => this.newApp(req, res));
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
  }

  // POST request handlers

  makeURL(obj) {
    let type = obj.type();
    let id = obj.id;
    return `${this.baseURL}/${type}/${id}`;
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
    } else if (req.payload.agreement) {
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
    let reg = this.db.get(Registration.type, req.thumbprint);
    if (!reg) {
      res.status(401);
      res.send(problem('unauthorized', 'Unknown account key'));
      return;
    }

    // Create a stub application
    let app = new Application(this);
    let scope = (this.policy.scopedAuthorizations)? app.url : undefined;

    // Parse the request elements, determine if it's acceptable
    try {
      let csr = new CSR(req.payload.csr);
      let notBefore = new Date(req.payload.notBefore);
      let notAfter = new Date(req.payload.notAfter);

      if (isNaN(notBefore.getTime())) {
        throw new Error('Invalid notBefore format');
      }
      if (isNaN(notAfter.getTime())) {
        throw new Error('Invalid notAfter format');
      }

      // This will throw with details unless it's OK
      csr.checkForDV(this.policy.allowedExtensions, this.policy.allowedAlgorithms);

      app.csr = req.payload.csr;
      app.notBefore = req.payload.notBefore;
      app.notAfter = req.payload.notAfter;
    } catch (e) {
      res.status(400);
      res.send(problem('unauthorized', 'Invalid application request', e.message));
      return;
    }

    // Assemble authorization requirements
    let requirements = [];
    for (let name of app.csr.names) {
      let authz = this.db.authzFor(req.thumbprint, name);
      if (!authz) {
        authz = new Authorization(req.thumbprint, name, scope);
      }
      this.db.put(authz);
      requirements.push(authz.asRequirement());
    }

    // TODO: Set OOB if required by policy

    // Return the application
    res.status(201);
    res.set('location', app.url);
    res.send(app.marshal());
  }
}

module.exports = ACMEServer;
