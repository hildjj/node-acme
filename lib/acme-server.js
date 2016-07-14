'use strict';

let TransportServer = require('./transport-server');

const TYPE_REGISTRATION  = 'reg';
//const TYPE_APPLICATION   = 'app';
//const TYPE_AUTHORIZATION = 'authz';
//const TYPE_CHALLENGE     = 'chall';
//const TYPE_CERTIFICATE   = 'cert';
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
    return {
      key:       this.key.toJSON(),
      status:    this.status,
      contact:   this.contact,
      agreement: this.agreement
    };
  }
}

Registration.type = TYPE_REGISTRATION;

/*
class Application {};
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

    let existing = this.db.get(Registration.type, thumbprint);
    if (existing) {
      res.status(409);
      res.set('location', this.makeURL(existing));
      res.end();
      return;
    }

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

}

module.exports = ACMEServer;
