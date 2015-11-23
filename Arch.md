Architecture for node-acme
==========================

The `node-acme` package is intended to provide a generic node.js library for
doing ACME operations, and to provide a simple command-line tool for scripting these operations.

## Goals

* Simplicity / modularity
* Scriptability
* Run as root only when necessary


## Process model

Phases: init -> reg -> authz <-> cert 
(The "authz <-> cert" is double-headed because we might want to do the reverse

1. Init - one step
  * Set server URI
  * Set account key pair (generate or import)
  * Corresponds to ctor on ACME client object
2. Reg
  2.1. Create
  2.2. View
  2.3. Update (incl. Agree to ToS)
3. Authz
  3.1. Get challenges
  3.2. Select challenge
  3.3. Run validation server (http, tls, dns)
  3.4. Respond to challenges
  3.5. Await validation
4. Cert
  4.1. Issue
  4.2. Revoke


## CLI Mock-up

```
# All commands support -f flag to set state file name
> acme init [--newkey | --key $PEM] $URL

> acme reg init [--contact $ADDR]
> acme reg show
> acme reg update [--email $ADDR] [--agree $URL]

# Requests a new authz
# Chooses a challenge according to the presented order
# Prints the selected challenge to STDOUT
> acme authz init [--type http-01,tls-sni-01,dns-01] $NAME
> acme authz serve $NAME <challenge.json
# ^^^ Only part that needs root, if at all
# ^^^ Would be nice if this could run without overall ACME state
> acme authz respond <challenge.json
# XXX Still need a clear "Give me the file to provision" flavor

> acme cert init [--newkey --keyout $PEM | --key $PEM] --domain $NAME ...
> acme cert fetch --url $URL
> acme cert revoke --cert $PEM

# Notionally...
> acme init --newkey http://example.com/acme/directory
> acme reg init && acme reg update $(acme reg show | grep tos | cut -f2)
> acme authz init $NAME | acme authz serve $NAME | acme authz respond
> acme cert init --key $PEM --domain $NAME | acme cert fetch >$CERT
```


## API mock-up

```
function ACMEClient(url, key) {
    // Store directory URL
    // Lookup metadata from directory
    // Generate or store key
}

ACMEClient.prototype = {
    newRegistration: function(contacts) { return Promise<regObject>; }
    updateRegistration: function(regObj) { return Promise<regObject>; }
    
    newAuthorization: function(name) { return Promise<authzObject>; }
    validationServer: function(name, challenge) { return serverObject; }
    respondToChallenge: function(challenge) { return Promise<challengeObject>; }
    awaitValidation: function(authzObject) { return Promise<authzObject>; }
    
    newCertificate: function(keyPair, names) { return Promise<URL>; }
    awaitIssuance: function(URL) { return Promise<cert>; }
    
    revokeCertificate: function(cert) { return Promise<>; }
};
```



