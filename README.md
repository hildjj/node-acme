node-acme
=========

Reference implementation of [ACME](https://ietf-wg-acme.github.io/acme/).

[![Build Status](https://travis-ci.org/hildjj/node-acme.svg?branch=master)](https://travis-ci.org/hildjj/node-acme)
[![Coverage Status](https://coveralls.io/repos/hildjj/node-acme/badge.svg?branch=master&service=github)](https://coveralls.io/github/hildjj/node-acme?branch=master)

## Goals

This implementation is intended more as a tool for learning about ACME and
working on its development than something to be used in production.

* Demonstrate how the protocol works in as minimal as a way as possible
* Provide a platform to show how possible changes to the protocol impact an
  implementation
* 100% test and documentation coverage
* Non-goal: Having a clean command line interface or API


## Architecture

Internally, this module has a layered structure reflecting the layering of ACME.

* `jose` and `nonce-source` modules that provide some basic services
* `transport-client` and `transport-server` address the [transport layer
  requirements](https://ietf-wg-acme.github.io/acme/#rfc.section.5) of the
  protocol, e.g., message signing and verification.
* `*-validation` modules capture the various ways to [validate possession of an
  identifier](https://ietf-wg-acme.github.io/acme/#rfc.section.7)
* `acme-client` and `acme-server` provide the logic for the [application-level
  issuance flow](https://ietf-wg-acme.github.io/acme/#rfc.section.6)

```
 acme-server                       acme-client
      |   |                         |   |
      |   +--------------+----------+   |
      |                  |              |
transport-server   *-validation   transport-client
      |   |              |              |
      |   +--------------+--------------+
      |                  |
 nonce-source           jose
```

