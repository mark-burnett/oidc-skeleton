# OpenID Connect Skeleton
[![Build Status](https://travis-ci.org/mark-burnett/oauth-skeleton.svg?branch=master)](https://travis-ci.org/mark-burnett/oauth-skeleton)
[![Coverage Status](https://img.shields.io/coveralls/mark-burnett/oauth-skeleton.svg)](https://coveralls.io/r/mark-burnett/oauth-skeleton)

## Description

This repo is for exploring how to implement an OpenID Connect provider and
consumers using [oauthlib](https://github.com/idan/oauthlib).

The repo has several components:

- `s_auth` - the OpenID Connect Provider (web service)
- `s_client` - an OpenID Connect Relying Party (web service), which also stores
  some resources
- `s_resource` - a resource server (web service)
- `s_user` - an SDK for this pretend web app
- `s_common` - misc. code used by one or more of the above modules

To run tests:

    $ pip install tox
    $ tox
