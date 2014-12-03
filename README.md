ndb_users
=========

__Pre-release/in development!__

> Simple user accounts for Google App Engine projects.

`ndb_users` is a Python module designed for use on Google App Engine where Google Accounts or OpenID cannot be used.

Build on Google's `ndb`/Datastore and `webapp2`, `ndb_users` aims to simply replace Google's User API:

```python
from ndb_users import users
```

More at [live ndb_users documentation](https://ndb-users.appspot.com/documentation).

## Features

##### Ready "Out of the box"
Includes styled log in, log out, and more pages for your web apps.

##### Extendable
Easily add additional attributes to the built-in `User` class (sublcass of `ndb.Model`).

##### Verify email addresses
Enforce email verification of new user accounts. Optional.

##### Forget the headache
Users can recover forgotten passwords via email links.

##### Hashed and salted
Passwords and hashed (using sha256) using a unique salt.

##### JSON or web `<form>`
Log users in via JSON request or submittable form.

##### Customizable
Customize the login or logout pages, messages, and more.

## Getting started

Copy `ndb_users` folder into your project.

In your project's `app.yaml`, add the following URL handlers in the `handlers` section:

```yaml
handlers:
- url: /_login/assets
  static_dir: ndb_users/assets
- url: /_login(.*)
  script: ndb_users.login.app
  secure: always
- url: /_ah/mail/.+
  script: ndb_users.mail.app
  login: admin
```

In your project's `app.yaml`, add `webapp2` under `libraries`, if not already present:

```yaml
libraries:
- name: webapp2
  version: latest
```

In your project's `app.yaml`, add `mail` under `inbound_services`:

```yaml
inbound_services:
- mail
```

## Usage

In your `webapp2` request handler(s) simply import the `users` module from `ndb_users` using:

```python
from ndb_users import users
```

#####Getting the logged in user, if any

Inside a `webapp2` request handler, it's easy to get a `User` object for the currently logged in user (if any):

```python
user = users.get_current_user()
```

#####Generating log in or log out links

```python
login_url = users.create_login_url()
logout_url = users.create_logout_url()
```

More documentation available: https://ndb-users.appspot.com/documentation

## Todo

In no specific order. See issue tracker for more.
 - Complete JSON API
 - Integrate a default link "back" or "home"
 - Check for bounced/rejected emails
 - Create styled (HTML) emails.
 - NDB_USERS_SITE_NICKNAME
 - NDB_USERS_DEFAULT_CONTINUE_URI
