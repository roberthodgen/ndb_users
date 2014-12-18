"""
The MIT License (MIT)

Copyright (c) 2014 Robert Hodgen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import webapp2

import hashlib

import random

import string

from google.appengine.ext import ndb

from datetime import datetime, timedelta

from google.appengine.api import app_identity

from ndb_users.config import *

from urllib import urlencode

from google.appengine.ext.webapp import template


def get_current_user():
  """ Returns a User object or None. """
  request = webapp2.get_request()
  cookie_value = request.cookies.get(NDB_USERS_COOKIE_KEY)
  if cookie_value:
    # Cookie found, validate it!
    user_session = UserSession.user_session_for_id(cookie_value)
    if user_session:
      # Found a UserSession live in ndb...
      if user_session.expires > datetime.now():
        user_key = ndb.Key(User, user_session.userId)
        return user_key.get()
  return None

def create_logout_url(redirect_uri=None):
  """ Destroys the User's session and redirects to `redirect_uri`.
  Note: Will return current protocol (i.e. http:// or https://),
  secure parameter in app.yaml will redirect to secure URL. """
  request = webapp2.get_request()
  if redirect_uri:
    return ''.join([
      request.host_url,
      NDB_USERS_LOGIN_URI,
      '?', urlencode({
        'action': 'logout',
        'continue': redirect_uri
      })
    ])
  return ''.join([
    request.host_url,
    NDB_USERS_LOGIN_URI, '?action=logout'
  ])

def create_login_url(redirect_uri=None):
  """ A login page, upon successful login will redirect to `redirect_uri`.
  Note: Will return current protocol (i.e. http:// or https://),
  secure parameter in app.yaml will redirect to secure URL. """
  request = webapp2.get_request()
  if redirect_uri:
    return ''.join([
      request.host_url,
      NDB_USERS_LOGIN_URI, '?', urlencode({
        'continue': redirect_uri
      })
    ])
  return ''.join([
    request.host_url,
    NDB_USERS_LOGIN_URI
  ])

def create_password_change_url(redirect_uri=None):
  """ Return a URL for changing the user's password. Redirect optional.
  Note: Will return current protocol (i.e. http:// or https://),
  secure parameter in app.yaml will redirect to secure URL. """
  request = webapp2.get_request()
  if redirect_uri:
    return ''.join([
      request.host_url,
      NDB_USERS_LOGIN_PASSWORD_CHANGE_URI,
      '?', urlencode({
        'continue': redirect_uri
      })
    ])
  return ''.join([
    request.host_url,
    NDB_USERS_LOGIN_PASSWORD_CHANGE_URI
  ])

def create_password_forgot_url(redirect_uri=None):
  """ Return a URL for resetting a user's password. Redirect optional.
  Note: Will return current protocol (i.e. http:// or https://),
  secure parameter in app.yaml will redirect to secure URL. """
  request = webapp2.get_request()
  if redirect_uri:
    return ''.join([
      request.host_url,
      NDB_USERS_LOGIN_PASSWORD_FORGOT_URI,
      '?', urlencode({
          'continue': redirect_uri
        })
    ])
  return ''.join([
    request.host_url,
    NDB_USERS_LOGIN_PASSWORD_FORGOT_URI
  ])

def _append_query(base, query):
  """ Append `query` to `base` if `query` has length. """
  if query:
    return ''.join([base, '?', query])
  return base

def template_values(template_values=dict(), query_options=dict(), user=None):
  """ Return `template_values` plus the default key-value pairs. """
  request = webapp2.get_request()
  continue_uri = request.GET.get('continue')
  if continue_uri:
    query_options['continue'] = continue_uri
    template_values.update(continue_uri=continue_uri)
  logout_query_options = query_options.copy()
  logout_query_options['action'] = 'logout'
  if not user:
    # Only fetch via get_current_user() if `user` kwarg is None
    user = get_current_user()
  if user:
    # Default key-value pairs with logged in user
    template_values.update(user={ 'email': user.email },
      logout_uri=_append_query(
        NDB_USERS_LOGIN_URI, urlencode(logout_query_options)),
      password_change_uri=_append_query(
        NDB_USERS_LOGIN_PASSWORD_CHANGE_URI, urlencode(query_options)),
      password_forgot_uri=_append_query(
        NDB_USERS_LOGIN_PASSWORD_FORGOT_URI, urlencode(query_options))
    )
  else:
    # Default key-value pairs with no user
    template_values.update(
        login_uri=_append_query(
          NDB_USERS_LOGIN_URI, urlencode(query_options)),
        create_uri=_append_query(
          NDB_USERS_LOGIN_CREATE_URI, urlencode(query_options)),
        password_forgot_uri=_append_query(
          NDB_USERS_LOGIN_PASSWORD_FORGOT_URI, urlencode(query_options)),
        password_reset_uri=_append_query(
          NDB_USERS_LOGIN_PASSWORD_RESET_URI, urlencode(query_options))
      )
  return template_values

def _user_id_for_email(email):
  """ Return a hash for `email`. """
  return hashlib.sha256(email).hexdigest()

def _password_hash(password, salt):
  """ Return a hash of the User's `password` and `salt`. """
  return hashlib.sha256(''.join([password, salt])).hexdigest()

def user_verified(user):
  """ Return True if `user.verified` is True or
  `NDB_USERS_ENFORCE_EMAIL_VERIFICATION` is False.
  """
  if NDB_USERS_ENFORCE_EMAIL_VERIFICATION:
    return bool(user.verified)
  return True

def _email_sender():
  """ Returns the email address all account activation and password recovery
  emails will come from (sender). See `users.NDB_USERS_EMAIL_SENDER`. """
  if NDB_USERS_EMAIL_SENDER:
    return NDB_USERS_EMAIL_SENDER
  else:
    # Construct using the Application ID
    return ''.join([
      'accounts@', app_identity.get_application_id(), '.appspotmail.com'])

def _generate_token():
  """ Returns a token of `NDB_USERS_TOKEN_LENGTH` length. """
  return ''.join(random.SystemRandom().sample(
      string.hexdigits, NDB_USERS_TOKEN_LENGTH))

def error_handler_unauthorized(request, response, exception):
  """ Used for handling an HTTP/1.1 401 Unauthorized error. Will display the
  login page with a message prompting the user to log in. """
  response.set_status(401)
  response.out.write(template.render(
    'ndb_users/templates/401-unauthorized.html',
    template_values(query_options={
        'continue': request.path
      })
  ))


class User(ndb.Model):
  """ User class defines a user. """

  email = ndb.StringProperty(required=True)
  passwordHash = ndb.StringProperty(required=True)
  passwordSalt = ndb.StringProperty(required=True)
  verified = ndb.BooleanProperty(default=False)
  created = ndb.DateTimeProperty(auto_now_add=True)
  updated = ndb.DateTimeProperty(auto_now=True)
  bounceCount = ndb.IntegerProperty(default=0)
  lastBounce = ndb.DateTimeProperty()

  @classmethod
  @ndb.transactional
  def create_user(cls, email, password):
    """ Used to create a new User in the ndb database. """
    email = email.lower() # Lowercase email address!
    new_user = User(
      key=ndb.Key(User, _user_id_for_email(email)),
      email=email,
      verified=not NDB_USERS_ENFORCE_EMAIL_VERIFICATION
    )
    return new_user.update_password(password)

  def __eq__(self, other)  :
    """ Overrides default equality check (==)."""
    # Compare the User's User ID
    return self.__class__.__name__+self.user_id() == other

  @ndb.transactional
  def update_password(self, new_password):
    """ Update this user's password to `new_password`. """
    password_salt = User._generate_password_salt()
    self.passwordSalt = password_salt
    self.passwordHash = _password_hash(new_password, password_salt)
    return self.put()

  def email_bounce_limited(self):
    """ Return True if this user cannot be sent additional emails. """
    if self.lastBounce:
      if self.lastBounce > datetime.now() - timedelta(
        hours=NDB_USERS_EMAIL_BOUNCE_RETRY_HOURS):
        return True
    return False

  @classmethod
  def _generate_password_salt(cls):
    return ''.join(random.SystemRandom().sample(''.join([string.digits,
      string.letters, string.punctuation]), NDB_USERS_SALT_LENGTH))

  @classmethod
  def user_for_email(cls, email):
    """ Return a User object or None for `email`. """
    return ndb.Key(User, _user_id_for_email(email)).get()

  def json_object(self):
    """ Return a Dictionary representation of this user. Will be the `user`
    object returned by all JSON API requests. """
    return {
      'email': self.email
    }


class UserSession(ndb.Model):
  """ UserSession class stores a User's session IDs (`user_session_id` cookie)
  and associates them with a User (via the User's `key`). """

  userId = ndb.StringProperty(required=True)
  created = ndb.DateTimeProperty(auto_now_add=True)
  expires = ndb.DateTimeProperty(required=True)

  @classmethod
  def user_session_for_id(cls, user_session_id):
    """ Find a UserSession object for `user_session_id`. """
    key = ndb.Key(UserSession, user_session_id)
    return key.get()

  @classmethod
  def _generate_session_id(cls):
    return ''.join(random.SystemRandom().sample(
      ''.join([string.ascii_letters, string.digits]),
      NDB_USERS_SESSION_ID_LENGTH))

  @classmethod
  def create_user_session(cls, user_id, extended=False, **kwargs):
    """ Creates a new UserSession in the ndb database for a given `user_id`. """
    if extended:
      expires = datetime.now() + timedelta(days=NDB_USERS_SESSION_EXTENDED_DAYS)
    else:
      expires = datetime.now() + timedelta(days=NDB_USERS_SESSION_STANDARD_DAYS)
    new_user_session = UserSession(
      key=ndb.Key(UserSession, UserSession._generate_session_id()),
      userId=user_id,
      expires=expires
    )
    return new_user_session.put()


class UserActivation(ndb.Model):
  """ UserActivation class stores a User's activation token and associates them
  with a User (via the User's `key`). """

  userId = ndb.StringProperty(required=True)
  created = ndb.DateTimeProperty(auto_now_add=True)
  expires = ndb.DateTimeProperty(required=True)

  @classmethod
  def create_user_activation(cls, user_id):
    """ Create a new UserActivation in the ndb datastore for a given
    `user_id`. """
    new_user_activation = UserActivation(
      key=ndb.Key(UserActivation, _generate_token()),
      userId=user_id,
      expires = datetime.now() + timedelta(days=NDB_USERS_ACTIVATION_DAYS)
    )
    return new_user_activation.put()

  @ndb.transactional(xg=True)
  def activate_user(self):
    """ Activate the User this UserActivation is assigned to and delete this
    UserActivation from the datastore. """
    user = ndb.Key(User, self.userId).get()
    if user:
      user.verified = True
      user.put()
      self.key.delete()
      return user
    return None

class UserRecovery(ndb.Model):
  """ UserRecovery class stores a User's password recovery token and associates
  them with a User (via the User's `key`). """

  userId = ndb.StringProperty(required=True)
  created = ndb.DateTimeProperty(auto_now_add=True)
  expires = ndb.DateTimeProperty(required=True)

  @classmethod
  def create_user_recovery(cls, user_id):
    """ Create a new UserRecovery in the datastore for a given `user_id`. """
    new_user_recovery = UserRecovery(
      key=ndb.Key(UserRecovery, _generate_token()),
      userId=user_id,
      expires = datetime.now() + timedelta(days=NDB_USERS_RECOVERY_DAYS)
    )
    return new_user_recovery.put()

  @ndb.transactional(xg=True)
  def reset_password(self, password):
    """ Reset the User's password to `password` this UserREcovery is assigned to
    and delete this UserRecovery from the datastore. """
    user = ndb.Key(User, self.userId).get()
    if user:
      if user.update_password(password):
        self.key.delete()
        return user
    return None
