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


from os import getenv

import webapp2

from webapp2_extras.routes import RedirectRoute

from google.appengine.ext import ndb

import json

import logging

import hashlib

from google.appengine.ext.webapp import template

from google.appengine.api import mail

import re

from ndb_users import users

from ndb_users.config import *

from urllib import urlencode

from datetime import datetime, timedelta


def _login_user_for_id(user_id, extended=False):
  """ Logs in the user identified by `user_id` by creating a UserSession and
  setting the cookies. Will create an extended session if `extended` is True.
  Note: Don't call this function except by logic within this module! """
  user_session_key = users.UserSession.create_user_session(user_id,
    extended=extended)
  request = webapp2.get_request()
  options = {
    'secure': _use_secure_cookies()
  }
  if extended:
    options['expires'] = datetime.now() + timedelta(
      days=NDB_USERS_SESSION_EXTENDED_DAYS)
  request.response.set_cookie(
    NDB_USERS_COOKIE_KEY,
    user_session_key.string_id(),
    **options
  )

def _logout_user():
  """ Delete the cookie and terminate the UserSession. """
  request = webapp2.get_request()
  cookie_value = request.cookies.get(NDB_USERS_COOKIE_KEY)
  if cookie_value:
    ndb.Key(users.UserSession, cookie_value).delete()
    request.response.delete_cookie(NDB_USERS_COOKIE_KEY)

def _use_secure_cookies():
  """ Return True if this is the Google App Engine production environment and
  `NDB_USERS_COOKIE_SECURE` is True. Otherwise return False. """
  if NDB_USERS_COOKIE_SECURE:
    if getenv('SERVER_SOFTWARE').startswith('Google App Engine/'):
      return True
  # Default
  return False

def _create_activation_email_for_user_id(user_id):
  """ Create an activation token for `user` and send an email to the User's
  email address including a link to activate. """
  request = webapp2.get_request()
  new_user_activation_key = users.UserActivation.create_user_activation(user_id)
  if new_user_activation_key:
    query_options = {
      'token': new_user_activation_key.string_id()
    }
    continue_uri = request.GET.get('continue')
    if continue_uri:
      query_options['continue'] = continue_uri
    activation_url = ''.join([request.host_url,
      webapp2.uri_for('loginActivate'), '?', urlencode(query_options)])
    user = ndb.Key(users.User, user_id).get()
    sender_email_address = users._email_sender()
    subject = 'Account Activation'
    body = """Your account has been created! Please confirm your email address \
by clicking the link below:

{activation_link}
""".format(activation_link=activation_url)
    mail.send_mail(sender_email_address, user.email, subject, body)

def _create_recovery_email_for_user_id(user_id):
  """ Create a password recovery token for `user` and send an email to the
  User's email address including a link to reset their password. """
  request = webapp2.get_request()
  new_user_recovery_key = users.UserRecovery.create_user_recovery(user_id)
  if new_user_recovery_key:
    query_options = {
      'token': new_user_recovery_key.string_id()
    }
    continue_uri = request.GET.get('continue')
    if continue_uri:
      query_options['continue'] = continue_uri
    reset_url = ''.join([
        request.host_url,
        webapp2.uri_for('loginPasswordReset'),
        '?', urlencode(query_options)
      ])
    user = ndb.Key(users.User, user_id).get()
    sender_email_address = users._email_sender()
    subject = 'Password Reset'
    body = """Reset your password by clicking the link below:

{recovery_link}

You may ignore this email and continue using your current password if you did \
not request this recovery or remember your current password.
""".format(recovery_link=reset_url)
    mail.send_mail(sender_email_address, user.email, subject, body)


class LoginPage(webapp2.RequestHandler):
  def get(self):
    user = users.get_current_user()
    if user:
      action = self.request.GET.get('action')
      if action == 'logout':
        _logout_user()
        if self.request.GET.get('continue'):
          self.redirect(self.request.GET.get('continue').encode('ascii'))
        self.response.out.write(template.render(
          'ndb_users/templates/logout-success.html',
          users.template_values()
        ))
      else:
        if self.request.GET.get('continue'):
          self.redirect(self.request.GET.get('continue').encode('ascii'))
        self.response.out.write(template.render(
          'ndb_users/templates/login-success.html',
          users.template_values()
        ))
      return None
    # Path and serve template
    self.response.out.write(template.render(
      'ndb_users/templates/login.html',
      users.template_values()
    ))

  def post(self):
    """ Log in a user via POST'ed `email` and `password` values. """
    # Make sure required POST parameters are present
    email = self.request.POST.get('email')
    password = self.request.POST.get('password')
    extended = bool(self.request.POST.get('extended'))
    if email and password:
      # Get a User for `email` and `password`
      user = ndb.Key(users.User, users._user_id_for_email(email.lower())).get()
      if user:
        # User found... check Password
        attempt = users._password_hash(password, user.passwordSalt)
        if attempt == user.passwordHash:
          if users.user_verified(user):
            # Success
            _login_user_for_id(user.key.string_id(), extended=extended)
            # Redirect if requested
            if self.request.GET.get('continue'):
              self.redirect(self.request.GET['continue'].encode('ascii'))
            self.response.out.write(template.render(
              'ndb_users/templates/login-success.html',
              users.template_values(template_values={
                  'user': user
                })
            ))
            return None
          else:
            # User email not verified (send another email)
            _create_activation_email_for_user_id(user.key.string_id())
            self.response.out.write(template.render(
              'ndb_users/templates/login-not-verified.html',
              users.template_values()
            ))
            return None
    # Error
    self.response.out.write(template.render(
      'ndb_users/templates/login-error.html',
      users.template_values()
    ))


class JsonLogin(webapp2.RequestHandler):
  def get(self):
    """ Return a `user` if logged in; empty object if no user; handle logging
    out users via JSON request. """
    response_object = dict()
    user = users.get_current_user()
    if user:
      response_object['user'] = user.json_object()
      action = self.request.GET.get('action')
      if action == 'logout':
        _logout_user()
        del response_object['user']
    self.response.content_type = 'application/json'
    self.response.out.write(json.dumps(response_object))

  def post(self):
    """ Log in a user via supplied JSON `email` and `password` values. """
    request_object = json.loads(self.request.body)
    email = request_object.get('email')
    password = request_object.get('password')
    extended = request_object.get('extended')
    response_object = dict()
    if email and password:
      # Get a User for `email` and `password`
      user = ndb.Key(users.User, users._user_id_for_email(email.lower())).get()
      if user:
        # User found... check Password
        attempt = users._password_hash(password, user.passwordSalt)
        if attempt == user.passwordHash:
          if users.user_verified(user):
            # Success
            _login_user_for_id(user.key.string_id(), extended=extended)
            response_object['user'] = user.json_object()
            self.response.content_type = 'application/json'
            self.response.out.write(json.dumps(response_object))
            return None
          else:
            # User email not verified (send another email)
            _create_activation_email_for_user_id(user.key.string_id())
            response_object['user_not_verified'] = True
            self.response.content_type = 'application/json'
            self.response.out.write(json.dumps(response_object))
            return None
      self.response_object['user_not_found'] = True
      self.response.content_type = 'application/json'
      self.response.out.write(json.dumps(response_object))
    else:
      self.abort(400)


class LoginCreate(webapp2.RequestHandler):
  def get(self):
    """ Display the Signup/Create Account template. """
    # Ensure user not logged in
    user = users.get_current_user()
    self.response.out.write(template.render(
      'ndb_users/templates/create.html',
      users.template_values()
    ))

  def post(self):
    """ Create a new User with `email` and `password` (confirmed by
    `password2 `). """
    email = self.request.POST.get('email')
    password = self.request.POST.get('password')
    password2 = self.request.POST.get('password2')
    # Make sure required POST parameters are present
    if not email or not password or not password2:
      self.response.out.write(template.render(
        'ndb_users/templates/create-error.html',
        users.template_values(template_values={
          'request': {
            'email': email,
            'password': password,
            'password2': password2
          }
        })
      ))
      return None
    # Check password equality
    if password != password2:
      self.response.out.write(template.render(
        'ndb_users/templates/create-error.html',
        users.template_values(template_values={
          'request': {
            'email': email,
            'password': password,
            'password2': password2
          }, 'passwordMismatch': True
        })
      ))
      return None
    # Check password length
    if len(password) < 4:
      self.response.out.write(template.render(
        'ndb_users/templates/create-error.html',
        users.template_values(template_values={
          'request': {
            'email': email,
            'password': password,
            'password2': password2
          }, 'passwordTooShort': True
        })
      ))
      return None
    # Check `email` against regular expression
    if not mail.is_email_valid(email):
      self.response.out.write(template.render(
        'ndb_users/templates/create-error.html',
        users.template_values(template_values={
          'request': {
            'email': email,
            'password': password,
            'password2': password2
          }, 'emailInvalid': True
        })
      ))
      return None
    # Try finding a User with this email...
    user_found = users.User.query(users.User.email==email).count(1)
    if user_found < 1:
      # Create a User
      new_user_key = users.User.create_user(email, password)
      if NDB_USERS_ENFORCE_EMAIL_VERIFICATION:
        _create_activation_email_for_user_id(new_user_key.string_id())
      else:
        # Log this user in!
        _login_user_for_id(new_user_key.string_id())
        if self.request.GET.get('continue'):
          self.redirect(self.request.GET.get('continue').encode('ascii'))
      self.response.out.write(template.render(
        'ndb_users/templates/create-success.html',
        users.template_values(template_values={
          'email_verification': NDB_USERS_ENFORCE_EMAIL_VERIFICATION
        })
      ))
      return None
    else:
      # Already exists
      self.response.out.write(template.render(
        'ndb_users/templates/create-error.html',
        users.template_values(template_values={
          'request': {
            'email': email,
            'password': password,
            'password2': password2
          }, 'emailExists': True
        })
      ))
      return None


class JsonLoginCreate(webapp2.RequestHandler):
  def post(self):
    """ Create a new user for the supplied `email` and `password`. """
    response_object = dict()
    user = users.get_current_user()
    request_object = json.loads(self.request.body)
    if not user:
      email = request_object.get('email')
      password = request_object.get('password')
      if email and password:
        # Check password length
        if len(password) < 4:
          response['password_too_short'] = True
          self.response.content_type = 'application/json'
          self.response.out.write(json.dumps(response_object))
          return None
        # Check `email`
        if not mail.is_email_valid(email):
          response_object['email_invalid'] = True
          self.response.content_type = 'application/json'
          self.response.out.write(json.dumps(response_object))
          return None
        # Try finding a User with this email...
        user_found = users.User.query(users.User.email==email).count(1)
        if user_found < 1:
          # Create a User
          new_user_key = users.User.create_user(email, password)
          response_object['user'] = new_user_key.get().json_object()
          if NDB_USERS_ENFORCE_EMAIL_VERIFICATION:
            _create_activation_email_for_user_id(new_user_key.string_id())
            response_object['email_verification'] = True
          else:
            # Log this user in!
            _login_user_for_id(new_user_key.string_id())
          self.response.content_type = 'application/json'
          self.response.out.write(json.dumps(response_object))
          return None
        else:
          # Already exists
          response_object['email_in_use'] = True
          self.response.content_type = 'application/json'
          self.response.out.write(json.dumps(response_object))
          return None
    self.abort(400) # Logged in user, no `email`, or no `password`


class LoginPasswordChange(webapp2.RequestHandler):
  def get(self):
    """ Display a change password form, if user is logged in. """
    user = users.get_current_user()
    if user:
      self.response.out.write(template.render(
        'ndb_users/templates/password-change.html',
        users.template_values()
      ))
      return None
    # No logged in user
    self.redirect(webapp2.uri_for('login'))

  def post(self):
    """ Change the logged in user's password. """
    user = users.get_current_user()
    if user:
      current_password = self.request.POST.get('password')
      new_password = self.request.POST.get('newPassword')
      new_password2 = self.request.POST.get('newPassword2')
      # Make sure required POST parameters are present
      if not current_password or not new_password or not new_password2:
        self.response.out.write(template.render(
          'ndb_users/templates/password-change-error.html',
          users.template_values()
        ))
        return None
      # Check password equality
      if new_password != new_password2:
        self.response.out.write(template.render(
          'ndb_users/templates/password-change-error.html', {
            'passwordMismatch': True
          }
        ))
        return None
      # Check password length
      if len(new_password) < 4:
        self.response.out.write(template.render(
          'ndb_users/templates/password-change-error.html', {
            'passwordTooShort': True
          }
        ))
        return None
      # Check `current_password` is indeed this user's password
      attempt = users._password_hash(current_password, user.passwordSalt)
      if attempt == user.passwordHash:
        # Correct password; update to `new_password`
        user.update_password(new_password)
        self.response.out.write(template.render(
          'ndb_users/templates/password-change-success.html',
          users.template_values()
        ))
        return None
      else:
        # Wrong `current_password)
        self.response.out.write(template.render(
          'ndb_users/templates/password-change-error.html',
          users.template_values()
        ))
        return None
    # Not logged in
    self.redirect(webapp2.uri_for('login'))


class JsonLoginPasswordChange(webapp2.RequestHandler):
  def get(self):
    self.response.out.write('JsonLoginPasswordChange')

  def post(self):
    self.response.out.write('JsonLoginPasswordChange')


class LoginActivate(webapp2.RequestHandler):
  def get(self):
    """ Activate a user's account with for a given activation token. """
    activation_token = self.request.GET.get('token')
    user = users.get_current_user()
    temp_values = {}
    if activation_token and not user:
      user_activation = ndb.Key(users.UserActivation, activation_token).get()
      if user_activation:
        if user_activation.expires > datetime.now():
          user = user_activation.activate_user()
          if user:
            _login_user_for_id(user.key.string_id())
            self.response.out.write(template.render(
              'ndb_users/templates/activate-success.html',
              users.template_values()
            ))
          return None
        else:
          temp_values['token_expired'] = True
    continue_uri = self.request.GET.get('continue')
    if user and continue_uri:
      self.redirect(continue_uri.encode('ascii'))
    self.response.out.write(template.render(
      'ndb_users/templates/activate-error.html',
      users.template_values(template_values=temp_values)
    ))


class JsonLoginAcivate(webapp2.RequestHandler):
  def get(self):
    self.response.out.write('JsonLoginAcivate')

  def post(self):
    self.response.out.write('JsonLoginAcivate')


class LoginPasswordForgot(webapp2.RequestHandler):
  def get(self):
    """ Display the password recovery form, asking for a user's email. """
    user = users.get_current_user()
    if not user:
      self.response.out.write(template.render(
        'ndb_users/templates/password-forgot.html',
        users.template_values()
      ))
    else:
      continue_uri = self.request.GET.get('continue')
      if continue_uri:
        self.redirect(continue_uri.encode('ascii'))
      else:
        self.redirect(webapp2.uri_for('login'))

  def post(self):
    """ Send a recovery email, if `email` is found. """
    # Require an email address...
    user = users.get_current_user()
    if user:
      self.redirect(webapp2.uri_for('login'))
      return None
    email = self.request.POST.get('email')
    if email:
      # Get a user's key for their email address...
      user = users.User.user_for_email(email)
      if user:
        if users.user_verified(user):
          _create_recovery_email_for_user_id(user.key.string_id())
          self.response.out.write(template.render(
            'ndb_users/templates/password-forgot-success.html',
            users.template_values()
          ))
        else:
          # User not verified
          self.response.out.write(template.render(
            'ndb_users/templates/password-forgot-error.html',
            users.template_values(template_values={
                'user_not_verified': True
              })
          ))
      else:
        self.response.out.write(template.render(
          'ndb_users/templates/password-forgot-error.html',
          users.template_values(template_values={
              'error_email_not_found': True,
              'email': email
            })
        ))
    else:
      # No `email` supplied in POST
      self.response.out.write(template.render(
        'ndb_users/templates/password-forgot-error.html',
        users.template_values(template_values={
            'error_invalid_email': True,
            'email': email
          })
      ))


class JsonLoginPasswordForgot(webapp2.RequestHandler):
  def get(self):
    self.response.out.write('JsonLoginPasswordForgot')

  def post(self):
    self.response.out.write('JsonLoginPasswordForgot')


class LoginPasswordReset(webapp2.RequestHandler):
  def get(self):
    """ Display a password reset form if the `token` is valid. """
    token = self.request.GET.get('token')
    user = users.get_current_user()
    if token and not user:
      user_recovery = ndb.Key(users.UserRecovery, token).get()
      if user_recovery:
        if user_recovery.expires > datetime.now():
          self.response.out.write(template.render(
            'ndb_users/templates/password-reset.html',
            users.template_values(query_options={
                'token': token
              })
          ))
          return None
    continue_uri = self.request.GET.get('continue')
    if user and continue_uri:
      self.redirect(continue_uri.encode('ascii'))
    self.response.out.write(template.render(
      'ndb_users/templates/password-reset-error.html',
      users.template_values(template_values={
          'token_invalid': True
        }, query_options={
          'token': token
        })
    ))

  def post(self):
    """ Reset the user's password for a `token` and passwords. """
    token = self.request.GET.get('token')
    user = users.get_current_user()
    password = self.request.POST.get('password')
    password2 = self.request.POST.get('password2')
    if token and not user:
      # Check passwords match
      if password != password2:
        self.response.out.write(template.render(
          'ndb_users/templates/password-reset-error.html',
          users.template_values(template_values={
              'password_mismatch': True
            }, query_options={
              'token': token
            })
        ))
        return None
      # Check password length
      if len(password) < 4:
        self.response.out.write(template.render(
          'ndb_users/templates/password-reset-error.html',
          users.template_values(template_values={
              'password_too_short': True
            }, query_options={
              'token': token
            })
        ))
        return None
      # Recover the User
      user_recovery = ndb.Key(users.UserRecovery, token).get()
      if user_recovery:
        if user_recovery.expires > datetime.now():
          user = user_recovery.reset_password(password)
          if user:
            _login_user_for_id(user.key.string_id())
            self.response.out.write(template.render(
              'ndb_users/templates/password-change-success.html',
              users.template_values(query_options={
                  'token': token
                })
            ))
          return None
    continue_uri = self.request.GET.get('continue')
    if user and continue_uri:
      self.redirect(continue_uri.encode('ascii'))
    self.response.out.write(template.render(
      'ndb_users/templates/password-reset-error.html',
      users.template_values(template_values={
        'token_invalid': True
        }, query_options={
          'token': token
        })
    ))


class JsonLoginPasswordReset(webapp2.RequestHandler):
  def get(self):
    self.response.out.write('JsonLoginPasswordReset')

  def post(self):
    self.response.out.write('JsonLoginPasswordReset')


app = webapp2.WSGIApplication([
  RedirectRoute(
    NDB_USERS_LOGIN_URI,
    handler=LoginPage,
    name='login',
    strict_slash=True
  ), webapp2.Route(
    NDB_USERS_LOGIN_API_PATH,
    handler=JsonLogin,
    name='jsonLogin'
  ), RedirectRoute(
    NDB_USERS_LOGIN_CREATE_URI,
    handler=LoginCreate,
    name='loginCreate',
    strict_slash=True
  ), webapp2.Route(
    NDB_USERS_LOGIN_CREATE_API_PATH,
    handler=JsonLoginCreate,
    name='jsonLoginCreate'
  ), RedirectRoute(
    NDB_USERS_LOGIN_PASSWORD_CHANGE_URI,
    handler=LoginPasswordChange,
    name='loginPasswordChange',
    strict_slash=True
  ), webapp2.Route(
    NDB_USERS_LOGIN_PASSWORD_CHANGE_API_PATH,
    handler=JsonLoginPasswordChange,
    name='jsonLoginPasswordChange'
  ), RedirectRoute(
    NDB_USERS_LOGIN_ACTIVATE_URI,
    handler=LoginActivate,
    name='loginActivate',
    strict_slash=True
  ), webapp2.Route(
    NDB_USERS_LOGIN_ACTIVATE_API_PATH,
    handler=JsonLoginAcivate,
    name='jsonLoginActivate'
  ), RedirectRoute(
    NDB_USERS_LOGIN_PASSWORD_FORGOT_URI,
    handler=LoginPasswordForgot,
    name='loginPasswordForgot',
    strict_slash=True
  ), webapp2.Route(
    NDB_USERS_LOGIN_PASSWORD_FORGOT_API_PATH,
    handler=JsonLoginPasswordForgot,
    name='jsonLoginPasswordReset'
  ), RedirectRoute(
    NDB_USERS_LOGIN_PASSWORD_RESET_URI,
    handler=LoginPasswordReset,
    name='loginPasswordReset',
    strict_slash=True
  ), webapp2.Route(
    NDB_USERS_LOGIN_PASSWORD_RESET_API_PATH,
    handler=JsonLoginPasswordReset,
    name='jsonLoginPasswordReset'
  )
])


def bad_request_error_page(request, response, exception):
  """ Used for HTTP/1.1 400 Bad request message output. """
  logging.exception(exception)
  response.write('Oops! The request could not be understood. [HTTP/1.1 400 Bad \
Request]')
  response.set_status(400)

def not_found_error_page(request, response, exception):
  """ Used for HTTP/1.1 404 message output """
  logging.exception(exception)
  response.write('Oops! I could swear this page was here! [HTTP/1.1 404 Not Fou\
nd]')
  response.set_status(404)

def internal_server_error_page(request, response, exception):
  """ Used for HTTP/1.1 500 message output """
  logging.exception(exception)
  response.write('Oops! An internal server error has occurred. [HTTP/1.1 500 In\
ternal Server Error]')
  response.set_status(500)


app.error_handlers[400] = bad_request_error_page
app.error_handlers[401] = users.error_handler_unauthorized
app.error_handlers[404] = not_found_error_page
app.error_handlers[500] = internal_server_error_page
