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

import hashlib

from google.appengine.ext.webapp import template

from google.appengine.api import mail

import re

from ndb_users import users

from ndb_users.config import *

from urllib import urlencode


def _login_user_for_id(user_id):
  """ Logs in `user_id` bu creating a UserSession and setting the cookies.
  Note: Don't call this function except by logic within this module! """
  user_session_key = users.UserSession.create_user_session(user_id)
  webapp2.get_request().response.set_cookie(
    NDB_USERS_COOKIE_KEY,
    user_session_key.string_id(),
    secure=_use_secure_cookies()
  )

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
      webapp2.uri_for('LoginActivate'), '?', urlencode(query_options)])
    user = ndb.Key(users.User, user_id).get()
    sender_email_address = users._email_sender()
    subject = 'Account Activation'
    body = """Your account has been created! Please confirm your email address \
by clicking the link below:

{activation_link}
""".format(activation_link=activation_url)
    mail.send_mail(sender_email_address, user.email, subject, body)


class LoginPage(webapp2.RequestHandler):
  def get(self):
    
    user = users.get_current_user()
    if user:
      if 'action' in self.request.GET:
        if self.request.GET['action'] == 'logout':
          cookie_value = self.request.cookies.get(NDB_USERS_COOKIE_KEY)
          if cookie_value:
            ndb.Key(users.UserSession, cookie_value).delete()
            self.response.delete_cookie(NDB_USERS_COOKIE_KEY)
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
    if email and password:
      # Get a User for `email` and `password`
      user = ndb.Key(users.User, users._user_id_for_email(email.lower())).get()
      if user:
        # User found... check Password
        attempt = users._password_hash(password, user.passwordSalt)
        if attempt == user.passwordHash:
          if users._user_verified(user):
            # Success
            _login_user_for_id(user.key.string_id())
            # Redirect if requested
            if self.request.GET.get('continue'):
              self.redirect(self.request.GET['continue'].encode('ascii'))
            self.response.out.write(template.render(
                'ndb_users/templates/login-success.html',
                users.template_values()
              ))
            return None
          else:
            # User not verified
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
    """ JSON GET Request. """

  def post(self):
    """ JSON POST Request. """


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
        'ndb_users/templates/create-error.html', {
          'request': {
            'email': email,
            'password': password,
            'password2': password2
          }
        }))
      return None
    # Check password equality
    if password != password2:
      self.response.out.write(template.render(
        'ndb_users/templates/create-error.html', {
          'request': {
            'email': email,
            'password': password,
            'password2': password2
          }, 'passwordMismatch': True
        }))
      return None
    # Check password length
    if len(password) < 4:
      self.response.out.write(template.render(
        'ndb_users/templates/create-error.html', {
          'request': {
            'email': email,
            'password': password,
            'password2': password2
          }, 'passwordTooShort': True
        }))
      return None
    # Check `email` against regular expression
    if not mail.is_email_valid(email):
      self.response.out.write(template.render(
        'ndb_users/templates/create-error.html', {
          'request': {
            'email': email,
            'password': password,
            'password2': password2
          }, 'emailInvalid': True
        }))
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
        'ndb_users/templates/create-success.html', {
          'email_verification': NDB_USERS_ENFORCE_EMAIL_VERIFICATION
        }))
      return None
    else:
      # Already exists
      self.response.out.write(template.render(
        'ndb_users/templates/create-error.html', {
          'request': {
            'email': email,
            'password': password,
            'password2': password2
          }, 'emailExists': True
        }))
      return None


class JsonLoginCreate(webapp2.RequestHandler):
  def get(self):
    """ JSON GET Request. """

  def post(self):
    """ JSON POST Request. """


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


class LoginActivate(webapp2.RequestHandler):
  def get(self):
    """ Activate a user's account with for a given activation token. """
    activation_token = self.request.GET.get('token')
    user = users.get_current_user()
    if activation_token and not user:
      user_activation = ndb.Key(users.UserActivation, activation_token).get()
      if user_activation:
        user = user_activation.activate_user()
        if user:
          _login_user_for_id(user.key.string_id())
          self.response.out.write(template.render(
              'ndb_users/templates/activate-success.html',
              users.template_values()
            ))
        return None
    continue_uri = self.request.GET.get('continue')
    if user and continue_uri:
      self.redirect(continue_uri.encode('ascii'))
    self.response.out.write(template.render(
        'ndb_users/templates/activate-error.html',
        users.template_values()
      ))


class LoginPasswordReset(webapp2.RequestHandler):
  def get(self):
    self.response.out.write('LoginPasswordReset')

  def post(self):
    self.response.out.write('LoginPasswordReset')


app = webapp2.WSGIApplication([
  RedirectRoute(
    NDB_USERS_LOGIN_URI,
    handler=LoginPage,
    name='login',
    strict_slash=True
  ), webapp2.Route(
    '/_login.json',
    handler=JsonLogin,
    name='jsonLogin'
  ), RedirectRoute(
    NDB_USERS_LOGIN_CREATE_URI,
    handler=LoginCreate,
    name='loginCreate',
    strict_slash=True
  ), webapp2.Route(
    '/_login/create.json',
    handler=JsonLoginCreate,
    name='jsonLoginCreate'
  ), RedirectRoute(
    NDB_USERS_LOGIN_PASSWORD_CHANGE_URI,
    handler=LoginPasswordChange,
    name='loginPasswordChange',
    strict_slash=True
  ), RedirectRoute(
    NDB_USERS_LOGIN_ACTIVATE_URI,
    handler=LoginActivate,
    name='LoginActivate',
    strict_slash=True
  ), RedirectRoute(
    NDB_USERS_LOGIN_PASSWORD_RESET_URI,
    handler=LoginPasswordReset,
    name='LoginPasswordReset',
    strict_slash=True
  )
])


def not_found_error_page(request, response, exception):
  """ Used for HTTP/1.1 404 message output """
  response.write('Oops! I could swear this page was here! [HTTP/1.1 404 Not Fou\
nd]')
  response.set_status(404)

def internal_server_error_page(request, response, exception):
  """ Used for HTTP/1.1 500 message output """
  response.write('Oops! An internal server error has occurred. [HTTP/1.1 500 In\
ternal Server Error]')
  response.set_status(500)


app.error_handlers[401] = users.error_handler_unauthorized
app.error_handlers[404] = not_found_error_page
app.error_handlers[500] = internal_server_error_page
