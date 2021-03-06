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

from google.appengine.ext.webapp import template

from ndb_users import users


class HomePage(webapp2.RequestHandler):
  def get(self):
    """ Serve the homepage. """
    user = users.get_current_user()
    self.response.out.write(template.render(
        'templates/index.html', {
          'user': user,
          'login_url': users.create_login_url(webapp2.uri_for('protected')),
          'logout_url': users.create_logout_url(webapp2.uri_for('home')),
          'password_forgot_url': users.create_password_forgot_url(
            webapp2.uri_for('protected')),
          'password_change_url': users.create_password_change_url(
            webapp2.uri_for('home'))
        }
      ))


class ProtectedPage(webapp2.RequestHandler):
  def get(self):
    """ Restrict this page to logged in users only! """
    user = users.get_current_user()
    if not user:
      self.abort(401)
    else:
      self.response.out.write(template.render(
          'templates/protected-page.html', {
            'user': user,
            'logout_url': users.create_logout_url(webapp2.uri_for('home')),
            'password_change_url': users.create_password_change_url(
              webapp2.uri_for('protected'))
          }
        ))


class DocumentationPage(webapp2.RequestHandler):
  def get(self):
    """ Serves the documentation page. """
    user = users.get_current_user()
    self.response.out.write(template.render(
        'templates/docs.html',{
            'user': user,
            'login_url': users.create_login_url(
              webapp2.uri_for('documentation')),
            'logout_url': users.create_logout_url(
              webapp2.uri_for('documentation')),
            'password_forgot_url': users.create_password_forgot_url(
              webapp2.uri_for('documentation')),
            'password_change_url': users.create_password_change_url(
              webapp2.uri_for('documentation'))
          }
      ))


class JsonApiPage(webapp2.RequestHandler):
  def get(self):
    """ Serves the JSON API page. """
    user = users.get_current_user()
    self.response.out.write(template.render(
      'templates/json-api.html', {
        'user': user,
        'login_url': users.create_login_url(
          webapp2.uri_for('documentation')),
        'logout_url': users.create_logout_url(
          webapp2.uri_for('documentation')),
        'password_forgot_url': users.create_password_forgot_url(
          webapp2.uri_for('documentation')),
        'password_change_url': users.create_password_change_url(
          webapp2.uri_for('documentation'))
      }))


class JsonApiGetLogin(webapp2.RequestHandler):
  def get(self):
    user = users.get_current_user()
    self.response.out.write(template.render(
      'templates/json-api-get-login.html', {
        'user': user,
        'login_url': users.create_login_url(
          webapp2.uri_for('documentation')),
        'logout_url': users.create_logout_url(
          webapp2.uri_for('documentation')),
        'password_forgot_url': users.create_password_forgot_url(
          webapp2.uri_for('documentation')),
        'password_change_url': users.create_password_change_url(
          webapp2.uri_for('documentation'))
      }))


class JsonApiPostLogin(webapp2.RequestHandler):
  def get(self):
    user = users.get_current_user()
    self.response.out.write(template.render(
      'templates/json-api-post-login.html', {
        'user': user,
        'login_url': users.create_login_url(
          webapp2.uri_for('documentation')),
        'logout_url': users.create_logout_url(
          webapp2.uri_for('documentation')),
        'password_forgot_url': users.create_password_forgot_url(
          webapp2.uri_for('documentation')),
        'password_change_url': users.create_password_change_url(
          webapp2.uri_for('documentation'))
      }))


class JsonApiPostLoginCreate(webapp2.RequestHandler):
  def get(self):
    user = users.get_current_user()
    self.response.out.write(template.render(
      'templates/json-api-post-login-create.html', {
        'user': user,
        'login_url': users.create_login_url(
          webapp2.uri_for('documentation')),
        'logout_url': users.create_logout_url(
          webapp2.uri_for('documentation')),
        'password_forgot_url': users.create_password_forgot_url(
          webapp2.uri_for('documentation')),
        'password_change_url': users.create_password_change_url(
          webapp2.uri_for('documentation'))
      }))


class JsonApiGetLoginActivate(webapp2.RequestHandler):
  def get(self):
    user = users.get_current_user()
    self.response.out.write(template.render(
      'templates/json-api-get-login-activate.html', {
        'user': user,
        'login_url': users.create_login_url(
          webapp2.uri_for('documentation')),
        'logout_url': users.create_logout_url(
          webapp2.uri_for('documentation')),
        'password_forgot_url': users.create_password_forgot_url(
          webapp2.uri_for('documentation')),
        'password_change_url': users.create_password_change_url(
          webapp2.uri_for('documentation'))
      }))


class JsonApiPostLoginPasswordChange(webapp2.RequestHandler):
  def get(self):
    user = users.get_current_user()
    self.response.out.write(template.render(
      'templates/json-api-post-login-password-change.html', {
        'user': user,
        'login_url': users.create_login_url(
          webapp2.uri_for('documentation')),
        'logout_url': users.create_logout_url(
          webapp2.uri_for('documentation')),
        'password_forgot_url': users.create_password_forgot_url(
          webapp2.uri_for('documentation')),
        'password_change_url': users.create_password_change_url(
          webapp2.uri_for('documentation'))
      }))


class JsonApiPostLoginPasswordForgot(webapp2.RequestHandler):
  def get(self):
    user = users.get_current_user()
    self.response.out.write(template.render(
      'templates/json-api-post-login-password-forgot.html', {
        'user': user,
        'login_url': users.create_login_url(
          webapp2.uri_for('documentation')),
        'logout_url': users.create_logout_url(
          webapp2.uri_for('documentation')),
        'password_forgot_url': users.create_password_forgot_url(
          webapp2.uri_for('documentation')),
        'password_change_url': users.create_password_change_url(
          webapp2.uri_for('documentation'))
      }))


class JsonApiGetLoginPasswordReset(webapp2.RequestHandler):
  def get(self):
    user = users.get_current_user()
    self.response.out.write(template.render(
      'templates/json-api-get-login-password-reset.html', {
        'user': user,
        'login_url': users.create_login_url(
          webapp2.uri_for('documentation')),
        'logout_url': users.create_logout_url(
          webapp2.uri_for('documentation')),
        'password_forgot_url': users.create_password_forgot_url(
          webapp2.uri_for('documentation')),
        'password_change_url': users.create_password_change_url(
          webapp2.uri_for('documentation'))
      }))


class JsonApiPostLoginPasswordReset(webapp2.RequestHandler):
  def get(self):
    user = users.get_current_user()
    self.response.out.write(template.render(
      'templates/json-api-post-login-password-reset.html', {
        'user': user,
        'login_url': users.create_login_url(
          webapp2.uri_for('documentation')),
        'logout_url': users.create_logout_url(
          webapp2.uri_for('documentation')),
        'password_forgot_url': users.create_password_forgot_url(
          webapp2.uri_for('documentation')),
        'password_change_url': users.create_password_change_url(
          webapp2.uri_for('documentation'))
      }))


app = webapp2.WSGIApplication([
    webapp2.Route(
      '/',
      handler=HomePage,
      name='home'
    ), webapp2.Route(
      '/protected',
      handler=ProtectedPage,
      name='protected'
    ), webapp2.Route(
      '/documentation',
      handler=DocumentationPage,
      name='documentation'
    ), webapp2.Route(
      '/json-api',
      handler=JsonApiPage,
      name='jsonApiPage'
    ), webapp2.Route(
      '/json-api/get/login',
      handler=JsonApiGetLogin,
      name='jsonApiGetLogin'
    ), webapp2.Route(
      '/json-api/post/login',
      handler=JsonApiPostLogin,
      name='jsonApiPostLogin'
    ), webapp2.Route(
      '/json-api/post/login/create',
      handler=JsonApiPostLoginCreate,
      name='jsonApiPostLoginCreate'
    ), webapp2.Route(
      '/json-api/get/login/activate',
      handler=JsonApiGetLoginActivate,
      name='jsonApiGetLoginActivate'
    ), webapp2.Route(
      '/json-api/post/login/password/change',
      handler=JsonApiPostLoginPasswordChange,
      name='jsonApiPostLoginPasswordChange'
    ), webapp2.Route(
      '/json-api/post/login/password/forgot',
      handler=JsonApiPostLoginPasswordForgot,
      name='jsonApiPostLoginPasswordForgot'
    ), webapp2.Route(
      '/json-api/get/login/password/reset',
      handler=JsonApiGetLoginPasswordReset,
      name='jsonApiPostLoginPasswordReset'
    ), webapp2.Route(
      '/json-api/post/login/password/reset',
      handler=JsonApiPostLoginPasswordReset,
      name='jsonApiPostLoginPasswordReset'
    )
  ])


app.error_handlers[401] = users.error_handler_unauthorized
