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


import logging

import webapp2

from google.appengine.ext.webapp.mail_handlers import BounceNotificationHandler

from ndb_users import users

from google.appengine.ext import ndb

from datetime import datetime


class BounceHandler(BounceNotificationHandler):
  def receive(self, bounce_message):
    logging.info('Received bounce notification: [%s]',
      str(bounce_message.notification))
    email = bounce_message.original.get('to')
    if email:
      logging.info('Original recipient: ' + email)
      user = ndb.Key(users.User, users._user_id_for_email(email.lower())).get()
      if user:
        # Increment this user's `bounceCount` and update `lastBounce`
        user.bounceCount += 1
        user.lastBounce = datetime.now()
        user.put()
      else:
        logging.info('User could not be found!')
    else:
      logging.info('Original recipient could not be determined!')


app = webapp2.WSGIApplication([BounceHandler.mapping()], debug=True)
