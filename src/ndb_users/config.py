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


""" The key a user's session ID will be stored under. Note: Changing this value
will in effect log out all currently logged in users. """
NDB_USERS_COOKIE_KEY = 'user_session_id'


""" Route URIs. Warning: Do not change `/_login` prefix unless module URL
handlers are updated in your .yaml file. """
NDB_USERS_LOGIN_URI                 = '/_login'
NDB_USERS_LOGIN_CREATE_URI          = '/_login/create'
NDB_USERS_LOGIN_ACTIVATE_URI        = '/_login/activate'
NDB_USERS_LOGIN_PASSWORD_CHANGE_URI = '/_login/password/change'
NDB_USERS_LOGIN_PASSWORD_RESET_URI  = '/_login/password/reset'