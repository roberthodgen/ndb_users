"""

Requires `requests` be installed.

```
pip install requests
```


"""

import requests

import urllib2

import re

import random

import string

import json

HOSTNAME = 'http://localhost:8080'
USER_EMAIL = str.join('', [''.join(random.SystemRandom().sample(''.join([string.digits,
      string.letters]), 8)), '@example.com'])
USER_PASSWORD = ''.join(random.SystemRandom().sample(''.join([string.digits,
      string.letters, string.punctuation]), 8))

COOKIES = {}

endpoints = {
    'get_user': {
        'name': 'Get current user.',
        'method': 'GET',
        'url': str.join('', [HOSTNAME, '/_login.json']),
        'assert': {
            'user': {}
        }
    }, 'log_in_user': {
        'name': 'Log in user.',
        'method': 'POST',
        'url': str.join('', [HOSTNAME, '/_login.json']),
        'data': {
            'email': USER_EMAIL,
            'password': USER_PASSWORD
        }, 'assert': {
            'user': {}
        }
    }, 'log_out_user': {
        'name': 'Log out user.',
        'method': 'GET',
        'url': str.join('', [HOSTNAME, '/_login.json']),
        'assert': {
            'user': {}
        }
    }, 'create_user': {
        'name': 'Create user account.',
        'method': 'POST',
        'url': str.join('', [HOSTNAME, '/_login/create.json']),
        'data': {
            'email': USER_EMAIL,
            'password': USER_PASSWORD
        }, 'assert': {
            'user': {}
        }
    }
}


def create_user():
    """ Create a new User. """
    endpoint = endpoints['create_user']
    r = requests.post(endpoint['url'], data=json.dumps(endpoint['data']))
    print '===================================================================='
    print str.join('', ['-- New request: ', endpoint['name']])
    print str.join('', ['-- URL: ', r.url])
    print str.join('', ['-- HTTP Status Code: ', str(r.status_code)])
    assert r.status_code == 200
    COOKIES['user_session_id'] = r.cookies['user_session_id']
    print str.join('', ['-- user_session_id: ', r.cookies['user_session_id']])
    response = r.json()
    print str.join('', ['-- JSON Response Object: ', json.dumps(response)])
    for required_key in endpoint['assert']:
        print str.join('', ['---- Assert: `', required_key, '` property ', str(type(endpoint['assert'][required_key]))])
        assert isinstance(response, type(endpoint['assert'][required_key]))
        assert required_key in response


def get_user():
    """ Get the current User. """
    endpoint = endpoints['get_user']
    r = requests.get(endpoint['url'], cookies=COOKIES)
    print '===================================================================='
    print str.join('', ['-- New request: ', endpoint['name']])
    print str.join('', ['-- URL: ', r.url])
    print str.join('', ['-- HTTP Status Code: ', str(r.status_code)])
    assert r.status_code == 200
    response = r.json()
    print str.join('', ['-- JSON Response Object: ', json.dumps(response)])
    for required_key in endpoint['assert']:
        print str.join('', ['---- Assert: `', required_key, '` property ', str(type(endpoint['assert'][required_key]))])
        assert isinstance(response, type(endpoint['assert'][required_key]))
        assert required_key in response


def log_out_user():
    """ Log out the user. """
    endpoint = endpoints['log_out_user']
    r = requests.get(endpoint['url'], params={'action': 'logout'}, cookies=COOKIES)
    print '===================================================================='
    print str.join('', ['-- New request: ', endpoint['name']])
    print str.join('', ['-- URL: ', r.url])
    print str.join('', ['-- HTTP Status Code: ', str(r.status_code)])
    assert r.status_code == 200
    response = r.json()
    print str.join('', ['-- JSON Response Object: ', json.dumps(response)])
    for required_key in endpoint['assert']:
        print str.join('', ['---- Assert: `', required_key, '` property ', str(type(endpoint['assert'][required_key]))])
        assert isinstance(response, type(endpoint['assert'][required_key]))
        assert required_key in response


def log_in_user():
    """ Log in a new User. """
    endpoint = endpoints['log_in_user']
    r = requests.post(endpoint['url'], data=json.dumps(endpoint['data']))
    print '===================================================================='
    print str.join('', ['-- New request: ', endpoint['name']])
    print str.join('', ['-- URL: ', r.url])
    print str.join('', ['-- HTTP Status Code: ', str(r.status_code)])
    assert r.status_code == 200
    COOKIES['user_session_id'] = r.cookies['user_session_id']
    print str.join('', ['-- user_session_id: ', r.cookies['user_session_id']])
    response = r.json()
    print str.join('', ['-- JSON Response Object: ', json.dumps(response)])
    for required_key in endpoint['assert']:
        print str.join('', ['---- Assert: `', required_key, '` property ', str(type(endpoint['assert'][required_key]))])
        assert isinstance(response, type(endpoint['assert'][required_key]))
        assert required_key in response


# CREATE USER
create_user()

# GET CURRENT USER
get_user()

# LOG OUT USER
log_out_user()

# LOG IN USER
log_in_user()

# GET CURRENT USER
get_user()
