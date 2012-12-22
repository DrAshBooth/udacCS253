# -*- coding: utf-8 -*-

from google.appengine.ext.webapp.util import run_wsgi_app

import os
import re

SECRET = "EDCBA"

from google.appengine.ext import db

import webapp2
import jinja2
import cgi
import hashlib
import hmac
import random
import string

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

def render_str(template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)


###### Cookie Encrypting #######
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()
    return hashlib.md5(s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
    
###### Password Encrypting #######
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)
    

##################################

class BlogHandler(webapp2.RequestHandler):
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', "%s=%s; Path=/" % (name, cookie_val))
        
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
        
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))
        
    def logout(self):
        self.response.headers.addheader('Set-Cookie', 'user_id=; Path=/')
        
    def initialise(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        
        
        
        
