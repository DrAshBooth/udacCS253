
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

class BaseHandler(webapp2.RequestHandler):
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
class MainPage(BaseHandler): 
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        visits = 0
        visit_cookie_str = self.request.cookies.get('visits', 0)
        if visit_cookie_str:
            cookie_val = check_secure_val(visit_cookie_str)
            if cookie_val:
                visits = int(cookie_val)
        visits += 1
        new_cookie_val = make_secure_val(str(visits))
        self.response.headers.add_header('Set-Cookie', "visits=%s" % new_cookie_val)
        if visits > 150:
            self.write("Awesome!")
        else:
            self.write("You have been here {} times!".format(visits))
      
    def post(self):
        the_string = self.request.get('text')
        self.write_form(the_string)

        
class Artwork(db.Model):
    title = db.StringProperty(required=True)
    art = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
        
class AsciiFront(BaseHandler): 
    def render_front(self, title="", art="", error=""):
        arts = db.GqlQuery("SELECT * FROM Artwork ORDER BY created DESC")
        self.render("ascii-chan-frontpage.html", title=title, art=art, error=error, arts=arts)
        
    def get(self):
        self.render_front()
        
    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")
        if title and art:
            a = Artwork(title=title, art=art)
            a.put()
            self.redirect("/unit2/asciichan")
        else:
            error = "Must enter both a title ad some artwork!"
            self.render_front(title, art, error)
            
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)
    
def blog_key(name="default"):
    return db.Key.from_path('blogs', name)
            
class BlogFront(BaseHandler): 
    def render_front(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")
        self.render("blog-frontpage.html", posts=posts)
        
    def get(self):
        self.render_front()
        
class PostPage(BaseHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        self.render("permalink.html", p=post)

class NewPostBlog(BaseHandler):
    def render_form(self, subject="", content="", error=""):
        self.render("blog-newpost.html", subject=subject, content=content, error=error)
    
    def get(self):
        self.render_form()
    
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            b = Post(parent=blog_key(), subject=subject, content=content)
            b.put()
            self.redirect('/unit2/blog/' + str(b.key().id()))
        else:
            error = "Must enter both subject and content please!"
            self.render_form(subject, content, error)
        
class Rot13Handler(BaseHandler):
    def get(self):
        self.render('rot13-form.html')
        
    def escape_html(self, s):
        return cgi.escape(s, quote=True)
    
    def get_rot13(self, s):
        s = unicode(s)
        intab = u"ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz"
        outtab = u"NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
        trantab = dict((ord(a), b) for a, b in zip(intab, outtab))
        s = s.translate(trantab)
        return self.escape_html(s)
      
    def post(self):
        the_string = self.request.get('text')
        if the_string:
            rot13 = self.get_rot13(the_string)
        self.render('rot13-form.html', text=rot13)
        
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BaseHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.redirect('/unit2/welcome?username=' + username)

class Welcome(BaseHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username=username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/blog/?', BlogFront),
                               ('/unit2/blog/([0-9]+)', PostPage),
                               ('/unit2/blog/newpost', NewPostBlog),
                               ('/unit2/asciichan', AsciiFront),
                               ('/unit2/rot13', Rot13Handler),
                               ('/unit2/signup', Signup),
                               ('/unit2/welcome', Welcome)],
                              debug=True)

def main():
    run_wsgi_app(app)

if __name__ == "__main__":
    main()
