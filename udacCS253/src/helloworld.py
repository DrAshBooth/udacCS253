
# -*- coding: utf-8 -*-

from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db

import os
import re
import webapp2
import jinja2
import cgi
import hashlib
import hmac
import random
import string
import urllib2 
from xml.dom import minidom
import json
import logging
import datetime

from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

SECRET = "EDCBA"

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
    
########### DB Stuff #############

def blog_key(name="default"):
    return db.Key.from_path('blogs', name)

def users_key(group="default"):
    return db.Key.from_path('users', group)

# wiki stuff
def Page_key(name='default'):
    return db.Key.from_path('Pages', name)

class Page(db.Model):
    url = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class Artwork(db.Model):
    title = db.StringProperty(required=True)
    art = db.TextProperty(required=True)
    coords = db.GeoPtProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)
    
    def as_dict(self):
        time_fmt = '%c'
        d = {'subject' : self.subject,
             'content' : self.content,
             'created' : self.created.strftime(time_fmt),
             'last_modified' : self.last_modified.strftime(time_fmt) }
        return d
    
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())
    
    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u
    
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)
    
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

####### Memcache Stuff ###########

def age_set(key, val):
    save_time = datetime.datetime.utcnow()
    memcache.set(key, (val, save_time))
    
def age_get(key):
    r = memcache.get(key)
    if r:
        val, save_time = r
        age = (datetime.datetime.utcnow() - save_time).total_seconds()
    else:
        val, age = None, 0
    return val, age

####### Blog functions ###########

def add_post(post):
    post.put()
    get_posts(update=True)
    return str(post.key().id())

def get_posts(update=False):
    q = Post.all().order('-created').fetch(limit=10)
    mc_key = 'BLOGS'
    posts, age = age_get(mc_key)
    if update or posts is None:
        posts = list(q)
        age_set(mc_key, posts)
    return posts, age

def age_str(age):
    s = 'queried %s seconds ago'
    age = int(age)
    if age == 1: s.replace('seconds', 'second')
    return s % age

##################################

class BaseHandler(webapp2.RequestHandler):
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)
        
    def get_coords(self, ip):
        IP_URL = "http://api.hostip.info/?ip="
        url = IP_URL + ip
        content = None
        try:
            content = urllib2.urlopen(url).read()
        except:
            return
        if content:
            m = minidom.parseString(content)
            coords = m.getElementsByTagName('gml:coordinates')
            if coords and coords[0].childNodes[0].nodeValue:
                lon, lat = coords[0].childNodes[0].nodeValue.split(',')
                return db.GeoPt(lat, lon)
        
class BlogHandler(BaseHandler):
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', "%s=%s; Path=/" % (name, cookie_val))
        
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
        
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))
        
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        
        if self.request.url.endswith('.json'):
            self.format = 'json'
        else: self.format = 'html'
        
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
        
def top_arts(update=False):
    key = 'top'
    arts = memcache.get(key)
    if arts is None or update:
        logging.error("DB QUERY")
        arts = db.GqlQuery("SELECT * FROM Artwork ORDER BY created DESC")
        # prevent the running of multiple queries
        arts = list(arts)
        memcache.set(key, arts)
    return arts 
        
class AsciiFront(BaseHandler):
    def gmaps_img(self, points):
        img_url = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
        if points:
            for p in points:
                img_url += "markers=%s,%s&" % (p.lat, p.lon)
            img_url = img_url[:-1]
            return img_url 
    
    def render_front(self, title="", art="", error=""):
        arts = top_arts()
        # finds which arts have coords
        points = filter(None, (a.coords for a in arts))
        # if we have any arts coords, make an image url
        image_url = None
        if points:
            image_url = self.gmaps_img(points)
        # display the image url
        self.render("ascii-chan-frontpage.html", title=title, art=art, error=error,
                    arts=arts, image_url=image_url)
        
    def get(self):
        self.render_front()
        
    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")
        if title and art:
            a = Artwork(title=title, art=art)
            # lookup users coordinates with ip
            coords = self.get_coords(self.request.remote_addr)
            # if we have coords add them to the art
            if coords:
                a.coords = coords
            a.put()
            # Re-run the query and update the cache
            top_arts(update=True)
            self.redirect("/unit2/asciichan")
        else:
            error = "Must enter both a title ad some artwork!"
            self.render_front(title, art, error)
            
class BlogFront(BlogHandler): 
    def render_front(self):
        posts, age = get_posts()
        if self.format == 'html':
            self.render("blog-frontpage.html", posts=posts, age=age_str(age))
        else:
            return self.render_json([p.as_dict() for p in posts])
        
    def get(self):
        self.render_front()
        
class PostPage(BlogHandler):
    def get(self, post_id):
        post_key = 'POST_' + post_id
        post, age = age_get(post_key)
        if not post:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            age_set(post_key, post)
            age = 0
        if not post:
            self.error(404)
            return
        if self.format == 'html':
            self.render("permalink.html", post=post, age=age_str(age))
        else:
            self.render_json(post.as_dict())
            
class FlushHandler(BlogHandler):
    def get(self):
        memcache.flush_all()
        self.redirect("/")

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
            self.redirect('/' + str(b.key().id()))
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

class Signup(BlogHandler):
    def valid_username(self, username):
        return username and USER_RE.match(username)
    
    def valid_password(self, password):
        return password and PASS_RE.match(password)
    
    def valid_email(self, email):
        return not email or EMAIL_RE.match(email)
    
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

        if not self.valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not self.valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not self.valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            # check user isn't already registered
            u = User.by_name(username)
            if u:
                msg = "That username is already registered"
                self.render('signup-form.html', error_username=msg)
            else:
                u = User.register(username, password, email)
                u.put()
                self.login(u)
                self.redirect('/welcome')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')
            
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = "Invalid Login!"
            self.render('login-form.html', error=msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')
        
class EditPage(BlogHandler):
    def get(self, page_name):
        if self.user:
            self.render("edit.html")
        else:
            self.redirect("/login")

    def post(self, page_name):
        if not self.user:
            self.redirect('/signup')
        content = self.request.get('content')
        if content:
            p = Page(parent=Page_key(), url=page_name, content=content)
            p.put()
            self.redirect('%s' % str(page_name))
        else:
            error = "content, please!"
            self.render("edit.html", content=content, error=error)
            
class WikiPage(BlogHandler):
    def get(self, page_name):
        ver = self.request.get("v")
        if ver:
            key = db.Key.from_path('Page', int(ver), parent=Page_key())
            page = db.get(key)
        else:
            page = db.GqlQuery("SELECT * FROM Page WHERE url = :url ORDER BY created DESC LIMIT 1", url=page_name).get()
        if page:
            self.render('page.html', content=page.content, url=page_name)
        if not page and self.user:
            self.redirect('/_edit' + page_name)
        if not page and not self.user:
            self.redirect('/login')
            
class HistoryPage(BlogHandler):
    def get(self, page_name):
        pages = Page.all().filter("url =", page_name).order("-created")
        if pages:
            self.render('page_history.html', pages=pages)
        if not pages and self.user:
            self.redirect('/_edit' + page_name)
        if not pages and not self.user:
            self.redirect('/login')

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/?(?:\.json)?', BlogFront),
                               ('/([0-9]+)(?:\.json)?', PostPage),
                               ('/newpost', NewPostBlog),
                               ('/signup', Signup),
                               ('/flush', FlushHandler),
                               ('/welcome', Unit3Welcome),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, HistoryPage),
                               (PAGE_RE, WikiPage),
                               ('/unit2/asciichan', AsciiFront),
                               ('/unit2/rot13', Rot13Handler)],
                              debug=True)

def main():
    run_wsgi_app(app)

if __name__ == "__main__":
    main()
