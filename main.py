import os
import webapp2
import jinja2
import string
import sys
import random
import hashlib
import hmac
from string import letters
from google.appengine.ext import db

reload(sys)
sys.setdefaultencoding('utf8')

secret = '4dd4848y175480y'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t= jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def which_nav(self):
        if self.read_secure_cookie('user_id'):
            return True
        else:
            return False


class MainPage(Handler):

    def get(self):
        posts = Article.all().order('-date')
        self.render("main.html", user = self.user, articles=self.render_str("article-body.html", posts = posts, user=self.user))


class LogIn(Handler):

    def post(self):
        username = self.request.get("name")
        password = self.request.get("password")
        checkuser = User.login(username,password)
        if checkuser:
            self.login(checkuser)
            self.redirect('/')
        else:
            self.render("main.html", nav=self.render_str("nav.html"),
                articles="Incorrect Login information")


    def get(self):
        print("goodbye")


class CreateUser(Handler):

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        confirm = self.request.get("confirm")
        email = self.request.get("email")
        userexists = User.by_name(username)
        error = "";
        if not password == confirm:
            error += "Passwords do not match."
        if userexists:
            error += " Username Exits."
        if not (username and email):
            error += " Please Fill in all fields"

        if error == "":
            hash_pw = make_pw_hash(username, password, make_salt())
            newuser = User(username=username, password=hash_pw, email=email)
            newuser.put()
            checkuser = User.by_name(username)
            self.login(newuser)
            self.redirect('/')

        else:
            self.render("main.html", user = self.user,
                articles=self.render_str("new_user.html", username=username, email=email, error=error))


    def get(self):
        self.render("main.html", user = self.user, articles=self.render_str("new_user.html"))


class CreateArticle(Handler):

    def post(self):

        title = self.request.get("title")
        category = self.request.get("category")
        post = self.request.get("post")
        error=""

        if error == "":
            if self.request.get("edit") != "":
                editarticle = Article.get(self.request.get("edit"))
                editarticle.title=title
                editarticle.category=category
                editarticle.text=post
                editarticle.put()

            else:
                thisarticle = Article(title=title, text=post, author=self.user.username, category=category)
                thisarticle.put()
            self.redirect('/')
        else:
            self.render("main.html",title= title, category=category, post=post, user=self.user, articles=self.render_str("add_new.html"))

    def get(self):
        if self.request.get("id"):
            post = Article.get(self.request.get("id"))
            self.render("main.html", user=self.user, articles=self.render_str("add_new.html",
                title=post.title, category=post.category, post=post.text, edit=self.request.get("id")))
        else:
            self.render("main.html", user=self.user, articles=self.render_str("add_new.html"))

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

class Article(db.Model):

    title = db.StringProperty(required = True)
    text = db.TextProperty(required = True)
    author = db.StringProperty(required = True)
    category = db.StringProperty(required = True)
    date = db.DateTimeProperty(auto_now_add = True)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.TextProperty(required = True)
    email = db.StringProperty(required = True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('username =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.password):
            return u


app = webapp2.WSGIApplication([('/', MainPage), ('/create', CreateUser), ('/post', CreateArticle), ('/login',LogIn), ('/logout',Logout)], debug=True)
