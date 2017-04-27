#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import random
import hashlib
import hmac
from string import letters

import jinja2

import sys

import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape=True)

secret = "ghudhh.sixi6,skja$ty12DSzo~aplrjvbd"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def users_key(group='default'):
    return db.Key.from_path('users', group)

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params["user"] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val)
        )

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


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
        name=name,
        pw_hash = pw_hash,
        )

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class MainPage(Handler):
    def get(self):
        # posts = self.request.get_all("posts")
        posts = Post.all().order('-created')
        self.render("front.html", posts=posts)


class Post(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self, title, body, created):
        self._render_text = self.body.replace('\n', '<br>')
        self.render("post.html", title, body, created)


class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(Handler):
    def get(self):
        self.render("new-post.html")

    def post(self):
        title = self.request.get("title")
        body = self.request.get("body")

        if title and body:
            post = Post(parent=blog_key(), title=title, body=body)
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "Title and content, please!"
            self.render("new-post.html", title=title, body=body, error=error)


class SignUp(Handler):
    def done(self):
        # Make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render("sign-up.html", error_username=msg)
        else:
            u = User.register(self.username, self.password)
            u.put()

            self.login(u)
            self.redirect('/welcome')

    def get(self):
        self.render("sign-up.html")

    def post(self):
        have_error = False
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")

        params = dict(username=self.username)

        print(self.username)
        if not valid_username(self.username):
            params["error_username"] = "That is not a valid username."
            have_error = True

        if not valid_password(self.password):
            params["error_password"] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params["error_verify"] = "Your passwords didn't match."

        if have_error:
            self.render("sign-up.html", **params)
        else:
            self.done()

    # def done(self, *a, **kw):
    #     raise NotImplementedError


# class Unit2Signup(SignUp):
#     def done(self):
#         self.redirect('/unit2/welcome?username=' + self.username)


class LoginPage(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/unit3/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)


# class Rot13(Handler):
#     def get(self):
#         self.render("rot13.html")

#     def post(self):
#         rot13 = ''
#         text = self.request.get("text")
#         if text:
#             rot13 = text.encode("rot13")

#         self.render("rot13.html", text=rot13)


class LogOut(Handler):
    def get(self):
        self.logout()
        self.redirect('/sign-up')


# class Unit3Welcome(Handler):
#     def get(self):
#         if self.user:
#             self.render('welcome.html', username=self.username)
#         else:
#             self.redirect('/sign-up')

class Welcome(Handler):
    def get(self):
        username = self.request.get("username")
        if valid_username(username):
            self.render("welcome.html", username=username)
        else:
            self.redirect("/sign-up")


app = webapp2.WSGIApplication([
    ('/', MainPage),
    # ('/unit2/rot13', Rot13),
    ('/login', LoginPage),
    ('/sign-up', SignUp),
    ('/welcome', Welcome),
    # ('/unit3/welcome', Unit3Welcome),
    ('/blog/new-post', NewPost),
    ('/blog/([0-9]+)', PostPage),
    ('/log-out', LogOut)
], debug=True)