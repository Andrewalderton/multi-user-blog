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
import webapp2

from google.appengine.ext import db

# Jinja setup
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = "ghudhhsixi6skja$ty12DSzoaplrjvbd"


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Model keys
def users_key(group='default'):
    return db.Key.from_path('users', group)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Username and password validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


def valid_password(password):
    return password and PASS_RE.match(password)


# Authentication
def make_pw_hash(name, password, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + password + salt).hexdigest()
    return '%s,%s' % (salt, h)

def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    u = make_pw_hash(name, password, salt)
    return hmac.compare_digest(str(h), str(u))

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    make_val = make_secure_val(val)
    if hmac.compare_digest(secure_val, make_val):
        return val


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val)
        )

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)

    @classmethod
    def register(cls, name, pw):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash)

    @classmethod
    def login(cls, username, password):
        u = User.by_name(username)
        if u and valid_pw(username, password, u.pw_hash):
            return u

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter("name =", name).get()
        return u


# Register new users and redirect to welcome page
class SignUp(Handler):
    def get(self):
        self.render("sign-up.html")

    def post(self):
        have_error = False
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")

        params = dict(username=self.username)

        if not valid_username(self.username):
            params["error_username"] = "That is not a valid username."
            have_error = True

        if not valid_password(self.password):
            params["error_password"] = "That wasn't a valid password."
            have_error = True

        elif self.password != self.verify:
            params["error_verify"] = "Your passwords didn't match."
            have_error = True

        if have_error:
            self.render("sign-up.html", **params)
        else:
            self.done()

    def done(self):
        # Make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = "That user already exists."
            self.render("sign-up.html", error_username=msg)
        else:
            u = User.register(self.username, self.password)
            u.put()
            self.login(u)
            self.redirect('/welcome')


# Welcome page displayed after SignUp success
class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/sign-up')


class Post(db.Model):
    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.StringProperty(required=True)
    likes_total = db.IntegerProperty(required=True)

    def render(self, user_id):
        key = db.Key.from_path('User', int(user_id), parent=users_key())
        user = db.get(key)

        self._render_text = self.body.replace('\n', '<br>')
        return render_str("post.html", post=self, user=user)


class NewPost(Handler):
    def get(self):
        if not self.user:
            self.redirect('/login')
        else:
            self.render("new-post.html")

    def post(self):
        title = self.request.get("title")
        body = self.request.get("body")
        author = self.user.name

        if title and body:
            post = Post(parent=blog_key(), title=title, body=body, author=author, likes_total=0)
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "Title and content, please!"
            self.render("new-post.html", title=title, body=body, error=error)


class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = Comment.all().ancestor(key).order('-created')

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, comments=comments)


class MainPage(Handler):
    def get(self):
        posts = Post.all().order('-created')
        self.render("front.html", posts=posts)


class LoginPage(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        u = User.login(username, password)

        if u:
            self.login(u)
            self.redirect('/')

        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class LogOut(Handler):
    def get(self):
        self.logout()
        self.redirect('/')


class EditPost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.name == post.author:
            self.render('edit-post.html', title=post.title,
                        body=post.body, author=post.author, post_id=post_id)
        elif not self.user:
            self.redirect('/login')
        else:
            error = "You can't edit other users' posts!"
            self.render("permalink.html", post=post, error=error)

    def post(self, post_id):
        title = self.request.get("title")
        body = self.request.get("body")

        if title and body:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            post.title = title
            post.body = body
            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "Title and Content both required to update."
            self.render("edit-post.html", title=title,
                        body=body, error=error)


class DeletePost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        cookie = self.request.cookies.get("user_id")
        val = check_secure_val(cookie)
        u = User.by_id(int(val))

        if post.author == u.name:
            post.delete()
            self.redirect('/')

        elif u.name:
            error = "You can't delete other users' posts!"
            self.render("permalink.html", post=post, error=error)
        else:
            self.redirect('/login')


class Comment(db.Model):
    post = db.ReferenceProperty(Post, collection_name='comments')
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_name = db.TextProperty(required=True)
    user_id = db.IntegerProperty(required=True)


class AddComment(Handler):
    def get(self, post_id):
        if not self.user:
            self.redirect('/login')

        self.render("add-comment.html")

    def post(self, post_id):
        comment = self.request.get("comment")

        cookie = self.request.cookies.get("user_id")
        val = check_secure_val(cookie)
        u = User.by_id(int(val))

        if comment and u:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            user_name = str(u.name)
            c = Comment(parent=key, comment=comment,
                        user_name=user_name, user_id=int(val))
            c.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "Please add a comment."
            self.render("add-comment.html", comments=comment, error=error)


class EditComment(Handler):
    def get(self, post_id, user_id, comment_id):
        if self.user and self.user.key().id() == int(user_id):
            post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=post_key)
            comment = db.get(key)

            self.render('edit-comment.html', comment=comment.comment)

        elif not self.user:
            self.redirect('/login')
        else:
            self.write("You can't edit other users' comments!")

    def post(self, post_id, user_id, comment_id):
        if self.user and self.user.key().id() == int(user_id):
            new_comment = self.request.get("comment")

            post_key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            key = db.Key.from_path('Comment', int(comment_id), parent=post_key)
            comment = db.get(key)

            comment.comment = new_comment
            comment.put()
            self.redirect('/blog/%s' % str(post_id))

        else:
            self.write("You can't edit other users' comments!")


class Likes(db.Model):
    like = db.ReferenceProperty(Post, collection_name='likes')
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class LikePost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.name == post.author:
            error = "You can't like your own post."
            self.render("permalink.html", post=post, error=error)

        elif not self.user:
            self.redirect('/login')

        else:
            user_id = self.user.key().id()
            likes = Likes.all().filter('user_id =', user_id).ancestor(key).get()

            if likes:
                self.redirect('/blog/' + str(post.key().id()))
            else:
                likes = Likes(parent=key,
                              user_id=self.user.key().id(),
                              post_id=post.key().id())

                post.likes_total += 1
                likes.put()
                post.put()

                self.redirect('/blog/' + str(post.key().id()))


class UnlikePost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and self.user.name == post.author:
            error = "You can't unlike your own post."
            self.render("permalink.html", post=post, error=error)

        elif not self.user:
            self.redirect('/login')

        else:
            user_id = self.user.key().id()
            likes = Likes.all().filter('user_id =', user_id).ancestor(key).get()

            if likes:
                likes.delete()
                post.likes_total -= 1
                post.put()

                self.redirect('/blog/' + str(post.key().id()))
            else:
                self.redirect('/blog/' + str(post.key().id()))


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/login', LoginPage),
    ('/log-out', LogOut),
    ('/sign-up', SignUp),
    ('/welcome', Welcome),
    ('/new-post', NewPost),
    ('/blog/([0-9]+)', PostPage),
    ('/edit-post/([0-9]+)', EditPost),
    ('/delete/([0-9]+)', DeletePost),
    ('/([0-9]+)/add-comment', AddComment),
    ('/([0-9]+)/edit-comment/([0-9]+)/([0-9]+)', EditComment),
    ('/([0-9]+)/like-post', LikePost),
    ('/([0-9]+)/unlike-post', UnlikePost)
], debug=True)
