import webapp2
import jinja2
import hashlib
import os
import re
import cgi
import hashlib
import hmac
import random
import string
import time

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                                autoescape=True)

from google.appengine.ext import db

SECRET = "FUCKYOU"

COOKIE_RE = re.compile(r'.+=;\s*Path=/')
def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)



# All about making password safe and hasing and etc.
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    hash = h.split(',')[0]
    print salt
    print hash
    if h == '%s,%s' % (hashlib.sha256(name+pw+salt).hexdigest(),salt):
        return 1
    else:
        return 0


def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    ###Your code here
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val



def escape_html(s):
    return cgi.escape(s, quote = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PWD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PWD_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.out.write(*a,**kw)

    def render_str(self,template,**params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

    def set_cookie(self,name,val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                    '%s=%s; Path=/' % (name,cookie_val))

    def read_cookie(self,name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val and check_secure_val(cookie_val):
            return cookie_val


class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.StringProperty(required= True)
    likes = db.StringListProperty(required= True)

class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_name(cls,name):
        u = User.all().filter('username =',name).get()
        return u

    @classmethod
    def register(cls,name,pw,email=None):
        user = User(username= name,pw_hash=pw,email=email)
        return user

    @classmethod
    def login(cls,name,pw):
        if User.by_name(name):
            return valid_pw(name,pw,User.by_name(name).pw_hash)


class Blog(Handler):
    def get(self):
        self.render_front()

    def render_front(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        #print "post is = ",posts.get().subject
        self.render("front.html",posts = posts)


class NewEntry(Handler):
    def render_newpost(self,subject="",content="",error=""):
        self.render("newentry.html",subject=subject,content=content,error=error)

    def get(self):
        #lets first check if the person is logged in by checking cash
        #if cash is valid let them proceed, if not tell them to log in
        username_fromcookie = self.request.cookies.get('user')
        if username_fromcookie:
            user_cookie = check_secure_val(username_fromcookie)
            if user_cookie:
                self.render_newpost()
            else:
                self.redirect("/blog/login")
        else:
            self.redirect("/blog/login")

    def post(self):

        username_fromcookie = self.request.cookies.get('user')

        author = check_secure_val(username_fromcookie)
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            post = Post(subject = subject, content = content,author = author,likes=list())
            post.put()
            id = post.key().id();
            print str(id)
            self.redirect("/blog/%d"%id)
        else:
            error = "Your content is either empty or shit!"
            self.render_newpost(subject=subject,content=content,error=error)

class SignupPage(Handler):
    def get(self):
        self.render_front()

    def render_front(self,name="",email="",nameErr="",pwdErr=""
                        ,pwdNoMatch="",emailErr="",duplicate=""):
        self.render("signup.html", name = name,
                                  email = email,
                                  nameInvalid = nameErr,
                                  pwdInvalid = pwdErr,
                                  pwdNotMatch = pwdNoMatch,
                                  emailInvalid = emailErr,
                                  duplicate = duplicate)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        userValid = valid_username(username)
        pwdValid = valid_password(password)
        emailValid = valid_email(email)
        verifyValid = (verify == password)

        if not userValid:
            nameinvalid = "username is not valid."
        else:
            nameinvalid =""
        if not pwdValid:
            pwdinvalid = "password is not valid"
        else:
            pwdinvalid = ""
        if not verifyValid:
            verifyinvalid = "password dont match"
        else:
            verifyinvalid = ""
        if not emailValid:
            emailinvalid = "email is not valid"
        else:
            emailinvalid =""
        if not(userValid and pwdValid and verifyValid and emailValid):
            self.render_front(username,email,nameinvalid,pwdinvalid,
                                        verifyinvalid,emailinvalid)
        else:
            if User.by_name(username):
                self.render_front(username,email,nameinvalid,pwdinvalid,
                            verifyinvalid,emailinvalid,"duplicate dude")
            else :
                u = User.register(username,make_pw_hash(username,password),email)
                u.put()
                self.response.headers.add_header('Set-Cookie',
                            'user=%s; Path=/' % make_secure_val(str(username)))
                self.redirect("/blog/welcome")

class WelcomeHandler(Handler):
    def get(self):
        username_fromcookie = self.request.cookies.get('user')
        if username_fromcookie:
            user_cookie = check_secure_val(username_fromcookie)
            if user_cookie:
                self.render("welcome.html",user_cookie=user_cookie)
            else:
                self.redirect("/blog/signup")
        else:
            self.redirect("/blog/signup")


class LoginHandler(Handler):
    def get(self):
        self.render_front()

    def render_front(self,invalid=""):
        self.render("login.html",invalid=invalid)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        if not(User.login(username,password)):
            self.render_front(invalid="invalid")
        else:
            self.response.headers.add_header('Set-Cookie','user=%s ; Path=/'
                                            % make_secure_val(str(username)))
            self.redirect("/blog/welcome")

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie','user=; Path=/')
        self.redirect("/blog")


class Permalink(Handler):
    def get(self,id):
        newpost = Post.get_by_id(int(id))
        #print "newpost is == ",newpost
        newpost_subject =newpost.subject
        newpost_content = newpost.content
        newpost_created = newpost.created
        newpost_author = newpost.author
        newpost_likes = newpost.likes
        self.render("front.html",id=id,newpost_subject=newpost_subject,
                                        newpost_content=newpost_content,
                                        newpost_created=newpost_created,
                                        newpost_author=newpost_author,
                                        newpost_likes = len(newpost.likes))


class EditEntry(Handler):
    def render_newpost(self,subject="",content="",error="",id=""):
        self.render("newentry.html",subject=subject,content=content,error=error,id=id)

    def get(self,id):
        currentUser_cookie = self.request.cookies.get('user')
        if currentUser_cookie:
            currentUser = check_secure_val(currentUser_cookie)
            currentPost = Post.get_by_id(int(id))
            currentPostUser = currentPost.author
            if currentPostUser == currentUser:
                self.render_newpost(subject=currentPost.subject,content=currentPost.content,id=id)
            else:
                PermissionDenied = "Permission Denied."
                self.render("front.html",id=id,
                                        newpost_subject=currentPost.subject,
                                        newpost_content=currentPost.content,
                                        newpost_created=currentPost.created,
                                        newpost_author=currentPost.author,
                                        PermissionDenied = PermissionDenied,
                                        newpost_likes = len(currentPost.likes),
)
        else:
            self.redirect("/blog/login")

    def post(self,id):

        username_fromcookie = self.request.cookies.get('user')
        currentPost = Post.get_by_id(int(id))


        author = check_secure_val(username_fromcookie)
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            currentPost.content = content
            currentPost.subject = subject
            currentPost.put()
            id = currentPost.key().id();
            print str(id)
            self.redirect("/blog/%d"%id)
        else:
            error = "put something decent here man! your content is either empty or shit!"
            self.render_newpost(subject=subject,content=content,error=error)

class Delete(Handler):
    def get(self,id):

        currentUser_cookie = self.request.cookies.get('user')
        if currentUser_cookie:
            currentUser = check_secure_val(currentUser_cookie)
            currentPost = Post.get_by_id(int(id))
            currentPostUser = currentPost.author
            if currentPostUser == currentUser:
                currentPost.delete()
                self.response.out.write("Delete complete!")
            else:
                PermissionDenied = "Permission Denied."
                self.render("front.html",id=id,
                                newpost_subject=currentPost.subject,
                                newpost_content=currentPost.content,
                                newpost_created=currentPost.created,
                                newpost_author=currentPost.author,
                                PermissionDenied = PermissionDenied,
                                newpost_likes = len(currentPost.likes),
)
        else:
            self.redirect("/blog/login")


class Comment(db.Model):
    post_id = db.StringProperty(required = True)
    comment_content = db.TextProperty(required = True)
    comment_author = db.StringProperty(required= True)
    created = db.DateTimeProperty(auto_now_add = True)

class AddComment(Handler):
    def get(self,id):
        comments = db.GqlQuery("select * from Comment where post_id = '%s' order by created desc"%id)
        self.render("comments.html",id=id,Comments = comments)


    def post(self,id):
        currentUser_cookie = self.request.cookies.get('user')
        if currentUser_cookie:
            currentUser = check_secure_val(currentUser_cookie)
            if currentUser:
                comment_content =self.request.get('comment')
                if comment_content:
                    comment = Comment(post_id = id, comment_content = comment_content,
                                                        comment_author = currentUser)
                    comment.put()
                    time.sleep(.5)
                    self.redirect("/blog/%d/comment"%int(id))
                else:
                    error = "You need to put some comment here"
                    comments = db.GqlQuery("select * from Comment where post_id = '%s'"%id)
                    self.render("comments.html",id=id,Comments = comments,Error=error)
            else:
                self.redirect("/blog/login")
        else:
            self.redirect("/blog/login")

class EditComment(Handler):
    def get(self,id1,id2):
        currentUser_cookie = self.request.cookies.get('user')
        if currentUser_cookie:
            currentUser = check_secure_val(currentUser_cookie)
            currentComment = Comment.get_by_id(int(id2))
            currentCommentUser = currentComment.comment_author
            if currentComment.comment_author == currentUser:
                self.render("comment_edit.html",comment=currentComment)
            else:
                self.response.out.write("Permission Denied")
        else:
            self.redirect("/blog/login")

    def post(self,id1,id2):
        username_fromcookie = self.request.cookies.get('user')
        currentComment = Comment.get_by_id(int(id2))


        content = self.request.get("content")

        if content:
            currentComment.comment_content = content
            currentComment.put()
            time.sleep(.5)
            self.redirect("/blog/%s/comment"%id1)
        else:
            error = "Put new comment!"
            self.render("comment_edit.html",comment=currentComment,Error=error)


class DelComment(Handler):
    def get(self,id1,id2):
        currentUser_cookie = self.request.cookies.get('user')
        if currentUser_cookie:
            currentUser = check_secure_val(currentUser_cookie)
            currentComment = Comment.get_by_id(int(id2))
            currentCommentUser = currentComment.comment_author
            if currentComment.comment_author == currentUser:
                currentComment.delete()
                time.sleep(.5)
                self.redirect("/blog/%s/comment"%id1)
            else:
                self.response.out.write("Permission Denied")
        else:
            self.redirect("/blog/login")

class LikePost(Handler):
    def get(self,id):
        currentUser_cookie = self.request.cookies.get('user')
        if currentUser_cookie:
            currentUser = check_secure_val(currentUser_cookie)
            currentPost = Post.get_by_id(int(id))
            if currentPost.author != currentUser and currentUser not in currentPost.likes:
                currentPost.likes.append(currentUser)
                currentPost.put()
                time.sleep(.5)
                self.redirect("/blog/%s"%id)
            else:
                newpost = Post.get_by_id(int(id))
                newpost_subject = newpost.subject
                newpost_content = newpost.content
                newpost_created = newpost.created
                newpost_author = newpost.author
                newpost_likes = newpost.likes
                PermissionDenied = "you either have already liked it or it's your post."
                self.render("front.html",id=id,newpost_subject=newpost_subject,
                                                newpost_content=newpost_content,
                                                newpost_created=newpost_created,
                                                newpost_author=newpost_author,
                                                newpost_likes = len(newpost.likes),
                                                PermissionDenied = PermissionDenied)
        else:
            self.redirect("/blog/login")

class UnlikePost(Handler):
    def get(self,id):
        currentUser_cookie = self.request.cookies.get('user')
        if currentUser_cookie:
            currentUser = check_secure_val(currentUser_cookie)
            currentPost = Post.get_by_id(int(id))
            if currentUser in currentPost.likes:
                currentPost.likes.remove(currentUser)
                currentPost.put()
                time.sleep(.5)
                self.redirect("/blog/%s"%id)
            else:
                newpost = Post.get_by_id(int(id))
                newpost_subject = newpost.subject
                newpost_content = newpost.content
                newpost_created = newpost.created
                newpost_author = newpost.author
                newpost_likes = newpost.likes
                PermissionDenied = "You cannot unlike this because you've never liked it in the first place asshole!"
                self.render("front.html",id=id,newpost_subject=newpost_subject,
                                                newpost_content=newpost_content,
                                                newpost_created=newpost_created,
                                                newpost_author=newpost_author,
                                                newpost_likes = len(newpost.likes),
                                                PermissionDenied = PermissionDenied)
        else:
            self.redirect("/blog/login")




app = webapp2.WSGIApplication([('/blog',Blog),
                               ('/blog/newpost',NewEntry),
                               ('/blog/(\d+)',Permalink),
                               ('/blog/signup', SignupPage),
                               ('/blog/welcome',WelcomeHandler),
                               ('/blog/login',LoginHandler),
                               ('/blog/logout',LogoutHandler),
                               ('/blog/(\d+)/edit',EditEntry),
                               ('/blog/(\d+)/delete',Delete),
                               ('/blog/(\d+)/comment',AddComment),
                               ('/blog/(\d+)/comment/(\d+)',EditComment),
                               ('/blog/(\d+)/comment/(\d+)/delete',DelComment),
                               ('/blog/(\d+)/like',LikePost),
                               ('/blog/(\d+)/unlike',UnlikePost)
                               ],debug=True)

