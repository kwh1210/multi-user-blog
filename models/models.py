from google.appengine.ext import db
import hashlib


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

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    author = db.ReferenceProperty(User,collection_name='user_posts',
                                        required= True)
    likes = db.StringListProperty(required= True)


class Comment(db.Model):
    post_id = db.StringProperty(required = True)
    comment_content = db.TextProperty(required = True)
    comment_author = db.StringProperty(required= True)
    created = db.DateTimeProperty(auto_now_add = True)