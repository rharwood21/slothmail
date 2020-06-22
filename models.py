from slothapp01 import db
from datetime import datetime
from flask_login import UserMixin
from slothapp01 import login
from werkzeug.security import generate_password_hash, check_password_hash
from hashlib import md5
from sqlalchemy import desc
from time import time
import jwt
from slothapp01 import app


penpals = db.Table('penpals',
    db.Column('penpal_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('friended_id', db.Integer, db.ForeignKey('user.id')))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    letters = db.relationship('Letter',backref = 'author', lazy ='dynamic')
    about_me = db.Column(db.String(140))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    friended = db.relationship(
        'User', secondary =penpals,
        primaryjoin=(penpals.c.penpal_id == id),
        secondaryjoin=(penpals.c.friended_id == id),
        backref=db.backref('penpals',lazy='dynamic'), lazy='dynamic'
    )

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)

    def __repr__(self):
        return '<User {}>'.format(self.username)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    

    #functions for user "penpals" database, may need to 
    #rename friend/unfriend action with zuck and all
    def friend(self, user):
        if not self.is_friends_with(user):
            self.friended.append(user)
    def unfriend(self, user):
        if self.is_friends_with(user):
            self.friended.remove(user)
    def is_friends_with(self, user):
        return self.friended.filter(penpals.c.friended_id == user.id).count()>0



    def followed_letters(self, sender):
        #page = request.args.get('page',1,type=int)
        letters = db.session.query(Letter).order_by(desc(Letter.timestamp)) #.paginate(page, 4, False)
        followed_letters = []
        for letter in letters:
            if letter.recipient == self.username:
                followed_letters.append(letter)
            if letter.user_id == self.id:
                followed_letters.append(letter)
        return followed_letters
    def penpal_letters(self, user):
        letters = db.session.query(Letter).order_by(desc(Letter.timestamp)) #.paginate(page, 4, False)
        penpal_letters = []
        for letter in letters:
            if (letter.recipient == self.username) and (letter.author.username == user) :
                penpal_letters.append(letter)
            if (letter.recipient == user) and (letter.author.username == self.username):
                penpal_letters.append(letter)
        return penpal_letters


        #followed = Letter.query.join(penpals, (penpals.c.friended_id == Letter.user_id)).filter(
        #                       penpals.c.friended_id == self.id)
        #own= Letter.query.filter_by(user_id=self.id)
        #return followed.union(own).order_by(Letter.timestamp.desc())
        
        #later for requiring friendship to send letters
        #join(
         #   penpals, (penpals.c.friended_id == Letter.user_id)).filter(
          #      penpals.c.penpal_id == self.id).order_by(Letter.timestamp.desc())

#password reset token generation and verification
    def get_reset_password_token(self, expires_in=800):
        return jwt.encode(
            {'reset_password' : self.id, 'exp': time()+expires_in},
            slothapp01.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, slothapp01.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)
        
class Letter(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(1000))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient = db.Column(db.String(32))

    def __repr__(self):
        return '<Letter {}>'.format(self.body)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))



