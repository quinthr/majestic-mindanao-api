from escapadeApp import db
import datetime


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer(), primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username=db.Column(db.String(32), unique=True,index=True)
    password_hash=db.Column(db.String(128))
    firstname = db.Column(db.String(30))
    middlename = db.Column(db.String(30))
    lastname = db.Column(db.String(30))
    age = db.Column(db.String(5))
    contact = db.Column(db.String(15))
    address = db.Column(db.TEXT())
    birthday = db.Column(db.DATE)
    role_id=db.Column(db.String(2))
    profile = db.Column(db.String(120))
    write = db.relationship('Write', backref='write_User')

class Write(db.Model):
    __tablename__ = 'write'
    write_id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DATE, default=datetime.datetime.now())
    author_id = db.Column(db.Integer,db.ForeignKey('user.id'))
    author_name = db.Column(db.VARCHAR)
    status = db.Column(db.VARCHAR)
    comment = db.Column(db.VARCHAR, nullable=True)
    region = db.relationship('Region', backref='region_Write')
    destination = db.relationship('Destination', backref='destination_Write')
    attraction = db.relationship('Attraction', backref='attraction_Write')

    def __init__(self, author_id='', author_name='', status=''):
        self.author_id = author_id
        self.author_name = author_name
        self.status = status

class Region(db.Model):
    __tablename__ = 'region'
    region_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.VARCHAR)
    content = db.Column(db.VARCHAR)
    photo = db.Column(db.String)
    write_id = db.Column(db.Integer, db.ForeignKey('write.write_id'))
    destination = db.relationship('Destination', backref='destination_Region')
    attraction = db.relationship('Attraction', backref='attraction_Region')

    def __init__(self, name='', content='', photo='', write_id=''):
        self.name = name
        self.content = content
        self.photo = photo
        self.write_id = write_id

class Destination(db.Model):
    __tablename__ = 'destination'
    destination_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.VARCHAR)
    content = db.Column(db.VARCHAR)
    location = db.Column(db.VARCHAR)
    photo = db.Column(db.String)
    write_id = db.Column(db.Integer, db.ForeignKey('write.write_id'))
    region_id = db.Column(db.Integer, db.ForeignKey('region.region_id'))
    attraction = db.relationship('Attraction', backref='attraction_Destination')

    def __init__(self, name='', content='', location='', photo='', write_id='', region_id=''):
        self.name = name
        self.content = content
        self.location = location
        self.photo = photo
        self.write_id = write_id
        self.region_id = region_id

class Attraction(db.Model):
    __tablename__ = 'attraction'
    attraction_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.VARCHAR)
    content = db.Column(db.VARCHAR)
    location = db.Column(db.VARCHAR)
    photo = db.Column(db.String)
    region_id = db.Column(db.Integer, db.ForeignKey('region.region_id'))
    destination_id = db.Column(db.Integer, db.ForeignKey('destination.destination_id'), nullable=True)
    write_id = db.Column(db.Integer, db.ForeignKey('write.write_id'))

    def __init__(self, name='', content='', location='', photo='', region_id='', destination_id='', write_id=''):
        self.name = name
        self.content = content
        self.location = location
        self.photo = photo
        self.region_id = region_id
        self.destination_id = destination_id
        self.write_id = write_id

class Photo(db.Model):
    __tablename__ = 'Photo'
    photo_id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.VARCHAR)
    secure_url = db.Column(db.String)
    url = db.Column(db.String)

    def __init__(self, public_id='', secure_url='', url=''):
        self.public_id = public_id
        self.secure_url = secure_url
        self.url = url
		
class Activitylogs(db.Model):
    __tablename__ = 'activitylogs'
    act_id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.VARCHAR)
    user_id = db.Column(db.Integer)
    client_id = db.Column(db.VARCHAR)
    role_id = db.Column(db.String(2))
    date = db.Column(db.DateTime, default=datetime.datetime.now())

class Notifications(db.Model):
    __tablename__ = 'notifications'
    notification_id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.VARCHAR)
    write_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    last_open = db.Column(db.DateTime, nullable=True)
    editor_id = db.Column(db.Integer, nullable=True)
    date = db.Column(db.DateTime, default=datetime.datetime.now())

    def __init__(self, status='', write_id='', user_id='', last_open='', editor_id=''):
        self.status = status
        self.write_id = write_id
        self.user_id = user_id
        self.last_open = last_open
        self.editor_id = editor_id
