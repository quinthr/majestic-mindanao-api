from escapadeApp import *
from models import *
from flask_cors import cross_origin
import binascii, base64, jsonpickle
from sqlalchemy import desc

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify ({'message':'token is missing!'}), 401

        try:
            data=jwt.decode(token, app.config['SECRET_KEY'])

            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated



@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), username=data['username'], password_hash=hashed_password, firstname=data['firstname'], middlename=data['middlename'],
                    lastname=data['lastname'], contact=data['contact'], address=data['address'], birthday=data['birthday'], role_id=3, profile='https://res.cloudinary.com/dbmtbrihl/image/upload/v1544125031/up.jpg',
                    age=data['age'])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message':'Registered successfully!'})

@app.route('/api/login/', methods=['GET'])
def login():
    auth = request.authorization
    admin = User.query.filter_by(username='admin').first()
    if admin is None:
        hashed_password = generate_password_hash('password', method='sha256')
        add_admin = User(public_id=str(uuid.uuid4()), username='admin', password_hash=hashed_password,
                        firstname='admin', middlename='admin',
                        lastname='admin', contact='09955890556', address='admin',
                        birthday='1998-08-27', role_id=1,
                        age=99)
        db.session.add(add_admin)
        db.session.commit()

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm = "Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm = "Login required!"'})

    if check_password_hash(user.password_hash, auth.password):
        token = jwt.encode(
            {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=90)},
            app.config['SECRET_KEY'])
        print 'Token generated!'
        return jsonify({'status':'ok', 'token': token.decode('UTF-8'), 'role_id':user.role_id, 'public_id':user.public_id,'message':'login successful!'})

@app.route('/api/writer/submit', methods=['POST'])
@cross_origin('*')
def writer_submit():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Submitted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    print photo
    region = Region(name=data['name'], content=data['content'],
                    photo=photo.secure_url,
                    write_id=get_write.write_id)
    db.session.add(region)
    db.session.commit()
    print('Good')
    editors = User.query.filter_by(role_id=str(2)).all()
    for editor in editors:
        notification = Notifications(status='submission', write_id=get_write.write_id, user_id=user.id, last_open=None, editor_id=editor.id)
        db.session.add(notification)
        db.session.commit()

    act_logsInput(data['username'],2,'own')
    
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/submit/destination', methods=['POST'])
@cross_origin('*')
def writer_submit_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Submitted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    region = Region.query.filter_by(name=data['region']).first()
    if region is None:
        return jsonify({'error': 'failed to add'})
    else:
        destination = Destination(name=data['name'], content=data['content'],
                        photo=photo.secure_url, location=data['location'],
                        region_id = region.region_id, write_id=get_write.write_id)
        db.session.add(destination)
        db.session.commit()
        print('Good')
        editors = User.query.filter_by(role_id=str(2)).all()
        for editor in editors:
            notification = Notifications(status='submission', write_id=get_write.write_id, user_id=user.id,
                                         last_open=None, editor_id=editor.id)
            db.session.add(notification)
            db.session.commit()

        act_logsInput(data['username'],2,'own')

        return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/submit/attraction', methods=['POST'])
@cross_origin('*')
def writer_submit_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Submitted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    region = Region.query.filter_by(name=data['region']).first()
    destination = Destination.query.filter_by(location=data['destination']).first()
    if region is None:
        return jsonify({'error': 'failed to add'})
    else:
        if destination is None:
            attraction = Attraction(name=data['name'], content=data['content'],
                                    photo=photo.secure_url, location=data['location'],
                                    destination_id=None,
                                    region_id=region.region_id, write_id=get_write.write_id)
        else:
            attraction = Attraction(name=data['name'], content=data['content'],
                            photo=photo.secure_url, location=data['location'], destination_id=destination.destination_id,
                            region_id = region.region_id, write_id=get_write.write_id)
        db.session.add(attraction)
        db.session.commit()
        print('Good')
        editors = User.query.filter_by(role_id=str(2)).all()
        for editor in editors:
            notification = Notifications(status='submission', write_id=get_write.write_id, user_id=user.id,
                                         last_open=None, editor_id=editor.id)
            db.session.add(notification)
            db.session.commit()

        act_logsInput(data['username'],2,'own')

        return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/draft/destination', methods=['POST'])
@cross_origin('*')
def writer_draft_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Drafted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    region = Region.query.filter_by(name=data['region']).first()
    if region is None:
        return jsonify({'error': 'failed to add'})
    else:
        destination = Destination(name=data['name'], content=data['content'],
                        photo=photo.secure_url, location=data['location'],
                        region_id = region.region_id, write_id=get_write.write_id)
        db.session.add(destination)
        db.session.commit()
        print('Good')
        return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/draft/destination2', methods=['POST'])
@cross_origin('*')
def writer_draft_destination2():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    region = Region.query.filter_by(name=data['region']).first()
    if region is None:
        return jsonify({'error': 'failed to add'})
    else:
        destination = Destination.query.filter_by(write_id=write.write_id).first()
        destination.name = data['name']
        destination.content = data['content']
        destination.location = data['location']
        destination.photo = photo.secure_url
        destination.region_id = region.region_id
        write.status = 'Drafted'
        db.session.commit()
        print('Good')
        return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/draft/attraction', methods=['POST'])
@cross_origin('*')
def writer_draft_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Drafted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    region = Region.query.filter_by(name=data['region']).first()
    destination = Destination.query.filter_by(name=data['destination']).first()
    if region is None:
        return jsonify({'error': 'failed to add'})
    else:
        if destination is None:
            attraction = Attraction(name=data['name'], content=data['content'],
                                    photo=photo.secure_url, location=data['location'],
                                    destination_id=None,
                                    region_id=region.region_id, write_id=get_write.write_id)
        else:
            attraction = Attraction(name=data['name'], content=data['content'],
                            photo=photo.secure_url, location=data['location'], destination_id=destination.destination_id,
                            region_id = region.region_id, write_id=get_write.write_id)
        db.session.add(attraction)
        db.session.commit()
        print('Good')
        return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/draft/attraction2', methods=['POST'])
@cross_origin('*')
def writer_draft_attraction2():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    region = Region.query.filter_by(name=data['region']).first()
    destination = Destination.query.filter_by(name=data['destination']).first()
    if region is None:
        return jsonify({'error': 'failed to add'})
    else:
        attraction = Attraction.query.filter_by(write_id=data['write_id']).first()
        attraction.name = data['name']
        attraction.content = data['content']
        attraction.location = data['location']
        attraction.photo = photo.secure_url
        attraction.region_id = region.region_id
        write.status = 'Drafted'
        if destination is None:
            attraction.destination_id = None
        else:
            attraction.destination_id = destination.destination_id
        db.session.commit()
        print('Good')
        return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/draft', methods=['POST'])
@cross_origin('*')
def writer_draft():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write(author_id=user.id, author_name=user.username, status='Drafted')
    db.session.add(write)
    db.session.commit()
    get_write = Write.query.filter((Write.author_id == user.id) & (Write.author_name == user.username)).order_by(Write.write_id.desc()).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    region = Region(name=data['name'], content=data['content'],
                    photo=photo.secure_url,
                    write_id=get_write.write_id)
    db.session.add(region)
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/draft2', methods=['POST'])
@cross_origin('*')
def writer_draft2():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    region = Region.query.filter_by(write_id=write.write_id).first()
    write.status = 'Drafted'
    region.name = data['name']
    region.content = data['content']
    region.photo = photo.secure_url
    db.session.commit()
    print('Good')

    act_logsInput(data['username'], 5, 'own')

    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/upload', methods=['POST'])
@cross_origin('*')
def upload_photo():
    data = request.get_json()
    print(data)
    photo = Photo(public_id=data['public_id'], secure_url=data['secure_url'], url=data['url'])
    db.session.add(photo)
    db.session.commit()
    return jsonify({'success': 'true'})

@app.route('/api/writer/delete', methods=['POST'])
@cross_origin('*')
def delete():
    data = request.get_json()
    print(data)
    file = binascii.a2b_base64(data['filename'])
    photo = Photo.query.filter((Photo.username == data['username']) & (Photo.photo == file)).first()
    db.session.delete(photo)
    db.session.commit()
    return jsonify({'success': 'true'})

@app.route('/api/writer/submissions', methods=['GET', 'POST'])
@cross_origin('*')
def submissions():
    data = request.get_json()
    output2 = []
    dict2 = {}
    user = User.query.filter_by(username=data['username']).first()
    count = Write.query.filter((Write.status == 'Submitted') & (Write.author_id == user.id)).order_by(Write.write_id.desc()).count()
    articles = Write.query.filter((Write.status == 'Submitted') & (Write.author_id == user.id)).order_by(Write.write_id.desc()).paginate(per_page=10,
                                                                                                 page=int(
                                                                                                     data['pagenum']),
                                                                                                 error_out=True).items
    articles2 = Write.query.filter((Write.status == 'Submitted') & (Write.author_id == user.id)).order_by(Write.write_id.desc()).paginate(per_page=10,
                                                                                            page=int(data['pagenum']),
                                                                                            error_out=True).iter_pages(
        left_edge=1, right_edge=1, left_current=2, right_current=2)
    frozen = jsonpickle.encode(articles2)
    dict2['paginate'] = frozen
    dict2['count'] = count
    output2.append(dict2)
    output = []
    for article in articles:
        dict = {}
        region = Region.query.filter_by(write_id=article.write_id).first()
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        attraction = Attraction.query.filter_by(write_id=article.write_id).first()
        if region is not None:
            dict['type'] = 'Region'
            dict['name'] = region.name
            dict['content'] = region.content
            dict['photo'] = region.photo
            dict['region_id'] = region.region_id
            dict['write_id'] = article.write_id
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        if destination is not None:
            dict['type'] = 'Destination'
            dict['name'] = destination.name
            dict['content'] = destination.content
            dict['photo'] = destination.photo
            dict['region_id'] = destination.region_id
            dict['write_id'] = article.write_id
            dict['location'] = destination.location
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            region = Region.query.filter_by(region_id=destination.region_id).first()
            dict['region_name'] = region.name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        if attraction is not None:
            attraction = Attraction.query.filter_by(write_id=article.write_id).first()
            dict = {}
            dict['type'] = 'Attraction'
            dict['name'] = attraction.name
            dict['content'] = attraction.content
            dict['photo'] = attraction.photo
            dict['region_id'] = attraction.region_id
            dict['write_id'] = attraction.write_id
            destination2 = Destination.query.filter_by(destination_id=attraction.destination_id).first()
            if destination2 is not None:
                dict['destination_id'] = attraction.destination_id
            region = Region.query.filter_by(region_id=attraction.region_id).first()
            dict['region_name'] = region.name
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        output.append(dict)
    return jsonify({'submissions': output, 'posts': output2})

@app.route('/api/writer/submissions/returned', methods=['GET', 'POST'])
@cross_origin('*')
def returned_submissions():
    data = request.get_json()
    output2 = []
    dict2 = {}
    user = User.query.filter_by(username=data['username']).first()
    count = Write.query.filter((Write.status == 'Checked') & (Write.author_id == user.id)).order_by(
        Write.write_id.desc()).count()
    articles = Write.query.filter((Write.status == 'Checked') & (Write.author_id == user.id)).order_by(
        Write.write_id.desc()).paginate(per_page=10,
                                    page=int(
                                        data['pagenum']),
                                    error_out=True).items
    articles2 = Write.query.filter((Write.status == 'Checked') & (Write.author_id == user.id)).order_by(
        Write.write_id.desc()).paginate(per_page=10,
                                    page=int(data['pagenum']),
                                    error_out=True).iter_pages(
        left_edge=1, right_edge=1, left_current=2, right_current=2)
    frozen = jsonpickle.encode(articles2)
    dict2['paginate'] = frozen
    dict2['count'] = count
    output2.append(dict2)
    output = []
    for article in articles:
        dict = {}
        region = Region.query.filter_by(write_id=article.write_id).first()
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        attraction = Attraction.query.filter_by(write_id=article.write_id).first()
        if region is not None:
            dict['type'] = 'Region'
            dict['name'] = region.name
            dict['content'] = region.content
            dict['photo'] = region.photo
            dict['region_id'] = region.region_id
            dict['write_id'] = article.write_id
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        if destination is not None:
            dict['type'] = 'Destination'
            dict['name'] = destination.name
            dict['content'] = destination.content
            dict['photo'] = destination.photo
            dict['region_id'] = destination.region_id
            dict['write_id'] = article.write_id
            dict['location'] = destination.location
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            region = Region.query.filter_by(region_id=destination.region_id).first()
            dict['region_name'] = region.name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        if attraction is not None:
            attraction = Attraction.query.filter_by(write_id=article.write_id).first()
            dict = {}
            dict['type'] = 'Attraction'
            dict['name'] = attraction.name
            dict['content'] = attraction.content
            dict['photo'] = attraction.photo
            dict['region_id'] = attraction.region_id
            dict['write_id'] = attraction.write_id
            destination2 = Destination.query.filter_by(destination_id=attraction.destination_id).first()
            if destination2 is not None:
                dict['destination_id'] = attraction.destination_id
            region = Region.query.filter_by(region_id=attraction.region_id).first()
            dict['region_name'] = region.name
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        output.append(dict)
    return jsonify({'submissions': output, 'posts': output2})

@app.route('/api/writer/drafts', methods=['GET', 'POST'])
@cross_origin('*')
def drafts():
    data = request.get_json()
    output2 = []
    dict2 = {}
    user = User.query.filter_by(username=data['username']).first()
    count = Write.query.filter((Write.status == 'Drafted') & (Write.author_id == user.id)).order_by(
        Write.write_id.desc()).count()
    articles = Write.query.filter((Write.status == 'Drafted') & (Write.author_id == user.id)).order_by(
        Write.write_id.desc()).paginate(per_page=10,
                                    page=int(
                                        data['pagenum']),
                                    error_out=True).items
    articles2 = Write.query.filter((Write.status == 'Drafted') & (Write.author_id == user.id)).order_by(
        Write.write_id.desc()).paginate(per_page=10,
                                    page=int(data['pagenum']),
                                    error_out=True).iter_pages(
        left_edge=1, right_edge=1, left_current=2, right_current=2)
    frozen = jsonpickle.encode(articles2)
    dict2['paginate'] = frozen
    dict2['count'] = count
    output2.append(dict2)
    output = []
    for article in articles:
        dict = {}
        region = Region.query.filter_by(write_id=article.write_id).first()
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        attraction = Attraction.query.filter_by(write_id=article.write_id).first()
        if region is not None:
            dict['type'] = 'Region'
            dict['name'] = region.name
            dict['content'] = region.content
            dict['photo'] = region.photo
            dict['region_id'] = region.region_id
            dict['write_id'] = article.write_id
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        if destination is not None:
            dict['type'] = 'Destination'
            dict['name'] = destination.name
            dict['content'] = destination.content
            dict['photo'] = destination.photo
            dict['region_id'] = destination.region_id
            dict['write_id'] = article.write_id
            dict['location'] = destination.location
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            region = Region.query.filter_by(region_id=destination.region_id).first()
            dict['region_name'] = region.name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        if attraction is not None:
            attraction = Attraction.query.filter_by(write_id=article.write_id).first()
            dict = {}
            dict['type'] = 'Attraction'
            dict['name'] = attraction.name
            dict['content'] = attraction.content
            dict['photo'] = attraction.photo
            dict['region_id'] = attraction.region_id
            dict['write_id'] = attraction.write_id
            destination2 = Destination.query.filter_by(destination_id=attraction.destination_id).first()
            if destination2 is not None:
                dict['destination_id'] = attraction.destination_id
            region = Region.query.filter_by(region_id=attraction.region_id).first()
            dict['region_name'] = region.name
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        output.append(dict)
    return jsonify({'submissions': output, 'posts': output2})

@app.route('/api/editor/submissions', methods=['GET', 'POST'])
@cross_origin('*')
def editor_submissions():
    data = request.get_json()
    output2 = []
    dict2 = {}
    user = User.query.filter_by(username=data['username']).first()
    count = Write.query.filter(Write.status == 'Submitted').order_by(
        Write.write_id.desc()).count()
    articles = Write.query.filter(Write.status == 'Submitted').order_by(
        Write.write_id.desc()).paginate(per_page=10,
                                    page=int(
                                        data['pagenum']),
                                    error_out=True).items
    articles2 = Write.query.filter(Write.status == 'Submitted').order_by(
        Write.write_id.desc()).paginate(per_page=10,
                                    page=int(data['pagenum']),
                                    error_out=True).iter_pages(
        left_edge=1, right_edge=1, left_current=2, right_current=2)
    frozen = jsonpickle.encode(articles2)
    dict2['paginate'] = frozen
    dict2['count'] = count
    output2.append(dict2)
    output = []
    for article in articles:
        dict = {}
        region = Region.query.filter_by(write_id=article.write_id).first()
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        attraction = Attraction.query.filter_by(write_id=article.write_id).first()
        if region is not None:
            dict['type'] = 'Region'
            dict['name'] = region.name
            dict['content'] = region.content
            dict['photo'] = region.photo
            dict['region_id'] = region.region_id
            dict['write_id'] = article.write_id
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        if destination is not None:
            dict['type'] = 'Destination'
            dict['name'] = destination.name
            dict['content'] = destination.content
            dict['photo'] = destination.photo
            dict['region_id'] = destination.region_id
            dict['write_id'] = article.write_id
            dict['location'] = destination.location
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            region = Region.query.filter_by(region_id=destination.region_id).first()
            dict['region_name'] = region.name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        if attraction is not None:
            attraction = Attraction.query.filter_by(write_id=article.write_id).first()
            dict = {}
            dict['type'] = 'Attraction'
            dict['name'] = attraction.name
            dict['content'] = attraction.content
            dict['photo'] = attraction.photo
            dict['region_id'] = attraction.region_id
            dict['write_id'] = attraction.write_id
            destination2 = Destination.query.filter_by(destination_id=attraction.destination_id).first()
            if destination2 is not None:
                dict['destination_id'] = attraction.destination_id
            region = Region.query.filter_by(region_id=attraction.region_id).first()
            dict['region_name'] = region.name
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        output.append(dict)
    return jsonify({'submissions': output, 'posts': output2})

@app.route('/api/writer/submission/edit', methods=['GET', 'POST'])
@cross_origin('*')
def edit_submissions():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    article = Write.query.filter_by(write_id=data['write_id']).first()
    output = []
    region = Region.query.filter_by(write_id=article.write_id).first()
    dict = {}
    dict['name'] = region.name
    dict['content'] = region.content
    dict['photo'] = region.photo
    dict['status'] = article.status
    photo = Photo.query.filter_by(secure_url=region.photo).first()
    dict['public_id'] = photo.public_id
    dict['secure_url'] = photo.secure_url
    dict['region_id'] = region.region_id
    dict['write_id'] = article.write_id
    dict['date'] = article.date
    dict['author_id'] = article.author_id
    user2 = User.query.filter_by(id=article.author_id).first()
    dict['author_name'] = user2.firstname + ' ' + user2.lastname
    dict['status'] = article.status
    dict['comment'] = article.comment
    output.append(dict)
    return jsonify({'submission': output})

@app.route('/api/writer/submission/edit-destination', methods=['GET', 'POST'])
@cross_origin('*')
def edit_submissions_destination():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    article = Write.query.filter_by(write_id=data['write_id']).first()
    output = []
    destination = Destination.query.filter_by(write_id=article.write_id).first()
    region = Region.query.filter_by(region_id=destination.region_id).first()
    dict = {}
    dict['name'] = destination.name
    dict['content'] = destination.content
    dict['photo'] = destination.photo
    photo = Photo.query.filter_by(secure_url=destination.photo).first()
    dict['public_id'] = photo.public_id
    dict['secure_url'] = photo.secure_url
    dict['region_id'] = destination.region_id
    dict['location'] = destination.location
    dict['write_id'] = article.write_id
    dict['region'] = region.name
    dict['date'] = article.date
    dict['author_id'] = article.author_id
    dict['author_name'] = article.author_name
    dict['status'] = article.status
    dict['comment'] = article.comment
    output.append(dict)
    return jsonify({'submission': output})

@app.route('/api/writer/submission/edit-attraction', methods=['GET', 'POST'])
@cross_origin('*')
def edit_submissions_attraction():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    article = Write.query.filter_by(write_id=data['write_id']).first()
    output = []
    attraction = Attraction.query.filter_by(write_id=article.write_id).first()
    dict = {}
    dict['name'] = attraction.name
    dict['content'] = attraction.content
    dict['photo'] = attraction.photo
    photo = Photo.query.filter_by(secure_url=attraction.photo).first()
    dict['public_id'] = photo.public_id
    dict['region_id'] = attraction.region_id
    if attraction.destination_id is not None:
        destination = Destination.query.filter_by(destination_id = attraction.destination_id).first()
        dict['destination_id'] = attraction.destination_id
        dict['destination'] = destination.location
    region = Region.query.filter_by(region_id=attraction.region_id).first()
    dict['region'] = region.name
    dict['location'] = attraction.location
    dict['write_id'] = article.write_id
    dict['date'] = article.date
    dict['author_id'] = article.author_id
    dict['author_name'] = article.author_name
    dict['status'] = article.status
    dict['comment'] = article.comment
    output.append(dict)
    return jsonify({'submission': output})

@app.route('/api/writer/submit/draft', methods=['GET',  'POST'])
@cross_origin('*')
def submit_draft():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    region = Region.query.filter_by(write_id=get_write.write_id).first()
    region.name=data['name']
    region.content=data['content']
    region.photo=photo.secure_url
    get_write.status='Submitted'
    get_write.date=datetime.datetime.today()
    db.session.commit()
    editors = User.query.filter_by(role_id=str(2)).all()
    for editor in editors:
        notification = Notifications(status='submission', write_id=get_write.write_id, user_id=user.id, last_open=None, editor_id=editor.id)
        db.session.add(notification)
        db.session.commit()
    print('Good')

    act_logsInput(data['username'],6,'own')

    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/submit/region2', methods=['GET',  'POST'])
@cross_origin('*')
def submit_region2():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(public_id=data['secure_url']).first()
    region = Region.query.filter_by(write_id=get_write.write_id).first()
    region.name=data['name']
    region.content=data['content']
    region.photo=photo.secure_url
    get_write.status='Submitted'
    get_write.date=datetime.datetime.today()
    db.session.commit()
    editors = User.query.filter_by(role_id=str(2)).all()
    for editor in editors:
        notification = Notifications(status='submission', write_id=get_write.write_id, user_id=user.id, last_open=None, editor_id=editor.id)
        db.session.add(notification)
        db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/submit/draft-destination', methods=['GET',  'POST'])
@cross_origin('*')
def submit_draft_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    destination = Destination.query.filter_by(write_id=get_write.write_id).first()
    destination.name=data['name']
    destination.content=data['content']
    destination.photo=photo.secure_url
    destination.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    destination.region_id = region.region_id
    get_write.status='Submitted'
    get_write.date=datetime.datetime.today()
    db.session.commit()
    editors = User.query.filter_by(role_id=str(2)).all()
    for editor in editors:
        notification = Notifications(status='submission', write_id=get_write.write_id, user_id=user.id, last_open=None, editor_id=editor.id)
        db.session.add(notification)
        db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/submit/destination2', methods=['GET',  'POST'])
@cross_origin('*')
def submit_draft_destination2():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    destination = Destination.query.filter_by(write_id=get_write.write_id).first()
    destination.name=data['name']
    destination.content=data['content']
    destination.photo=photo.secure_url
    destination.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    destination.region_id = region.region_id
    get_write.status='Submitted'
    get_write.date=datetime.datetime.today()
    db.session.commit()
    editors = User.query.filter_by(role_id=2).all()
    for editor in editors:
        notification = Notifications(status='submission', write_id=get_write.write_id, user_id=user.id, last_open=None, editor_id=editor.id)
        db.session.add(notification)
        db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/submit/draft-attraction', methods=['GET',  'POST'])
@cross_origin('*')
def submit_draft_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    attraction = Attraction.query.filter_by(write_id=get_write.write_id).first()
    attraction.name=data['name']
    attraction.content=data['content']
    attraction.photo=photo.secure_url
    attraction.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    attraction.region_id = region.region_id
    destination = Destination.query.filter_by(location=data['destination']).first()
    if destination is not None:
        attraction.destination_id = destination.destination_id
    else:
        attraction.destination_id = None
    get_write.status='Submitted'
    get_write.date=datetime.datetime.today()
    db.session.commit()
    editors = User.query.filter_by(role_id=str(2)).all()
    for editor in editors:
        notification = Notifications(status='submission', write_id=get_write.write_id, user_id=user.id, last_open=None, editor_id=editor.id)
        db.session.add(notification)
        db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/submit/attraction2', methods=['GET',  'POST'])
@cross_origin('*')
def submit_return2():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    attraction = Attraction.query.filter_by(write_id=get_write.write_id).first()
    attraction.name = data['name']
    attraction.content = data['content']
    attraction.photo = photo.secure_url
    attraction.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    attraction.region_id = region.region_id
    destination = Destination.query.filter_by(location=data['destination']).first()
    if destination is not None:
        attraction.destination_id = destination.destination_id
    else:
        attraction.destination_id = None
    get_write.status = 'Submitted'
    get_write.date = datetime.datetime.today()
    db.session.commit()
    editors = User.query.filter_by(role_id=str(2)).all()
    for editor in editors:
        notification = Notifications(status='submission', write_id=get_write.write_id, user_id=user.id, last_open=None, editor_id=editor.id)
        db.session.add(notification)
        db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/edit', methods=['GET',  'POST'])
@cross_origin('*')
def edit_submit():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(secure_url=data['secure_url']).first()
    region = Region.query.filter_by(write_id=get_write.write_id).first()
    region.name=data['name']
    region.content=data['content']
    region.photo=photo.secure_url
    get_write.date=datetime.datetime.today()
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/edit/destination', methods=['GET',  'POST'])
@cross_origin('*')
def edit_submit_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    destination = Destination.query.filter_by(write_id=get_write.write_id).first()
    destination.name=data['name']
    destination.content=data['content']
    destination.photo=photo.secure_url
    destination.location=data['location']
    region = Region.query.filter_by(name=data['region']).first()
    destination.region_id = region.region_id
    get_write.date=datetime.datetime.today()
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/writer/edit/attraction', methods=['GET',  'POST'])
@cross_origin('*')
def edit_submit_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    get_write = Write.query.filter_by(write_id=data['write_id']).first()
    photo = Photo.query.filter_by(public_id=data['public_id']).first()
    attraction = Attraction.query.filter_by(write_id=get_write.write_id).first()
    attraction.name=data['name']
    attraction.content=data['content']
    attraction.photo=photo.secure_url
    attraction.location=data['location']
    region = Region.query.filter_by(name=data['region']).first()
    attraction.region_id = region.region_id
    destination = Destination.query.filter_by(name=data['destination']).first()
    if destination is not None:
        attraction.destination_id = destination.destination_id
    else:
        attraction.destination_id = None
    get_write.date=datetime.datetime.today()
    db.session.commit()
    print('Good')
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/publish/region', methods=['POST'])
@cross_origin('*')
def editor_submit_reg():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    region = Region.query.filter_by(write_id=data['write_id']).first()
    region.name = data['region']
    region.content = data['content']
    db.session.commit()
    write.status = 'Posted'
    db.session.commit()
    print('Good')
    notifications = Notifications.query.filter_by(write_id=write.write_id).all()

    db.session.commit()
    for notification in notifications:
        db.session.delete(notification)
        db.session.commit()
    notification_new = Notifications(status='returned', write_id=write.write_id, user_id=write.author_id, last_open=None,
                                     editor_id=None)
    db.session.add(notification_new)

    act_logsInput(data['username'],3,write.author_name)  #note author_name sa write kay username

    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/publish/destination', methods=['POST'])
@cross_origin('*')
def editor_submit_des():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    destination = Destination.query.filter_by(write_id=data['write_id']).first()
    destination.name = data['name']
    destination.content = data['content']
    destination.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    destination.region_id = region.region_id
    db.session.commit()
    write.status = 'Posted'
    db.session.commit()
    print('Good')

    notifications = Notifications.query.filter_by(write_id=write.write_id).all()
    for notification in notifications:
        db.session.delete(notification)
        db.session.commit()

    notification_new = Notifications(status='returned', write_id=write.write_id, user_id=write.author_id, last_open=None,
                                     editor_id=None)
    db.session.add(notification_new)
    db.session.commit()

    act_logsInput(data['user_username'],2,'own')

    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/publish/attraction', methods=['POST'])
@cross_origin('*')
def editor_submit_att():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    attraction = Attraction.query.filter_by(write_id=data['write_id']).first()
    attraction.name = data['name']
    attraction.content = data['content']
    attraction.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    attraction.region_id = region.region_id
    destination = Destination.query.filter_by(location=data['destination']).first()
    if destination is not None:
        attraction.destination_id = destination.destination_id
    else:
        attraction.destination_id = None
    db.session.commit()
    write.status = 'Posted'
    db.session.commit()
    print('Good')

    notifications = Notifications.query.filter_by(write_id=write.write_id).all()
    for notification in notifications:
        db.session.delete(notification)
        db.session.commit()

    notification_new = Notifications(status='returned', write_id=write.write_id, user_id=write.author_id, last_open=None,
                                     editor_id=None)
    db.session.add(notification_new)
    db.session.commit()

    act_logsInput(data['user_username'],2,'own')

    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/delete/region', methods=['POST'])
@cross_origin('*')
def editor_delete_reg():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    region = Region.query.filter_by(write_id=data['write_id']).first()
    write.status = 'Hidden'
    db.session.commit()

    act_logsInput(data['username'],1,write.author_name)

    return jsonify({'message': 'Deleted successfully!'})

@app.route('/api/editor/delete/destination', methods=['POST'])
@cross_origin('*')
def editor_delete_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    destination = Destination.query.filter_by(write_id=data['write_id']).first()
    attractions = Attraction.query.filter_by(destination_id=destination.destination_id).all()
    if attractions is not None:
        for attraction in attractions:
            db.session.delete(attraction)
            db.session.commit()
    db.session.delete(destination)
    db.session.commit()
    db.session.delete(write)
    db.session.commit()

    act_logsInput(data['username'],1,write.author_name)

    return jsonify({'message': 'Deleted successfully!'})

@app.route('/api/editor/delete/attraction', methods=['POST'])
@cross_origin('*')
def editor_delete_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    attraction = Attraction.query.filter_by(write_id=data['write_id']).first()
    db.session.delete(attraction)
    db.session.commit()
    db.session.delete(write)
    db.session.commit()

    act_logsInput(data['username'],1,write.author_name)

    return jsonify({'message': 'Deleted successfully!'})

@app.route('/api/editor/edit/region', methods=['POST'])
@cross_origin('*')
def editor_edit_reg():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    region = Region.query.filter_by(write_id=data['write_id']).first()
    region.name = data['region']
    region.content = data['content']
    db.session.commit()
    write.status = 'Checked'
    write.comment = data['comment']
    db.session.commit()
    print('Good')
    notifications = Notifications.query.filter_by(write_id=write.write_id).all()

    for notification in notifications:
        db.session.delete(notification)
        db.session.commit()
    notification_new = Notifications(status='checked', write_id=write.write_id, user_id=write.author_id,last_open=None,editor_id=None)
    db.session.add(notification_new)
    db.session.commit()

    act_logsInput(data['username'],4,write.author_name)

    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/edit/destination', methods=['POST'])
@cross_origin('*')
def editor_edit_destination():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    destination = Destination.query.filter_by(write_id=data['write_id']).first()
    destination.name = data['name']
    destination.content = data['content']
    destination.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    destination.region_id = region.region_id
    db.session.commit()
    write.status = 'Checked'
    write.comment = data['comment']
    db.session.commit()
    print('Good')
    notifications = Notifications.query.filter_by(write_id=write.write_id).all()

    for notification in notifications:
        db.session.delete(notification)
        db.session.commit()
    notification_new = Notifications(status='checked', write_id=write.write_id, user_id=write.author_id, last_open=None,
                                     editor_id=None)
    db.session.add(notification_new)
    db.session.commit()
    return jsonify({'message': 'Added successfully!'})

@app.route('/api/editor/edit/attraction', methods=['POST'])
@cross_origin('*')
def editor_edit_attraction():
    print('gdsf')
    data = request.get_json()
    print(data)
    write = Write.query.filter_by(write_id=data['write_id']).first()
    attraction = Attraction.query.filter_by(write_id=data['write_id']).first()
    attraction.name = data['name']
    attraction.content = data['content']
    attraction.location = data['location']
    region = Region.query.filter_by(name=data['region']).first()
    attraction.region_id = region.region_id
    destination = Destination.query.filter_by(location=data['destination']).first()
    if destination is not None:
        attraction.destination_id = destination.destination_id
    else:
        attraction.destination_id = None
    db.session.commit()
    write.status = 'Checked'
    write.comment = data['comment']
    db.session.commit()
    print('Good')
    notifications = Notifications.query.filter_by(write_id=write.write_id).all()

    for notification in notifications:
        db.session.delete(notification)
        db.session.commit()
    notification_new = Notifications(status='checked', write_id=write.write_id, user_id=write.author_id, last_open=None,
                                     editor_id=None)
    db.session.add(notification_new)
    db.session.commit()
    return jsonify({'message': 'Added successfully!'})

@app.route('/get_regions')
@cross_origin('*')
def regions():
    articles = Write.query.filter_by(status='Posted').all()
    articles = Write.query.join(Region).filter(Write.write_id == Region.write_id).filter(
        Write.status == 'Posted').all()
    output = []
    for article in articles:
        region = Region.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['name'] = region.name
        dict['content'] = region.content
        dict['photo'] = region.photo
        dict['region_id'] = region.region_id
        output.append(dict)
    return jsonify({'regions': output})

@app.route('/get_destinations')
@cross_origin('*')
def get_destinations():
    articles = Write.query.join(Destination).filter(Write.write_id == Destination.write_id).filter(
        Write.status == 'Posted').all()
    output = []
    for article in articles:
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['name'] = destination.name
        dict['location'] = destination.location
        dict['content'] = destination.content
        dict['photo'] = destination.photo
        dict['region_id'] = destination.region_id
        region = Region.query.filter_by(region_id=destination.region_id).first()
        dict['region_name'] = region.name
        output.append(dict)
    return jsonify({'destinations': output})

@app.route('/get_posted')
@cross_origin('*')
def get_posted():
    data = request.get_json()
    print data
    output2 = []
    dict2 = {}
    count = Write.query.filter_by(status='Posted').count()
    articles = Write.query.filter(Write.status == 'Posted').order_by(desc(Write.write_id)).paginate(per_page=10,
                                                                                            page=int(data['pagenum']),
                                                                                            error_out=True).items
    articles2 = Write.query.filter_by(status='Posted').order_by(desc(Write.write_id)).paginate(per_page=10, page=int(data['pagenum']), error_out=True).iter_pages(left_edge=1, right_edge=1, left_current=2, right_current=2)
    frozen = jsonpickle.encode(articles2)
    dict2['paginate'] = frozen
    dict2['count'] = count
    output2.append(dict2)
    output = []
    for article in articles:
        dict = {}
        region = Region.query.filter_by(write_id=article.write_id).first()
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        attraction = Attraction.query.filter_by(write_id=article.write_id).first()
        if region is not None:
            dict['type'] = 'Region'
            dict['name'] = region.name
            dict['content'] = region.content
            dict['photo'] = region.photo
            dict['region_id'] = region.region_id
            dict['write_id'] = article.write_id
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        elif destination is not None:
            dict['type'] = 'Destination'
            dict['name'] = destination.name
            dict['content'] = destination.content
            dict['photo'] = destination.photo
            dict['region_id'] = destination.region_id
            dict['write_id'] = article.write_id
            dict['location'] = destination.location
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            region = Region.query.filter_by(region_id=destination.region_id).first()
            dict['region_name'] = region.name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        elif attraction is not None:
            attraction = Attraction.query.filter_by(write_id=article.write_id).first()
            dict = {}
            dict['type'] = 'Attraction'
            dict['name'] = attraction.name
            dict['content'] = attraction.content
            dict['photo'] = attraction.photo
            dict['region_id'] = attraction.region_id
            dict['write_id'] = attraction.write_id
            destination2 = Destination.query.filter_by(destination_id=attraction.destination_id).first()
            if destination2 is not None:
                dict['destination_id'] = attraction.destination_id
            region = Region.query.filter_by(region_id=attraction.region_id).first()
            dict['region_name'] = region.name
            dict['date'] = article.date.strftime('%B %d, %Y')
            dict['author_id'] = article.author_id
            dict['author_name'] = article.author_name
            user = User.query.filter_by(username=article.author_name).first()
            dict['author_name'] = user.firstname + ' ' + user.lastname
            dict['status'] = article.status
        else:
            continue
        output.append(dict)
    print output
    return jsonify({'submissions': output, 'posts': output2})

@app.route('/get/all/attractions')
@cross_origin('*')
def get_all_attractions():
    data = request.get_json()
    output2 = []
    dict2 = {}
    count = Write.query.join(Attraction).filter(Write.write_id == Attraction.write_id).filter(
        Write.status == 'Posted').order_by(Write.write_id.desc()).count()
    articles = Write.query.join(Attraction).filter(Write.write_id == Attraction.write_id).order_by(Write.write_id.desc()).filter(
        Write.status == 'Posted').paginate(per_page=10,
                                           page=int(data['pagenum']),
                                           error_out=True).items
    articles2 = Write.query.join(Attraction).filter(Write.status == 'Posted').filter(
        Write.write_id == Attraction.write_id).order_by(Write.write_id.desc()).paginate(per_page=10,
                                                                                page=int(data['pagenum']),
                                                                                error_out=True).iter_pages(
        left_edge=1, right_edge=1, left_current=2, right_current=2)
    frozen = jsonpickle.encode(articles2)
    dict2['paginate'] = frozen
    dict2['count'] = count
    output2.append(dict2)
    output = []
    print(articles)
    for article in articles:
        attraction = Attraction.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Attraction'
        dict['name'] = attraction.name
        dict['content'] = attraction.content
        dict['photo'] = attraction.photo
        dict['region_id'] = attraction.region_id
        dict['write_id'] = attraction.write_id
        destination = Destination.query.filter_by(destination_id=attraction.destination_id).first()
        if destination is not None:
            dict['destination_id'] = attraction.destination_id
        region = Region.query.filter_by(region_id=attraction.region_id).first()
        dict['region_name'] = region.name
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author_name'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    return jsonify({'submissions': output, 'posts': output2})

@app.route('/get/all/destinations')
@cross_origin('*')
def get_all_destinations():
    data = request.get_json()
    output2 = []
    dict2 = {}
    count = Write.query.join(Destination).filter(Write.write_id == Destination.write_id).filter(
        Write.status == 'Posted').order_by(Write.write_id.desc()).count()
    articles = Write.query.join(Destination).filter(Write.write_id == Destination.write_id).order_by(Write.write_id.desc()).filter(
        Write.status == 'Posted').paginate(per_page=10,
                                           page=int(data['pagenum']),
                                           error_out=True).items
    articles2 = Write.query.join(Destination).filter(Write.status == 'Posted').filter(
        Write.write_id == Destination.write_id).order_by(Write.write_id.desc()).paginate(per_page=10,
                                                                                page=int(data['pagenum']),
                                                                                error_out=True).iter_pages(
        left_edge=1, right_edge=1, left_current=2, right_current=2)
    frozen = jsonpickle.encode(articles2)
    dict2['paginate'] = frozen
    dict2['count'] = count
    output2.append(dict2)
    output = []
    for article in articles:
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Destination'
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = destination.photo
        dict['region_id'] = destination.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        region = Region.query.filter_by(region_id=destination.region_id).first()
        dict['region_name'] = region.name
        dict['location'] = destination.location
        user = User.query.filter_by(username=article.author_name).first()
        dict['author_name'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    return jsonify({'submissions': output, 'posts': output2})

@app.route('/get/all/region')
@cross_origin('*')
def get_all_region():
    data = request.get_json()
    output2 = []
    dict2 = {}
    count = Write.query.join(Region).filter(Write.write_id == Region.write_id).filter(Write.status == 'Posted').order_by(Write.write_id.desc()).count()
    articles = Write.query.join(Region).filter(Write.write_id == Region.write_id).order_by(Write.write_id.desc()).filter(Write.status == 'Posted').paginate(per_page=10,
                                                                                            page=int(data['pagenum']),
                                                                                            error_out=True).items
    articles2 = Write.query.join(Region).filter(Write.status == 'Posted').filter(Write.write_id == Region.write_id).order_by(Write.write_id.desc()).paginate(per_page=10,
                                                                                            page=int(data['pagenum']),
                                                                                            error_out=True).iter_pages(
        left_edge=1, right_edge=1, left_current=2, right_current=2)
    frozen = jsonpickle.encode(articles2)
    dict2['paginate'] = frozen
    dict2['count'] = count
    output2.append(dict2)
    output = []
    print(articles)
    for article in articles:
        region = Region.query.filter_by(write_id=article.write_id).first()
        print region.name
        dict = {}
        dict['type'] = 'Region'
        dict['name'] = region.name
        dict['content'] = region.content
        dict['photo'] =region.photo
        dict['region_id'] = region.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author_name'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    return jsonify({'submissions': output, 'posts': output2})

@app.route('/get/region')
@cross_origin('*')
def get_region123123():
    data = request.get_json()
    output = []
    dict = {}
    region = Region.query.join(Write).filter((Region.name == data['title']) & (Write.status == 'Posted')).first()
    article = Write.query.filter_by(write_id=region.write_id).first()
    dict['type'] = 'Region'
    dict['name'] = region.name
    dict['content'] = region.content
    dict['photo'] = region.photo
    dict['region_id'] = region.region_id
    dict['write_id'] = article.write_id
    dict['date'] = article.date.strftime('%B %d, %Y')
    dict['author_id'] = article.author_id
    dict['author_name'] = article.author_name
    user = User.query.filter_by(username=article.author_name).first()
    dict['author_name'] = user.firstname + ' ' + user.lastname
    dict['status'] = article.status
    output.append(dict)
    return jsonify({'post': output})

@app.route('/get/destination')
@cross_origin('*')
def get_destination():
    data = request.get_json()
    output = []
    dict = {}
    print data
    destination = Destination.query.join(Write).filter((Destination.name == data['title']) & (Write.status == 'Posted')).first()
    destinations = Destination.query.all()
    for destination in destinations:
        if data['title'] == destination.name:
            break
    article = Write.query.filter_by(write_id=destination.write_id).first()
    dict['type'] = 'Destination'
    dict['name'] = destination.name
    dict['content'] = destination.content
    dict['photo'] = destination.photo
    dict['region_id'] = destination.region_id
    region = Region.query.filter_by(region_id=destination.region_id).first()
    dict['region_name'] = region.name
    dict['write_id'] = article.write_id
    dict['location'] = destination.location
    dict['date'] = article.date.strftime('%B %d, %Y')
    dict['author_id'] = article.author_id
    dict['author_name'] = article.author_name
    user = User.query.filter_by(username=article.author_name).first()
    dict['author_name'] = user.firstname + ' ' + user.lastname
    dict['status'] = article.status
    output.append(dict)
    return jsonify({'post': output})

@app.route('/get/attraction')
@cross_origin('*')
def get_attraction():
    data = request.get_json()
    output = []
    dict = {}
    attraction = Attraction.query.filter_by(name=data['title']).first()
    article = Write.query.filter_by(write_id=attraction.write_id).first()
    dict['type'] = 'Attraction'
    dict['name'] = attraction.name
    dict['content'] = attraction.content
    dict['photo'] = attraction.photo
    dict['region_id'] = attraction.region_id
    dict['write_id'] = article.write_id
    region = Region.query.filter_by(region_id=attraction.region_id).first()
    dict['region_name'] = region.name
    dict['date'] = article.date.strftime('%B %d, %Y')
    dict['author_id'] = article.author_id
    dict['author_name'] = article.author_name
    user = User.query.filter_by(username=article.author_name).first()
    dict['author_name'] = user.firstname + ' ' + user.lastname
    dict['status'] = article.status
    output.append(dict)
    return jsonify({'post': output})

@app.route('/get/attraction/byregion')
@cross_origin('*')
def get_attraction_byregion():
    data = request.get_json()
    output = []

    region = Region.query.filter_by(name = data['title']).first()

    attractions = Attraction.query.join(Write).filter((Attraction.region_id == region.region_id) & (Write.status == 'Posted')).all()
    for attraction in attractions:
        dict = {}
        article = Write.query.filter_by(write_id=attraction.write_id).first()
        dict['type'] = 'Attraction'
        dict['name'] = attraction.name
        dict['content'] = attraction.content
        dict['photo'] = attraction.photo
        dict['region_id'] = attraction.region_id
        dict['write_id'] = article.write_id
        region = Region.query.filter_by(region_id=attraction.region_id).first()
        dict['region_name'] = region.name
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author_name'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    return jsonify({'post2': output})

@app.route('/get/destination/byregion')
@cross_origin('*')
def get_destination_byregion():
    data = request.get_json()
    output = []

    print data
    region = Region.query.filter_by(name = data['title']).first()
    destinations = Destination.query.join(Write).filter((Destination.region_id == region.region_id) & (Write.status == 'Posted')).all()

    for destination in destinations:
        dict = {}
        article = Write.query.filter_by(write_id=destination.write_id).first()
        dict['type'] = 'Destination'
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = destination.photo
        dict['region_id'] = destination.region_id
        region = Region.query.filter_by(region_id=destination.region_id).first()
        dict['region_name'] = region.name
        dict['write_id'] = article.write_id
        dict['location'] = destination.location
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author_name'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    return jsonify({'post3': output})

@app.route('/get/all/user')
@cross_origin('*')
def get_all_users():
    output = []  
    users = User.query.filter((User.role_id == str(2)) | (User.role_id == str(3))).all()
    for user in users:
        dict = {}
        dict['id'] = user.id
        dict['public_id'] = user.public_id
        dict['username'] = user.username
        dict['firstname'] = user.firstname
        dict['middlename'] = user.middlename
        dict['fullname'] = user.firstname+ ' ' + user.middlename + ' ' + user.lastname
        dict['age'] = user.age
        dict['contact'] = user.contact
        dict['address'] = user.address
        dict['role_id'] = user.role_id
        output.append(dict)
    return jsonify({'status': 'ok', 'entries': output, 'count': len(output)})

@app.route('/api/promotedemote', methods=['POST'])
@cross_origin('*')
def promote_and_demote():
    data = request.get_json()
    user = User.query.filter_by(id = data['userid']).first()

    if data['response'] == 'yes':
        user.role_id = 2
        db.session.commit()

    else:
        user.role_id = 3
        db.session.commit()

    return jsonify({'message': 'Registered successfully!'})

@app.route('/api/profile', methods=['GET'])
@cross_origin('*')
def profile():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    dict = {}
    output = []
    dict['firstname'] = user.firstname
    dict['middlename'] = user.middlename
    dict['lastname'] = user.lastname
    dict['age'] = user.age
    dict['contact'] = user.contact
    dict['birthday'] = user.birthday
    dict['profile'] = user.profile
    output.append(dict)

    print('Good')
    return jsonify({'infos': output})


@app.route('/get_yourpost')
@cross_origin('*')
def your_post():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    authorid = user.id
    print authorid
    articles = Write.query.join(Region).filter(Write.write_id == Region.write_id).filter((Write.status == 'Posted') & (Write.author_id == authorid)).all()
    articles2 = Write.query.join(Destination).filter(Write.write_id == Destination.write_id).filter((Write.status == 'Posted') & (Write.author_id == authorid)).all()
    articles3 = Write.query.join(Attraction).filter(Write.write_id == Attraction.write_id and Write.author_id == authorid).filter(
        Write.status == 'Posted').all()
    output = []
    for article in articles:
        region = Region.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Region'
        dict['name'] = region.name
        dict['content'] = region.content
        dict['photo'] =region.photo
        dict['region_id'] = region.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    for article in articles2:
        destination = Destination.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Destination'
        dict['name'] = destination.name
        dict['content'] = destination.content
        dict['photo'] = destination.photo
        dict['region_id'] = destination.region_id
        dict['write_id'] = article.write_id
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)
    for article in articles3:
        attraction = Attraction.query.filter_by(write_id=article.write_id).first()
        dict = {}
        dict['type'] = 'Attraction'
        dict['name'] = attraction.name
        dict['content'] = attraction.content
        dict['photo'] = attraction.photo
        dict['region_id'] = attraction.region_id
        dict['write_id'] = attraction.write_id
        destination = Destination.query.filter_by(destination_id=attraction.destination_id).first()
        if destination is not None:
            dict['destination_id'] = attraction.destination_id
        dict['date'] = article.date.strftime('%B %d, %Y')
        dict['author_id'] = article.author_id
        dict['author_name'] = article.author_name
        user = User.query.filter_by(username=article.author_name).first()
        dict['author'] = user.firstname + ' ' + user.lastname
        dict['status'] = article.status
        output.append(dict)

    return jsonify({'submissions': output})
	
@app.route('/api/profile/edit',  methods=['POST'])
@cross_origin('*')
def profile_edit():
    print 'Proof'
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    user.profile = data['profile']
    db.session.commit()

    return jsonify({'message': 'success!'})

@app.route('/api/notifications/editor', methods=['GET', 'POST'])
@cross_origin('*')
def get_notifications():
    data = request.get_json()
    output = []
    user = User.query.filter_by(username=data['username']).first()
    notifications = Notifications.query.filter((Notifications.editor_id == user.id) & (Notifications.status == 'submission')).all()
    notifications_unread = Notifications.query.filter((Notifications.status == 'submission') &
        ((Notifications.editor_id == user.id) & (Notifications.last_open == None))).count()
    output2 = []
    dict2 = {}
    dict2['count'] = notifications_unread
    output2.append(dict2)
    for notification in notifications:
        dict = {}
        dict['status'] = notification.status
        user = User.query.filter_by(id=notification.user_id).first()
        dict['username'] = user.username
        dict['fullname'] = user.firstname + ' ' + user.lastname
        dict['profile'] = user.profile
        dict['write_id'] = notification.write_id
        dict['date'] = notification.date.strftime('%d/%m/%y %H:%M')
        if notification.last_open is None:
            dict['unread'] = 'True'
        else:
            dict['unread'] = 'False'
        write = Write.query.filter_by(write_id=notification.write_id).first()
        region_check = Region.query.filter_by(write_id=write.write_id).first()
        destination_check = Destination.query.filter_by(write_id=write.write_id).first()
        attraction_check = Attraction.query.filter_by(write_id=write.write_id).first()
        if region_check is not None:
            dict['type'] = 'region'
            dict['name'] = region_check.name
        elif destination_check is not None:
            dict['type'] = 'destination'
            dict['name'] = destination_check.name
        elif attraction_check is not None:
            dict['type'] = 'attraction'
            dict['name'] = attraction_check.name
        output.append(dict)
    print(output)


    return jsonify({'notifications': output, 'count':output2})

@app.route('/api/notifications/writer', methods=['GET', 'POST'])
@cross_origin('*')
def get_notifications_writer():
    data = request.get_json()
    output = []
    user = User.query.filter_by(username=data['username']).first()
    notifications = Notifications.query.filter((Notifications.user_id == user.id) & ((Notifications.status == 'returned')) | ((Notifications.status == 'checked'))).order_by(desc(Notifications.notification_id)).all()
    notifications_unread = Notifications.query.filter(((Notifications.status == 'returned') | (Notifications.status == 'checked')) &
        ((Notifications.user_id == user.id) & (Notifications.last_open == None))).count()
    output2 = []
    dict2 = {}
    dict2['count'] = notifications_unread
    output2.append(dict2)
    for notification in notifications:
        dict = {}
        dict['status'] = notification.status
        user = User.query.filter_by(id=notification.user_id).first()
        dict['username'] = user.username
        dict['fullname'] = user.firstname + ' ' + user.lastname
        dict['profile'] = user.profile
        dict['write_id'] = notification.write_id
        dict['date'] = notification.date.strftime('%d/%m/%y %H:%M')
        if notification.last_open is None:
            dict['unread'] = 'True'
        else:
            dict['unread'] = 'False'
        write = Write.query.filter_by(write_id=notification.write_id).first()
        region_check = Region.query.filter_by(write_id=write.write_id).first()
        destination_check = Destination.query.filter_by(write_id=write.write_id).first()
        attraction_check = Attraction.query.filter_by(write_id=write.write_id).first()
        if region_check is not None:
            dict['type'] = 'region'
            dict['name'] = region_check.name
        elif destination_check is not None:
            dict['type'] = 'destination'
            dict['name'] = destination_check.name
        elif attraction_check is not None:
            dict['type'] = 'attraction'
            dict['name'] = attraction_check.name
        output.append(dict)
    print output
    print output2
    return jsonify({'notifications': output, 'count':output2})


@app.route('/mark-read/editor', methods=['GET', 'POST'])
@cross_origin('*')
def mark_read_editor():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    notifications= Notifications.query.filter((Notifications.status == 'submission') &
                                                      ((Notifications.editor_id == user.id) & (
                                                                  Notifications.last_open == None))).all()
    for notification in notifications:
        notification.last_open = datetime.datetime.now()
        db.session.commit()
    return 'success'

@app.route('/mark-read/writer', methods=['GET', 'POST'])
@cross_origin('*')
def mark_read_writer():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    notifications = Notifications.query.filter(((Notifications.status == 'returned') | (Notifications.status == 'checked')) &
                                                      ((Notifications.user_id == user.id) & (
                                                                  Notifications.last_open == None))).all()
    print notifications
    for notification in notifications:
        print notification.user_id
        notification.last_open = datetime.datetime.now()
        db.session.commit()
    return 'success'


def act_logsInput(username,method,client): # method delete=1, submit=2, publish=3, return=4, draft=5, submitfromdraft=6 change
    user = User.query.filter_by(username=username).first()
    act = Activitylogs(status=method,user_id=user.id,client_id = client,role_id = user.role_id)
    db.session.add(act)
    db.session.commit()


@app.route('/api/activity_logs', methods=['GET']) # chnage
@cross_origin('*')
def act_log_view():
    print('gdsf')
    data = request.get_json()
    print(data)
    user = User.query.filter_by(username=data['username']).first()
    acts = Activitylogs.query.filter(Activitylogs.user_id==user.id).all()

    output = []
    for act in acts:
        dict = {}
        if act.client_id == 'own':
            dict['current_user'] = user.id
            dict['client_id'] = act.client_id
            dict['status'] = act.status
            dict['date'] = act.date
            dict['clientFname'] = 'own'
            dict['clientLname'] = 'own'

        else:
            user_client = User.query.filter_by(username = act.client_id).first()
            dict['current_user'] = user.id
            dict['client_id'] = act.client_id
            dict['status'] = act.status
            dict['date'] = act.date
            dict['clientFname'] = user_client.firstname
            dict['clientLname'] = user_client.lastname
        output.append(dict)
    print output

    print('Good')
    return jsonify({'acts': output})
