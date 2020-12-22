import os
import yaml
import psycopg2

from flask import Flask, request, jsonify, render_template, url_for, flash, redirect
from flask_wtf.file import FileAllowed, FileField, FileRequired
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
# from flask_mail import Mail, Message

from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import ValidationError, DataRequired, EqualTo
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_sqlalchemy import SQLAlchemy
from flask import send_from_directory
from flask_uploads import IMAGES , UploadSet, configure_uploads, patch_request_class
from PIL import Image as pil_img

from datetime import datetime

app = Flask(__name__)
base_dir = os.path.abspath(os.path.dirname(__file__))
ENV = 'dev'

def get_config(fname):
    '''
    Creates connection to yaml file which holds the DB user and pass
    '''
    with open(fname) as f:
        cfg = yaml.load(f, Loader=yaml.SafeLoader)
    return cfg

if ENV == 'dev':
    cfg = get_config('config.yml')
    connection = cfg['connection'][ENV]
    app.debug = True
    app.config[connection['username']] = connection['password']

    app.config['SECRET_KEY'] = connection['secret_key']

    # uploading photos 
    app.config['UPLOADED_PHOTOS_DEST'] = os.path.join('', 'static/images/')
    ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

    photos = UploadSet('photos', IMAGES)
    configure_uploads(app, photos)
    patch_request_class(app)

    # app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    # app.config['MAIL_PORT'] = 587
    # app.config['MAIL_USE_TLS'] = True
    # app.config['MAIL__USE_SSL'] = False
    # app.config['MAIL_USERNAME'] = connection['mail_user']
    # app.config['MAIL_PASSWORD'] = connection['mail_pass']

else:
    app.debug = False
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
    app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

    app.config['MAIL_SERVER'] = os.environ['MAIL_SERVER']
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL__USE_SSL'] = False
    app.config['MAIL_USERNAME'] = os.environ['MAIL_USERNAME']
    app.config['MAIL_PASSWORD'] = os.environ['MAIL_PASSWORD']

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# mail = Mail(app)
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view =  'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

    def get_reset_token(self, expires_seconds = 1800):
        s = Serializer(app.config['SECRET_KEY'], expires_seconds)
        return s.dumps({'user_id' : self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return user.query.get(user_id)

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.id

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

class AddProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15))
    name = db.Column(db.String(80))
    album_name = db.Column(db.String(350))
    album_id = db.Column(db.Integer)
    post_url = db.Column(db.String(300))
    image = db.Column(db.LargeBinary)
    caption = db.Column(db.Text())
    pub_date = db.Column(db.DateTime, nullable = False, default = datetime.utcnow)

    def __repr__(self):
        return '<AddProduct %r>' % self.name

class Album(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(15))
    album_name = db.Column(db.String(350))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('UserName', validators = [InputRequired(), Length(min = 4, max = 15)])
    password = PasswordField('Password', validators = [InputRequired(), Length(min = 8, max = 80)])
    remember = BooleanField('Remember Me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators = [InputRequired(), Email(message = 'Invalid Email'), Length(max = 50)])
    username = StringField('UserName', validators = [InputRequired(), Length(min = 4, max = 15)])
    password = PasswordField('Password', validators = [InputRequired(), Length(min = 8, max = 80)])

    def validate_username(self, username):
        '''
        Raises a validation error if a user tries to register using an existing username
        '''
        user = User.query.filter_by(username = username.data).first()
        if user:
            raise ValidationError('Username Taken')

    def validate_email(self, email):
        '''
        Raises a validation error if a user tries to register using an existing email
        '''
        user = User.query.filter_by(email = email.data).first()
        if user:
            raise ValidationError('Email Taken')

class UpdateAccountForm(FlaskForm):
    email = StringField('email', validators = [InputRequired(), Email(message = 'Invalid Email'), Length(max = 50)])
    username = StringField('UserName', validators = [InputRequired(), Length(min = 4, max = 15)])

    submit = SubmitField('Update')
    def validate_username(self, username):
        '''
        Raises a validation error if a user tries to register using an existing username
        '''
        if username.data != current_user.username:
            user = User.query.filter_by(username = username.data).first()
            if user:
                raise ValidationError('Username Taken')

    def validate_email(self, email):
        '''
        Raises a validation error if a user tries to register using an existing email
        '''
        if email.data != current_user.email:
            user = User.query.filter_by(email = email.data).first()
            if user:
                raise ValidationError('Email Taken')

class RequestResetForm(FlaskForm):
    email = StringField('email', validators = [InputRequired(), Email(message = 'Invalid Email'), Length(max = 50)])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        '''
        Raises a validation error if a user tries to register using an existing email
        '''
        if email.data != current_user.email:
            user = User.query.filter_by(email = email.data).first()
            if user is None:
                raise ValidationError('There is no accouunt with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators = [DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators = [DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class AddImage(FlaskForm):
    name = StringField('name')
    # image = TextAreaField('image', validators = [DataRequired()])
    image_f = FileField('image_f', validators=[FileRequired(), FileAllowed(['jpg', 'png', 'gif', 'jpeg'], 'Image only please')])
    caption = StringField('caption')
    post = SubmitField('post')

class CreateAlbum(FlaskForm):
    album_name = StringField('name')
    post = SubmitField('post')


@app.route('/account/',methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()

    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated', 'success')
        return redirect(url_for('account'))

    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        # flash('Your account has not been updated, the email or username might already exist by another user', 'error')

    return render_template('account.html', title = 'Account', form = form)

@app.route('/logout/')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/login_error/')
def login_error():
    return render_template('login_error.html')

@app.route('/login/',methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember = form.remember.data)
                flash('Account Created For {}!'.format(form.username.data))
                return redirect(url_for('home'))
        else:
            return redirect(url_for('login_error'))

    return render_template('login.html', form=form)

@app.route('/signup/', methods = ['GET','POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method = 'sha256') # sha256 will generate a hash which is 80 chars long
        new_user = User(username = form.username.data, email = form.email.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # send congrat email for registering
        # with app.app_context():
        #     msg = Message(subject = 'Welcome {}'.format(form.username.data), 
        #                   sender = app.config.get("MAIL_USERNAME"), 
        #                   recipients = [str(form.email.data)], 
        #                   body = 'Congratulations you have signed up and your account has been created!')
        #     mail.send(msg)

        return redirect(url_for('login'))
    else:
        return render_template('signup.html', form = form, message= 'Username / Email Already Exists')

    return render_template('signup.html', form = form)

@app.route('/reset_password/',methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        Flask('An email has been sent with instructions to resset your password', 'info')
        return redirect(url_for('login'))

    return render_template('reset_request.html', title = 'Rest Password', form = form)

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_required
@app.route('/album/<username>/<album_name>/', methods = ['GET', 'POST'])
def album(username, album_name):
    form = AddImage(request.form)
    user = User.query.filter_by(username = username).first_or_404()
    current_username = current_user.username

    if username == current_username:
        album_id_query = Album.query.filter_by(username = username, album_name = album_name).all()
        album_id = [a.id for a in album_id_query][0]

        posts = AddProduct.query.filter_by(username = username, album_name = album_name).order_by(AddProduct.pub_date.desc()).all()
        if request.method == 'POST':
            # add secure filename -- video does it by doing : photos.save(request.files.get('image_f'), name = secrets.token_hex(10) + ".")
            user = current_user.username
            f = request.files.get('image_f')
            if allowed_file(f.filename):
                file_name = secure_filename(f.filename)
                print("filename: ", f.filename, file_name)
                # url = photos.url(f).replace("_uploads", "static")
                url = app.config['UPLOADED_PHOTOS_DEST'] + file_name

                # image = photos.save(f)
                name = form.name.data
                caption = form.caption.data
                read_file = f.read()

                newFile = AddProduct(username = user, name = name, post_url = url, image = read_file, caption = caption, album_name = album_name, album_id = album_id)
                
                db.session.add(newFile)
                db.session.commit()
                return redirect(url_for('album', username = user, album_name = album_name))

            else:
                flash('Allowed image types are -> png, jpg, jpeg, gif')

        return render_template('album.html', title = username, user = user, posts = posts, album_name = album_name, album_id = album_id, form = form)
    else:
        return render_template('403_error.html')

@login_required
@app.route('/p/<id>/')
def post_detail(id):
    user=current_user
    post = AddProduct.query.filter_by(id=id, username = user.username).first_or_404()
   
    return render_template('post_details.html', post=post, user=user)

@app.route('/delete_post/<id>')
@login_required
def delete_post(id):
    AddProduct.query.filter_by(id=int(id)).delete()
    db.session.commit()

    return redirect('/my_albums/')

@app.route('/delete_album/<album_name>/<album_id>/')
@login_required
def delete_album(album_name, album_id):
    AddProduct.query.filter_by(album_name=str(album_name), album_id = int(album_id)).delete()
    db.session.commit()
    Album.query.filter_by(album_name = str(album_name), id = int(album_id)).delete()
    db.session.commit()
    return redirect('/my_albums/')

@app.route('/post_mdl/<id>')
def post_mdl(id):

    post = Post.query.filter_by(id=id).first_or_404()

    posts = list()
    users = User.query.filter_by().all()
    for p in range(0,len(users)):
        if users[p] != current_user:
           posts += Post.query.filter_by(author=users[p])
    
    user=current_user
    return render_template('_post_modal.html', post=post, posts=posts, id=int(id))

@app.route('/my_albums/', methods = ['GET', 'POST'])
@login_required
def my_albums():
    form = CreateAlbum(request.form)
    username = current_user.username
    album_names_list = Album.query.filter_by(username = username).all()
    album_list = [a.album_name for a in album_names_list] 

    if request.method == 'GET':
        album_name = form.album_name.data
        return render_template('my_albums.html', form = form, album_list = album_list)

    if (request.method == 'POST')  & (form.album_name.data not in album_list):
        album_name = form.album_name.data
        add_user_albums = Album(username = username, album_name = album_name)
        db.session.add(add_user_albums)
        db.session.commit()

        album_names_list = Album.query.filter_by(username = username).all()
        album_list = [a.album_name for a in album_names_list] 
        return render_template('my_albums.html', form = form, album_list = album_list)
    
    if (request.method == 'POST')  & (form.album_name.data in album_list):
        flash('This album already exists!')
        album_name = form.album_name.data
        return render_template('my_albums.html', form = form, album_list = album_list)

    return render_template('my_albums.html', form = form, album_list = album_list)

@app.route('/', methods = ['GET', 'POST'])
def home():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug = True)
