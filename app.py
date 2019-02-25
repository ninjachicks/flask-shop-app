#!/usr/bin/env python3

import cgi
import os
import json
from functools import wraps
from passlib.hash import sha256_crypt

from flask import (Flask, render_template, flash, redirect, 
    url_for, session, logging, request, jsonify)
from sqlalchemy import create_engine, insert, delete, update
from sqlalchemy.orm import sessionmaker
from flask_mysqldb import MySQL
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.github import make_github_blueprint, github

from wtforms import (Form, StringField, TextAreaField, 
    PasswordField, SelectField, validators)
from wtforms_alchemy import ModelForm


from database_setup import Categories, Items, Users, Base


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flaskshop.db'


# Creating DB Engine
engine = create_engine('sqlite:///flaskshop.db')
# Bind the engine to the metadata of the Base class
Base.metadata.bind = engine
# Declaring sessionmaker
DBSession = sessionmaker(bind=engine)

db = SQLAlchemy(app)
migrate = Migrate(app, db)


github_blueprint = make_github_blueprint(client_id='0014280a3d68abcc37ac', client_secret='5e7a97cd939dbfe52fa929cf62d56664b08724a4', redirect_url='/')
app.register_blueprint(github_blueprint, url_prefix='/github_login')


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# Login Form
class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=3, max=25)])
    password = PasswordField('Password', [validators.DataRequired()])

def tmp():
    return True
# Category Form Class
# class CategoryForm(Form):
#     name = StringField('Name', [validators.Length(min=1, max=200)])
class CategoryForm(ModelForm):
    def get_session():
        return db.session

    class Meta:
        model = Categories
        only = ['name']
        

# Item Form Class
class ItemForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=200)])
    detail = TextAreaField('Detail', [validators.Length(min=3)])
    category = SelectField('Category', [validators.DataRequired()])


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, please log in', 'danger')
            return redirect(url_for('login'))
    return wrap


#JSON Catalog Endpoint
@app.route('/catalog.json')
def get_current_catalog():
    # DBSession() instance
    #db_session = DBSession()
    # Get current catalog
    catalog = db.session.query(Categories).all()
    results = {'Category': list()}

    for category in catalog:
        #db_session = DBSession()
        items = db.session.query(Items).filter(Items.category == category.name).all()
        category_data = {
            'id': category.id,
            'name': category.name,
            'items': [item.serialize for item in items]
        }
        results['Category'].append(category_data)
    
    return jsonify(results)


# JSON Catalog Item Endpoint
@app.route('/<string:category>/<string:name>/JSON')
def get_single_item(category, name):

    # DBSession() instance
    #db_session = DBSession()

    singleitem = db.session.query(Items).filter(Items.name == name)

    return jsonify(Item=[i.serialize for i in singleitem.all()])


# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


# Home/Index
@app.route("/")
def home():
    return render_template('home.html')


# About
@app.route("/about")
def about():
    return render_template('about.html')


# Register
@app.route('/register', methods=['GET', 'POST'])
def register():

    form = RegisterForm(request.form)

    if request.method == 'POST' and form.validate():
        # Populate Form Fields
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # DBSession() instance
        #db_session = DBSession()

        #import pdb; pdb.set_trace()
        new_user = Users(name=name, email=email, username=username, password=password)
        db.session.add(new_user)
        # commit to db
        db.session.commit()

        flash('You are now registered and can log in!', 'success')

        return redirect(url_for('home'))
    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm(request.form)

    if request.method == 'POST' and form.validate():
        # Get Form Fields
        username = form.username.data
        password_post = form.password.data

        # Creating DB Session
        #db_session = DBSession()

        try:
            # Getting User Data
            user = db.session.query(Users).filter(Users.username == username).first()

            # Password Verification
            if sha256_crypt.verify(password_post, user.password) and username == user.username:
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('home'))

            else:
                error = 'Invalid login'
                return render_template('login.html', error=error, form=form)

        except:
            error = 'Invalid login'
            return render_template('login.html', error=error, form=form)
    
    else:
        return render_template('login.html', form=form)


# # GitHub Login
# @app.route("/github")
# def github_login():

#     session['logged_in'] = True

#     flash('You are now logged in', 'success')
#     return redirect(url_for('home'))


# GitHub Login
@app.route("/github")
def github_login():

    if not github.authorized:
        return redirect(url_for('github.login'))
    account_info = github.get('/user')

@app.route("/itworks")
def itworks():
    return render_template('home.html')

    # if account_info.ok:
    #     account_info_json = account_info.json()
    #     username = account_info_json['login']
    #     # Passed
    #     session['logged_in'] = True
    #     session['username'] = username

    #     flash('You are now logged in', 'success')
    #     return redirect(url_for('home'))

    # flash('Request failed', 'danger')

    # return render_template('home.html')


# Catalog
@app.route("/catalog")
def catalog():
    
    # DBSession() instance
    #db_session = DBSession()
    # get Username from session
    username = session.get('username')

    catalog = db.session.query(Categories).order_by(Categories.name)
    
    latestitems = db.session.query(Items).order_by(Items.creation_time.desc()).limit(10)

    user_id = db.session.query(Users.id).filter(Users.username == username).scalar()

    # returns 2 variables for template 'catalog
    return render_template('catalog.html', catalog=catalog, latestitems=latestitems, user_id=user_id)


# Single Category
@app.route("/<string:name>")
def category(name):

    # DBSession() instance
    #db_session = DBSession()

    catalog = db.session.query(Categories.name).filter(Categories.name == name)

    category = db.session.query(Items).filter(Items.category == name)

    countitems = db.session.query(Items).filter(Items.category == name).count()

    # returns 2 variables for template 'categories
    return render_template('category.html', category=category, catalog=catalog, 
        countitems=countitems)


# Single Item Page
@app.route("/<string:category>/<string:name>/")
def item(name, category):
    
    # DBSession() instance
    #db_session = DBSession()

    singleitem = db.session.query(Items).filter(Items.name == name)

    return render_template('item.html', singleitem=singleitem)


# Add Category
@app.route('/add_category', methods=['GET', 'POST'])
@is_logged_in
def add_category():

    form = CategoryForm(request.form)
    # get Username from session
    username = session.get('username')
    # Open DB Session
    #db_session = DBSession()
    # get user_id from DB
    #user_id = db_session.query(Users.id).filter(Users.name == username).all()

    user = db.session.query(Users).filter(Users.username == username).first()
    user_id = user.id

    if request.method == 'POST' and form.validate():

        # Get Form Values
        name = form.name.data
        # Open DB Session
        #db_session = DBSession()
        # Insert into DB
        newcategory = Categories(name=name, user_id=user_id)
        db.session.add(newcategory, user_id)
        # Commit to DB
        db.session.commit()

        flash('Category created', 'success')

        return redirect(url_for('catalog'))
    else:
        flash(str(form.errors))

    return render_template('add_category.html', form=form)


# Delete Category
@app.route('/delete_cat/<string:id>', methods=['POST'])
@is_logged_in
def delete_cat(id):

    # Open DB Session
    #db_session = DBSession()
    # Fetch Category from DB
    result = db.session.query(Categories).filter(Categories.id == id).first()
    # Delete Category
    db.session.delete(result)
    # Commit to DB
    db.session.commit()

    flash('Category deleted', 'success')

    return redirect(url_for('catalog'))


# Edit Category
@app.route('/edit_cat/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_cat(id):

    # Creating DB Session
    #db_session = DBSession()
    # Fetch Category from DB
    category = db.session.query(Categories).filter(Categories.id == id).first()

    # Get Form
    form = CategoryForm(request.form)
    # Populate category form fields
    form.name.data = category.name

    if request.method == 'POST' and form.validate():
        newname = request.form['name']

        app.logger.info(newname)

        # Edit Category
        category.name = newname
        # Commit to DB
        db.session.commit()

        flash('Category updated', 'success')

        return redirect(url_for('catalog'))
    return render_template('edit_cat.html', form=form)


# Add Item
@app.route('/add_item', methods=['GET', 'POST'])
@is_logged_in
def add_item():

    form = ItemForm(request.form)

    username = session.get('username')
    # DBSession() instance
    #db_session = DBSession()
    # get categories for dropdown
    categories = db.session.query(Categories)

    user = db.session.query(Users).filter(Users.username == username).first()
    user_id = user.id
    #form = ItemForm(request.POST, obj=categories)
    form.category.choices = [(c.name, c.name) for c in categories]

    if request.method == 'POST' and form.validate():
        # Get Form Values
        name = form.name.data
        detail = form.detail.data
        category = form.category.data

        newitem = Items(name=name, detail=detail, category=category, user_id=user_id)
        db.session.add(newitem)

        # Commit to DB
        db.session.commit()

        flash('Item created', 'success')

        return redirect(url_for('catalog'))

    return render_template('add_item.html', form=form, categories=categories, user_id=user_id)

# Delete Item
@app.route('/delete_item/<string:id>', methods=['POST'])
@is_logged_in
def delete_item(id):

    # Open DB Session
    #db_session = DBSession()
    # Fetch Category from DB
    delitem = db.session.query(Items).filter(Items.id==id).first()
    # Delete Item
    db.session.delete(delitem)
    # Commit to DB
    db.session.commit()

    flash('Item deleted', 'success')

    return redirect(url_for('catalog'))

# Edit Item
@app.route('/edit_item/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_item(id):

    # Creating DB Session
    #db_session = DBSession()

    item = db.session.query(Items).filter(Items.id == id).first()
    categories = db.session.query(Categories)

    # Get Form
    form = ItemForm(request.form)

    # Populate item form fields
    form.category.choices = [(c.name, c.name) for c in categories]
    form.name.data = item.name
    form.detail.data = item.detail
    form.name.default = item.name
    form.detail.default = item.detail
    form.category.default = item.category
    form.process()

    if request.method == 'POST' and form.validate():
        newcategory = request.form['category']
        newname = request.form['name']
        newdetail = request.form['detail']

        app.logger.info(newcategory, newname, newdetail)

        # Edit Category
        item.category = newcategory
        item.name = newname
        item.detail = newdetail
        # Commit to DB
        db.session.commit()

        flash('Item updated', 'success')

        return redirect(url_for('catalog'))
    return render_template('edit_item.html', form=form)


if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(debug=True)
