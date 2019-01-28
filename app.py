import cgi
import os
from flask import Flask, render_template, flash, redirect, url_for, session, logging, request, jsonify
from flask_mysqldb import MySQL
from functools import wraps
from passlib.hash import sha256_crypt
from sqlalchemy import create_engine, insert, delete, update
from sqlalchemy.orm import sessionmaker
from wtforms import Form, StringField, TextAreaField, PasswordField, validators

from database_setup import Categories, Items, Users, Base

# Creating DB Engine
engine = create_engine('sqlite:///flaskshop.db')
# Bind the engine to the metadata of the Base class
Base.metadata.bind = engine
# Declaring sessionmaker
DBSession = sessionmaker(bind=engine)


app = Flask(__name__)


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

# Category Form Class
class CategoryForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=200)])

# Item Form Class
class ItemForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=200)])
    detail = TextAreaField('Detail', [validators.Length(min=30)])
    category = TextAreaField('Category', [validators.Length(min=20)])

# Home/Index
@app.route("/")
def home():
    return render_template('home.html')


# About
@app.route("/about")
def about():
    return render_template('about.html')


# Catalog
@app.route("/catalog")
def catalog():
    
    # DBSession() instance
    db_session = DBSession()

    catalog = db_session.query(Categories.name)
    
    latestitems = db_session.query(Items.name).order_by(Items.creation_time.desc())

    print(catalog)
    print(latestitems)
    # Ausgabe von 2 Variablen für Template "catalog"
    return render_template('catalog.html', catalog=catalog, latestitems=latestitems)


# Single Article
# @app.route("/articles/<string:id>/")
# def article(id):
#     # Create cursor
#     #c = mysql.connection.cursor()

#     # Get article
#     result = c.execute("""
#         SELECT * 
#         FROM articles
#         WHERE id = %s;""", [id]
#     )

#     article = c.fetchone()

#     return render_template('article.html', article=article)

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # DBSession() instance
        db_session = DBSession()

        #import pdb; pdb.set_trace()
        new_user = Users(name=name, email=email, username=username, password=password)
        db_session.add(new_user)
        # commit to db
        db_session.commit()

        flash('You are now registered and can log in!', 'success')

        return redirect(url_for('home'))
    return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_post = request.form['password']

        db_session = DBSession()
        user = db_session.query(Users).filter(Users.username==username).first()

        if sha256_crypt.verify(password_post, user.password):
            # Passed
            session['logged_in'] = True
            session['username'] = username

            flash('You are now logged in', 'success')
            return redirect(url_for('home'))

        else:
            error = 'Invalid login'
            return render_template('login.html', error=error) 
    
    else:
        return render_template('login.html')

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

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Add Category
@app.route('/add_category', methods=['GET', 'POST'])
@is_logged_in
def add_category():
    form = CategoryForm(request.form)
    if request.method == 'POST' and form.validate():
        # Get Form Values
        name = form.name.data
        print(name)

        # Open DB Session
        db_session = DBSession()      

        # Insert into DB
        newcategory = Categories(name=name)
        db_session.add(newcategory)

        # Commit to DB
        db_session.commit()

        flash('Article created', 'success')

        return redirect(url_for('catalog'))
    return render_template('add_category.html', form=form)


# Add Item
@app.route('/add_item', methods=['GET', 'POST'])
@is_logged_in
def add_item():
    form = ItemForm(request.form)
    if request.method == 'POST' and form.validate():
        # Get Form Values
        name = form.name.data
        detail = form.detail.data
        category = form.category.data

        # Open DB Session
        db_session = DBSession()      

        # Execute
        db_session.execute("""
            INSERT INTO items(name, detail, category)
            VALUES(%s, %s, %s)
        """, (name, detail, category))

        # Commit to DB
        db_session.commit()

        flash('Article created', 'success')

        return redirect(url_for('catalog'))
    return render_template('add_item.html', form=form)


# # Edit Article
# @app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
# @is_logged_in
# def edit_article(id):
#     # Create Cursor
#     c = mysql.connection.cursor()

#     # Get article by id
#     result = c.execute("""
#         SELECT * 
#         FROM articles
#         WHERE id = %s
#     """, [id])

#     article = c.fetchone()

#     # Close Connection
#     c.close()

#     # Get Form
#     form = ArticleForm(request.form)

#     # Populate article form fields
#     form.title.data = article['title']
#     form.body.data = article['body']

#     if request.method == 'POST' and form.validate():
#         title = request.form['title']
#         body = request.form['body']

#         # Create Cursor
#         c = mysql.connection.cursor()
#         app.logger.info(title)

#         # Execute
#         c.execute("""
#             UPDATE articles
#             SET title = %s, body = %s
#             WHERE id = %s
#         """, (title, body, id))

#         # Commit to DB
#         mysql.connection.commit()

#         # Close connection
#         c.close()

#         flash('Article updated', 'success')

#         return redirect(url_for('dashboard'))
#     return render_template('edit_article.html', form=form)


# # Delete Article
# @app.route('/delete_article/<string:id>', methods=['POST'])
# @is_logged_in
# def delete_article(id):

#     # Create Cursor
#     c = mysql.connection.cursor()

#     # Execute
#     c.execute("""
#         DELETE
#         FROM articles
#         WHERE id = %s
#     """, [id])

#     # Commit to DB
#     mysql.connection.commit()

#     # Close Connection
#     c.close()

#     flash('Article deleted', 'success')

#     return redirect(url_for('dashboard'))


if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(debug=False)
