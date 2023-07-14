import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
app = Flask(__name__)
app.secret_key = 'b_5#y2L"F4Q8z\n\xec]/'

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

Session(app)

db = SQL("sqlite:///users.db")

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/register", methods=("GET", "POST"))
def register():
    if request.method == 'GET':
        return render_template('register.html')

    if request.method == 'POST':
        name = request.form.get('name')
        number = request.form.get('number')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirmpassword')

        if (name == '' or number == '' or username == '' or password == '' or confirm == ''):
            return render_template('error.html', error_message = 'Please fill in all required fields')

        if (password != confirm):
            return render_template('error.html', error_message = 'Ensure passwords match before submitting')

        try:
            if (len(number) != 8):
                return render_template('error.html', error_message = 'Ensure that you key in a 8 digit mobile number')

            number = int(number)
        except:
            return render_template('error.html', error_message = 'Ensure that you key in a numerical mobile number')

        # We can hash the password for security

        hash = generate_password_hash(password)

        # We can start working with SQL now
        try:
            db.execute('INSERT INTO students (username, password, full_name, mobile) VALUES (?, ?, ?, ?)', username, hash, name, number)
            return render_template('index.html', studentname = session['username'])

        except Exception:
            return render_template('error.html', error_message = 'Username taken')

@app.route("/login", methods=("GET", "POST"))
def login():

    session.clear()

    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # We are reminded that actualpassword is actually a list of dictionaries (in fact, it is a list with 1 item and the item is a dictionary with 1 keyvalue pair)
        actualpassword = db.execute('SELECT password FROM students WHERE username = ?', username)

        if (username == '' or password == ''):
            return render_template('error.html', error_message = 'Please fill in all required fields')

        # Note that you get an empty list if no password is extracted due to invalid username
        if (actualpassword == []):
            return render_template('error.html', error_message = 'Invalid Username')

        # We are accessing the unique 1st row (as only 1 username called farhan exists) and finding the value of the key known as 'password'
        if not check_password_hash(actualpassword[0]['password'], password):
            return render_template('error.html', error_message = 'Wrong Password')

        session['username'] = username

        # We are using redirect here as we want to move the user over to another website, instead of having him stay in the login website
        # Otherwise, if he refreshes the page, he will have to login again, which is not user friendly
        return redirect('/loggedin')

@app.route('/logout')
def logout():
    # Remove the username from the session if it's there
    session.pop('username', None)
    return redirect('/')

@app.route("/loggedin", methods=("GET", "POST"))
def loggedin():
    if 'username' in session:
        user = session['username']
        # If user is logged in, render the logged in index page
        return render_template('loggedin.html', user = user)
    else:
        return render_template('index.html')

@app.route("/booking", methods=("GET", "POST"))
def boooking():
    if request.method == 'GET':
        return render_template('booking.html')












