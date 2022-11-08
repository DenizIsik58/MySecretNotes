import json, sqlite3, click, functools, os, hashlib, time, random, sys
# import bcrypt
import secrets
import string
from datetime import timedelta

import bcrypt
from flask import Flask, current_app, g, session, redirect, render_template, url_for, request


### DATABASE FUNCTIONS ###

def connect_db():
    return sqlite3.connect(app.database)


def init_db():
    """Initializes the database with our great SQL schema"""
    conn = connect_db()
    db = conn.cursor()
    db.executescript("""

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS notes;

CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assocUser INTEGER NOT NULL,
    dateWritten DATETIME NOT NULL,
    note TEXT NOT NULL,
    publicID TEXT NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    salt TEXT NOT NULL,
    hashed_password TEXT NOT NULL
);

INSERT INTO users VALUES(null,"admin", "$2b$12$/NiVWHZUAu1kIyVtebyuYe",  "$2b$12$/NiVWHZUAu1kIyVtebyuYeNZy1CQ04C6d7adkJSPTrCKkiwUxWeZu");
INSERT INTO users VALUES(null,"bernardo", "$2b$12$uUDPHNTgwyqTE/cFJid5LO", "$2b$12$uUDPHNTgwyqTE/cFJid5LOrpnXwfrXwZW3ETA2b0Y/HXw3PMlIS9.");
INSERT INTO users VALUES(null,"stud@secu18.itu.dk", "NO SALT", "INSERT_PASSWORD_HERE");
INSERT INTO notes VALUES(null,2,"1993-09-23 10:10:10","hello my friend",1234567890);
INSERT INTO notes VALUES(null,2,"1993-09-23 12:10:10","i want lunch pls",1234567891);

""")


### APPLICATION SETUP ###
app = Flask(__name__)
app.database = "db.sqlite3"
app.secret_key = os.urandom(32)


### ADMINISTRATOR'S PANEL ###
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(**kwargs)

    return wrapped_view


@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return redirect(url_for('notes'))


@app.route("/notes/", methods=('GET', 'POST'))
@login_required
def notes():
    importerror = ""
    # Posting a new note:
    if request.method == 'POST':
        if request.form['submit_button'] == 'add note':
            note = request.form['noteinput']

            db = connect_db()
            c = db.cursor()

            statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null, ?, ? ,? ,?);"""
            print(statement)
            c.execute(statement, ((session['userid'], time.strftime('%Y-%m-%d %H:%M:%S'), note, str(generate_random_note_id()))))

            db.commit()
            db.close()
        elif request.form['submit_button'] == 'import note':

            noteid = request.form['noteid']
            db = connect_db()
            c = db.cursor()

            statement = """SELECT * from NOTES where publicID = ?"""
            c.execute(statement, (noteid,))

            result = c.fetchall()
            if len(result) > 0:
                row = result[0]
                statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null, %s,?,?,?);""" %(session['userid'])

                # Sanitize sql input from written note since retrieving the note from database could include a sql-command causing sql-injection
                c.execute(statement, (row[2], row[3], row[4]))
            else:
                importerror = "No such note with that ID!"

            db.commit()
            db.close()

    db = connect_db()
    c = db.cursor()

    statement = "SELECT * FROM notes WHERE assocUser = ?;"
    print(statement)
    c.execute(statement, (session['userid'],))

    notes = c.fetchall()
    print(notes)

    return render_template('notes.html', notes=notes, importerror=importerror)


@app.route("/login/", methods=('GET', 'POST'))
def login():
    session.clear()

    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = connect_db()
        c = db.cursor()
        # Fix user input by removing string inputs and replacing it with a question mark

        # Move username from the username and password field down to execution method
        get_user_stm = "SELECT * FROM users WHERE username = ?"
        c.execute(get_user_stm, (username,))
        user_res = c.fetchall()

        # Get the salt for the specific user registered in the database
        salt = user_res[0][2]
        # Calculate the hashed password
        hashed_pwd = bcrypt.hashpw(password.encode("utf-8"), salt.encode("utf-8")).decode("utf-8")

        # Check if a user exists in the database with the username and the calculated hash
        statement = "SELECT * FROM users WHERE username = ? AND hashed_password = ?;"
        c.execute(statement, (username, hashed_pwd))

        result = c.fetchall()

        # If they exist, start a new session and redirect to the notes page
        if len(result) > 0:
            session.clear()
            session['logged_in'] = True
            session['userid'] = result[0][0]
            session['username'] = result[0][1]
            return redirect(url_for('index'))
        else:
            error = "Wrong username or password!"
    return render_template('login.html', error=error)


@app.route("/register/", methods=('GET', 'POST'))
def register():
    session.clear()
    errored = False
    usererror = ""
    passworderror = ""

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        if len(password) < 8:
            errored = True
            passworderror = "The length of your password should be 8 or more characters"

        db = connect_db()
        c = db.cursor()

        # We have removed the password field and implemented password hashing using salt
        # That way users can have the same password but the result of hash will be different
        # We will here only check if the given username exists in the db
        user_statement = """SELECT * FROM users WHERE username = ?;"""
        c.execute(user_statement, (username,))

        # Username already exists
        if len(c.fetchall()) > 0:
            errored = True
            usererror = "That username is already in use by someone else!"

        # Username doesn't exist. Register to db and redirect to notes
        if not errored:
            statement = """INSERT INTO users(id,username,salt,hashed_password) VALUES(null,?,?,?);"""

            # Generate a random salt and hash their password
            salt = bcrypt.gensalt()
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt)

            print(statement)
            c.execute(statement, (username, salt.decode('utf-8'), hashed_pw.decode('utf-8')))

            # After inserting data into the database, find the user to get their id and username to start a session
            stm = """SELECT * FROM users WHERE username = ?;"""
            c.execute(stm, (username,))

            result = c.fetchall()

            if len(result) > 0:
                session.clear()
                session['logged_in'] = True
                session['userid'] = result[0][0]
                session['username'] = result[0][1]
                db.commit()
                db.close()

                # Display success registration and redirect to notes page instead of login page
                return f"""<html>
                            <head>
                                <meta http-equiv="refresh" content="2;url=/notes" />
                            </head>
                            <body>
                                <h1>SUCCESS!!! Redirecting in 2 seconds...</h1>
                            </body>
                            </html>
                            """

        db.commit()
        db.close()
    return render_template('register.html', usererror=usererror, passworderror=passworderror)


@app.route("/logout/")
@login_required
def logout():
    """Logout: clears the session"""
    session.clear()
    return redirect(url_for('index'))

def generate_random_note_id():
    letters = string.ascii_letters
    digits = string.digits
    special_chars = string.punctuation

    alphabet = letters + digits + special_chars

    note_id_length = 15

    note_id = ''
    for i in range(note_id_length):
        note_id += ''.join(secrets.choice(alphabet))

    return note_id

if __name__ == "__main__":
    # create database if it doesn't exist yet
    if not os.path.exists(app.database):
        init_db()
    runport = 5000
    if (len(sys.argv) == 2):
        runport = sys.argv[1]
    try:
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=1) # Kill session after 1 minute
        app.run()  # runs on machine ip address to make it visible on netowrk
    except:
        print("Something went wrong. the usage of the server is either")
        print("'python3 app.py' (to start on port 5000)")
        print("or")
        print("'sudo python3 app.py 80' (to run on any other port)")
