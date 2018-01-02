#!/usr/bin/env python3

""" Small web server in flask to receive an APK (via HTTP POST) , analyse it and return the results.

Disclaimer:
This is really a very quick hack, done in a couple of hours.

What's still needed is:
  * better error logging (look at flask.logging)
  * rate limiting - maybe to be done on the WSGI / web server guide
  * better checking if a file is an APK
  * improved UX / UI
  * separation of user (HTML) output versus API output (JSON). Currently the latter is missing completely
  * add a "score" (float) to how confident we are that it's malware (or bening-ware)
  * and of course... as always ... better documentation


Questions & critique: via github please. Send a pull request! Thanks!

"""


from flask import Flask, abort, flash, redirect, render_template, g      # , Response
from flask import request
import werkzeug
import pprint

import os
import hashlib
import sqlite3
from datetime import datetime
from malware_test.predict import predict

" global vars "
UPLOAD_FOLDER = '/tmp/uploads'
ALLOWED_EXTENSIONS = set(['apk'])
BASEPATH="/api/v1"
# BASEPATH="/"
DBNAME="hashes.db"
debug = False
force = False
conn = None


app = Flask(__name__)
app.secret_key = 'XXXX insert your long random string XXX'
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


""" helper functions for DB interaction """


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db


def connect_db():
    return sqlite3.connect(DBNAME)


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()


def exists_in_db(hash):
    """ check if hash exists in DB """
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT count(*) FROM hashes WHERE sha256=?", (hash,))
    return c.fetchone()[0]


def insert_into_db(filename, hash, is_malware):
    """ insert a filename + it's hash and the malware status into the DB """
    conn = get_db()
    c = conn.cursor()
    now = datetime.utcnow().strftime('%Y%m%d_%H:%M:%S')
    c.execute("INSERT INTO hashes (sha256, filename, ip, ts, malware) values (?,?,?,?,?);", (hash, filename, request.remote_addr, now, is_malware))
    conn.commit()


def db_is_malware(sha256):
    """ return the status of a given hash, if it's malware or not... according to the DB """
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT malware FROM hashes WHERE sha256=?", (sha256,))
    return c.fetchone()[0]


def cached_analysis(sha256):
    is_malware = "Unknown"
    if exists_in_db(sha256):
        is_malware = db_is_malware(sha256)
    return render_template('result.html', malware=is_malware, sha256=sha256)


def check_api_key():
    """ this function must be called first thing by every other endpoint function unless it's a public endpoint """
    # replace this by a SELECT valid_keys FROM api_keys;
    return
    valid_keys=['XXX', 'YYY']
    if ('X-Api-Key' in request.headers):
        apikey = request.headers['X-Api-Key']
        if debug:
            pprint.pprint("apikey = {}".format(apikey))
        if (apikey not in valid_keys):
            abort(401)
        else:
            return True


def sha256_checksum(filename, block_size=65536):
    """ calculate the sha256 checksum of a given file """
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def allowed_file(filename):
    """ check if the given filename is allowed """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def file_is_apk(filename):
    # XXX FIXME: this needs to be fleshed out. Use something like the unix file(1) tool to detect if it's a valid APK format
    return True


def analyse(filename, sha256):
    is_malware = predict(filename, alg='rf', models='../malware_test/models', features='../malware_test/low_gen/features.p').values()[0] == 1
    return is_malware


@app.route('/help')
def help():
    return render_template('index.html')
    # return '''possible API endpoints: <p/>
    #     /api/v1/submit..... this is a HTTP POST method. Please submit the APK file to be analysed <br/>
    #     /help <br/>
    # '''


@app.route('/')
def index():
    return help()


@app.route(BASEPATH + '/submit', methods=['GET', 'POST'])
def submit():
    if request.method == 'POST':
        # check_api_key()
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('Error: No file part uploaded.')
            return redirect(request.url)
        f = request.files['file']
        now=datetime.utcnow().strftime('%Y%m%d_%H:%M:%S')
        pid=os.getpid()
        if f.filename == '':
            flash('Error: No file uploaded or selected')
            return redirect(request.url)
        filename='{}-{}-{}'.format(now, pid, werkzeug.secure_filename(f.filename))
        fullpath=os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if f and allowed_file(f.filename):
            f.save(fullpath)
            if debug:
                print("saved file: {}".format(fullpath))
        else:
            flash('Error: filename not allowed or file not uploaded. Allowed extensions: *.apk')
            return redirect(request.url)

        # check if file too big
        filesize = os.path.getsize(fullpath)
        if debug:
            print("filesize: {}".format(filesize))
        if (filesize > app.config['MAX_CONTENT_LENGTH']):
            flash('Error: file too large')
            return redirect(request.url)
            # abort(413)      # HTTP Error Payload Too Large (RFC 7231)
        # check if file was already analysed, if yes, return previous analysis or re-analyse if force==True
        h = sha256_checksum(fullpath)
        flash('Info: sha256 = {}'.format(h))
        if debug:
            print("h: {}".format(h))

        # if h in seen_hashes and not force:
        if not exists_in_db(h) and not force:
            new_file = True
        else:
            flash('Info: file already analyzed. Using cached version.')
            new_file = False
            return cached_analysis(h)

        # check if file is truly an APK,
        # XXX FIXME. Add a test is the submitted file is truly an APK

        # analyse or return error message
        if new_file and allowed_file(filename) and file_is_apk(fullpath):
            is_malware = analyse(fullpath, h)
            insert_into_db(filename, h, is_malware)
            return render_template('result.html', malware=is_malware, sha256=h)
        else:
            flash('Unsupported Media Type')
            return redirect(request.url)
    else:
        return render_template('index.html')


def upload():
    # get API key from headers and validate
    # check_api_key()
    pass


if __name__ == '__main__':
    app.run(debug=debug, host='0.0.0.0')
