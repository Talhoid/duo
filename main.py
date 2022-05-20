from flask import Flask, send_from_directory, jsonify, render_template, request
import hashlib, hmac, time, os, sys, sqlite3, secrets, json, base64, requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlite3 import Error
from pathlib import Path
from constants import Constants
from flask_request_id import RequestID
from flask_cors import CORS
from operator import itemgetter as destructure
consts = Constants(SCRIPT_PATH = os.path.dirname(os.path.realpath(sys.argv[0])))
key = secrets.token_bytes(32)
class DownloadTokenError(Exception):
    code = 403
    description = "Token error"
class FileError(Exception):
    code = 403
    description = "File error"
def get_request_id(request):
    return request.environ.get("FLASK_REQUEST_ID")
def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file, check_same_thread=False)
        return conn
    except BaseException as e:
        print(e)

    return conn
def execute(conn, sql, params = ()):
    try:
        c = conn.cursor()
        return c.execute(sql, params)
    except Error as e:
        raise e
def dir_last_updated(folder):
    return str(max(os.path.getmtime(os.path.join(root_path, f))
                   for root_path, dirs, files in os.walk(folder)
                   for f in files))
expired_tokens_db = create_connection('expired_tokens.db')
if expired_tokens_db is not None:
    execute(expired_tokens_db, """
    CREATE TABLE IF NOT EXISTS tokens (
	    token text
    );
    """)
    expired_tokens_db.commit()
else:
    print("Error! Database connection failed! Key feature will be missing!")
app = Flask(__name__,
            static_url_path='', 
            static_folder='web/static',
            template_folder='web/templates')
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
app.config['TEMPLATES_AUTO_RELOAD'] = True
@app.context_processor
def inject_stage_and_region():
    return dict(cache_gen=dir_last_updated)
shatype = hashlib.sha3_256
secret = secrets.token_hex(16)
RequestID(app)
CORS(app)
# @app.after_request
# def after_request(response):
#     response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
#     response.headers["Expires"] = 0
#     response.headers["Pragma"] = "no-cache"
#     return response

@app.errorhandler(DownloadTokenError)
def handle_download_error(err):
    response = {
        "error": err.description, 
        "request_id": get_request_id(request)
    }
    if len(err.args) > 0:
        response["message"] = err.args[0]
        response["type"] = err.args[1]
    return render_template("error.html"), err.code
@app.errorhandler(FileError)
def handle_file_error(err):
    response = {
        "error": err.description, 
        "request_id": get_request_id(request)
    }
    if len(err.args) > 0:
        response["message"] = err.args[0]
        response["type"] = err.args[1]
    return render_template("error.html"), err.code
(response), err.code
@app.route('/')
def home():
    return render_template('home.html')
@app.route('/get/<filename>/')
@app.route('/get/<filename>/<type>/')
def generate(filename, type="link"):
    if type == "link":
        if Path(f'{consts.SCRIPT_PATH}/web/uploads/{filename}').is_file():
            current_time = bytes(str(time.time()), 'utf-8')
            salt = secrets.token_hex(16)
            token = hmac.new(bytes(secret + salt + filename, 'utf-8'), current_time, shatype).hexdigest()
            origin = request.url.split('/')[2]
            nonce = secrets.token_bytes(12)
            encrypted_info = nonce + AESGCM(key).encrypt(nonce, bytes(json.dumps({
                'filename': filename,
                'date': current_time.decode('utf-8'),
                'token': token,
                'salt': salt
            }), "utf-8"), b"")
            url = "/https/download/" + base64.urlsafe_b64encode(encrypted_info).decode('ascii')
            return render_template('file_link_gen.html', origin=origin, filename=filename, url=url)
        else:
            raise FileError('Invalid file', 'not_found')
    elif type == "json":
        current_time = bytes(str(time.time()), 'utf-8')
        salt = secrets.token_hex(16)
        token = hmac.new(bytes(secret + salt + filename, 'utf-8'), current_time, shatype).hexdigest()
        # g.filename = filename
        # g.current_time = current_time.decode('utf-8')
        # g.token = token
        # g.salt = salt
        # g.origin = request.url.split('/')[2]
        return jsonify({
            'url': f'{ request.url.split("/")[2] }/download/{ filename }/{ current_time.decode("utf-8") }/{ token }/{ salt }/'
        })
    else:
        raise FileError('Invalid type', 'invalid_type')
@app.route('/download/<ciphertext>/')
def download(ciphertext):
    ciphertext = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
    print(ciphertext)
    decrypted = json.loads(AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], b""))

    filename, date, token, salt = destructure('filename', 'date', 'token', 'salt')(decrypted)
    print(f"{filename=} {date=} {token=} {salt=}")
    date = float(date)
    time_limit = 10 * 60
    expired_tokens = []
    for token in execute(expired_tokens_db, 'SELECT * FROM tokens').fetchall():
        expired_tokens.append(token[0])
    isValid = hmac.new(bytes(secret + salt + filename, 'utf-8'), str(date).encode('utf-8'), shatype).hexdigest() == token and not token in expired_tokens
    if (time.time() - date) > time_limit and isValid:
        raise DownloadTokenError('Your token has expired', 'expired')
    elif token in expired_tokens:
        raise DownloadTokenError('Your token has already been used', 'used')
    elif not isValid:
        raise DownloadTokenError('Your token is invalid', 'invalid')
    elif isValid:
        execute(expired_tokens_db, """ INSERT INTO tokens(token)
            VALUES(?) """, (token,))
        expired_tokens_db.commit()
        return send_from_directory(f'{consts.SCRIPT_PATH}/web/uploads', filename, cache_timeout=0, mimetype='application/octet-stream')
@app.route('/https/<path:path>')
def https(path):
    print(path)
    session = requests.Session()
    response = session.request(request.method, f"https://{request.url.split('/')[2]}/{path}", headers=request.headers)
    return (response.text, response.status_code, response.headers.items())
app.run('0.0.0.0', port=8080, debug=True)