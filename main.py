from flask import *
import webbrowser
import uuid
import json
import os
import hashlib
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# default data for new vault
master_password = ""
credentials = []
default_credentials = [dict(id="392d3ad8-b1c4-4ea2-8567-22b954c84839",
                            title="Email Account",
                            url="www.hotmail.com",
                            username="tom@hotmail.com",
                            password="whatsmyageagain",
                            notes="you've got mail"),
                       dict(id="216f2833-943f-4358-8867-40c89636183c",
                            title="Bank Account",
                            url="www.bankofamerica.com",
                            username="mark@yahoo.com",
                            password="sometimesitmakesmewanttolaugh",
                            notes="mucho moolah"),
                       dict(id="9f88dae6-fa60-4516-8825-66db252b6d12",
                            title="Social Media",
                            url="www.myspace.com",
                            username="travis@outlook.com",
                            password="whosgonnabetheoddmanout",
                            notes="just for fun")]

# func to handle vault encryption
def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }

# func to handle vault decryption
def decrypt(enc_dict, password):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted


app = Flask(__name__)

# app route to serve static files
@app.route('/static/<path:path>')
def www_static(path):
    return send_from_directory('static', path)

# app route to handle requests to root
@app.route('/')
def www_default():
    if session.get('logged_in'):
        return redirect("/credentials")
    else:
        return redirect("/login")

# app route to handle login
@app.route('/login', methods=["GET", "POST"])
def www_login():
    if session.get('logged_in'):
        return redirect("/credentials")
    if request.method == "GET":
        if not os.path.exists("vault.bin"):
            loginmessage = "set an encryption password to create a new vault file"
        else:
            loginmessage = "enter your encryption password to unlock the vault file"
        return render_template('login.html', loginmessage=loginmessage)
    if request.method == "POST":
        try:
            global master_password
            master_password = request.form["password"]
            if not os.path.exists("vault.bin"):
                datatowrite = str(encrypt(str(default_credentials), master_password))
                with open('vault.bin', 'w') as f:
                    f.write(datatowrite)
            with open('vault.bin', 'r') as f:
                dataread = f.read()
            loaded_credentials = eval(str(decrypt(eval(dataread), master_password).decode('utf-8')))
            i = 0
            credentials.clear()
            for i in range(0, len(loaded_credentials)):
                credentials.append(loaded_credentials[i])
                i += 1
            session['logged_in'] = True
            flash("Login Success", "success")
            return redirect("/credentials")
        except Exception as e:
            flash("Password Incorrect: " + str(e), "danger")
            return redirect("/login")

# app route to load and save credential data
@app.route('/credentials', methods=["GET", "POST"])
def www_credentials():
    if not session.get('logged_in'):
        flash("Not Logged In", "danger")
        return redirect("/login")
    if request.method == "GET":
        credentials.sort(key=lambda item: item.get("title"))
        return render_template('credentials.html', credentials=credentials)
    if request.method == "POST":
        try:
            id_fields = request.form.getlist('id')
            title_fields = request.form.getlist('title')
            url_fields = request.form.getlist('url')
            username_fields = request.form.getlist('username')
            password_fields = request.form.getlist('password')
            notes_fields = request.form.getlist('notes')
            for i in range(0, len(credentials)):
                credentials[i]["id"] = id_fields[i]
                credentials[i]["title"] = title_fields[i]
                credentials[i]["url"] = url_fields[i]
                credentials[i]["username"] = username_fields[i]
                credentials[i]["password"] = password_fields[i]
                credentials[i]["notes"] = notes_fields[i]
            encrypted_credentials = str(encrypt(str(credentials), master_password))
            with open('vault.bin', 'w') as f:
                f.write(encrypted_credentials)
            # uncomment below lines to save a plaintext copy for export to another password manager
            # with open('vault.plaintext.bin', 'w') as f:
                # f.write(str(credentials))
            flash("Save Success", "success")
            return redirect("/credentials")
        except Exception as e:
            flash("Save Error: " + str(e), "danger")
            return redirect("/credentials")

# app route for adding a new blank credential
@app.route('/add', methods=["POST"])
def www_add():
    if not session.get('logged_in'):
        flash("Not Logged In", "danger")
        return redirect("/login")
    else:
        credentials.append(dict(id=str(uuid.uuid4()),
                                title="",
                                url="",
                                username="",
                                password="",
                                notes=""))
        encrypted_credentials = str(encrypt(str(credentials), master_password))
        with open('vault.bin', 'w') as f:
            f.write(encrypted_credentials)
        flash("Add Success", "success")
        return redirect("/credentials")

# app route for deleting a credential
@app.route('/delete', methods=["POST"])
def www_delete():
    if not session.get('logged_in'):
        flash("Not Logged In", "danger")
        return redirect("/login")
    else:
        i = 0
        for i in range(0, len(credentials)):
            if credentials[i]['id'] == request.form['del_id']:
                credentials.pop(i)
                encrypted_credentials = str(encrypt(str(credentials), master_password))
                with open('vault.bin', 'w') as f:
                    f.write(encrypted_credentials)
                break
            i += 1
        flash("Delete Success", "success")
        return redirect("/credentials")

# app route for handling logout
@app.route('/logout', methods=["GET", "POST"])
def www_logout():
    if session.get('logged_in'):
        session['logged_in'] = False
        credentials = None
        flash("Logout Success", "success")
        return redirect("/login")

# run app on specified port
if __name__ == "__main__":
    app.secret_key = os.urandom(32)
    # webbrowser.open("https://127.0.0.1:8192")
    app.run(host='192.168.2.2', port=8192, ssl_context=('cert.pem', 'key.pem'))
