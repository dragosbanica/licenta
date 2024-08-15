from flask import Flask, jsonify, request, render_template, url_for, redirect, session, send_file
import subprocess
import os
from scripts.download_oval import download_oval_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime


app = Flask(__name__)

type = "unknown" # Global variable which we can use in run_openscap()


#################SQL DATABASE SECTION############

app.config['SECRET_KEY']='mysecretkey'

app.config["SQLALCHEMY_DATABASE_URI"]='sqlite:///users.db'
app.config['SQLAlCHEMTY_TRACK_MODIFICANTIONS']=False

db=SQLAlchemy(app)

class User(db.Model):

	__tablename__='users'
	id=db.Column(db.Integer,primary_key=True)
	username=db.Column(db.Text)
	password=db.Column(db.Text)

	def __repr__(self):
		return f'User {self.username}>'


with app.app_context():
	db.create_all()


##################################################



####Forces users to acces the login page first####

def login_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if 'username' not in session:
			return redirect(url_for('login'))
		return f(*args, **kwargs)
	return decorated_function

##################################################

def run_openscap():

	# Determine the name of the Ubuntu version in order to download the correct file
	distro_codename = subprocess.check_output(['lsb_release', '-cs']).decode('utf-8').strip()
	oval_file = f"com.ubuntu.{distro_codename}.{type}.oval.xml"

	# Verify if the OVAL file exist
	if not os.path.isfile(oval_file):
		return f"OVAL file {oval_file} not found. Please download the correct OVAL file for your distribution."

	# Create the name of the file where you want your results of the scan to be
	username=session['username']
	now=datetime.now()
	timestamp=now.strftime("%Y%m%d_%H%M%S")
	filename=f"{username}_{timestamp}.html"


	directory=os.path.join('generated_files', username)
	os.makedirs(directory, exist_ok=True)

	file_path=os.path.join(directory, filename)


	# Bash command for Open SCAP to evaluate
	cmd = ['oscap', 'oval', 'eval', '--report', file_path, oval_file]

	# Execute command
	result = subprocess.run(cmd, capture_output=True, text=True)

	if result.returncode == 0:
		x= f"Scan completed successfully. Report saved to {filename}."
		return x, filename
	else:

		x= f"Scan failed. Error: {result.stderr}"
		filename="0"
		return x, filename


####Get the name of the files in the directory of the current user###


def get_file_names():
	username=session['username']
	directory=os.path.join('generated_files', username)
	if not os.path.exists(directory):
		os.makedirs(directory)
	files=os.listdir(directory)
	return files

#####################################################################

@app.route('/')
@login_required
def index():
	if 'username' in session:
		welcome_msg=f"Good to see you {session['username']}!"
		files=get_file_names()
		return render_template('index.html', welcome_msg=welcome_msg,  files=files)
	else:
		return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method== 'POST':
		username=request.form['username']
		password=request.form['password']
		user=User.query.filter_by(username=username).first()

		if user and check_password_hash(user.password, password):
			session['username']=username
			return redirect(url_for('index'))
		else:
			return "Incorrect username or password!"

	return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
	if request.method=='POST':
		username=request.form['username']
		password=request.form['password']

		hashed_password=generate_password_hash(password, method='pbkdf2:sha256')

		new_user=User(username=username, password=hashed_password)

		try:
			db.session.add(new_user)
			db.session.commit()
			return redirect(url_for('login'))
		except:
			return "There seems to be a problem with the registration. Please try again"
	return render_template('register.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
	session.pop('username', None)
	return redirect(url_for('login'))


@app.route('/scan', methods=['POST'])
@login_required
def scan():
	result = run_openscap()
	username=session['username']
	directory=os.path.join('generated_files', username)
	file_path=os.path.join(directory, result[1])

	with open(file_path, 'r') as file:
		report_content=file.read()
	return jsonify({'message': result[0], 'report': report_content})


@app.route('/view_file/<filename>')
@login_required
def view_file(filename):
	username=session['username']
	directory=os.path.join('generated_files', username)
	file_path=os.path.join(directory, filename)

	if not os.path.exists(file_path):
		return "The file doesn't exist!", 404

	with open(file_path, 'r') as file:
		content=file.read()

	return render_template('view_file.html',content=content)


@app.route('/process_input', methods=['POST'])
@login_required
def process_input():
	types=['cve', 'pkg', 'usn']
	char_input=request.form['nrInput']

	if char_input is not None:
		try:
			char_input=int(char_input)
			files=get_file_names()

			if char_input in (0,1,2):
				global type
				type=types[char_input]

			x=download_oval_file(char_input) #x contains: type, distribution codename and a message in case of an error
			if isinstance(x[2], str):
				if x[2]== "The file exists in the current directory!":
					prc_msg=f"The data type {x[0]} for {x[1]} is already downloaded in your directory. You can now procced to scan your system."
					return render_template('prc_input.html', prc_msg=prc_msg, files=files)
				else:
					prc_msg="Invalid input format. Please insert a number ranged from 0 to 2 which matches the data type."
					return render_template('index.html', error=True)
			else:
				prc_msg=f"We downloaded your OVAL Definitions data type {x[0]} for your distribution codename of Ubuntu: {x[1]}. You can now procced to scan your system."
				return render_template('prc_input.html', prc_msg=prc_msg, files=files)
		except ValueError:
			prc_msg="Invalid input format. Please insert a number ranged from 0 to 2 which matches the data type."
			return render_template('index.html', error=True)
	else:
		prc_msg="No number provided. Please insert a number."
		return render_template('index.html', error=True)


if __name__ == '__main__':
	app.run(debug=True)




