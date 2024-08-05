from flask import Flask, jsonify, request, render_template
import subprocess
import os
from scripts.download_oval import download_oval_file

app = Flask(__name__)

type = "unknown"

def run_openscap():

	# Determina numele fisierului OVAL in functie de versiunea Ubuntu
	distro_codename = subprocess.check_output(['lsb_release', '-cs']).decode('utf-8').strip()
	oval_file = f"com.ubuntu.{distro_codename}.{type}.oval.xml"

	# Verifica daca fisierul OVAL exista
	if not os.path.isfile(oval_file):
		return f"OVAL file {oval_file} not found. Please download the correct OVAL file for your distribution."

	# Comanda pentru rularea OpenSCAP
	cmd = ['oscap', 'oval', 'eval', '--report', 'report.html', oval_file]

	# Executa comanda
	result = subprocess.run(cmd, capture_output=True, text=True)

	if result.returncode == 0:
		return f"Scan completed successfully. Report saved to report.html."
	else:
		return f"Scan failed. Error: {result.stderr}"

@app.route('/')
def index():
	return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
	result = run_openscap()
	with open('report.html', 'r') as file:
		report_content=file.read()
	return jsonify({'message': result, 'report': report_content})


@app.route('/process_input', methods=['POST'])
def process_input():
	types=['cve', 'pkg', 'usn']
	char_input=request.form['nrInput']

	if char_input is not None:
		try:
			char_input=int(char_input)
			if char_input in (0,1,2):
				global type
				type=types[char_input]

			x=download_oval_file(char_input) #x contains: type, distribution codename and a message in case of an error
			if isinstance(x[2], str):
				if x[2]== "The file exists in the current directory!":
					prc_msg=f"The data type {x[0]} for {x[1]} is already downloaded in your directory. You can now procced to scan your system."
					return render_template('prc_input.html', prc_msg=prc_msg)
				else:
					prc_msg="Invalid input format. Please insert a number ranged from 0 to 2 which matches the data type."
					return render_template('index.html', error=True)
			else:
				prc_msg=f"We downloaded your OVAL Definitions data type {x[0]} for your distribution codename of Ubuntu: {x[1]}. You can now procced to scan your system."
				return render_template('prc_input.html', prc_msg=prc_msg)
		except ValueError:
			prc_msg="Invalid input format. Please insert a number ranged from 0 to 2 which matches the data type."
			return render_template('index.html', error=True)
	else:
		prc_msg="No number provided. Please insert a number."
		return render_template('index.html', error=True)

if __name__ == '__main__':
	app.run(debug=True)




