import subprocess
import os


def download_oval_file(tmp):
	types=['cve', 'pkg', 'usn']
	dir='/home/student/licenta'

	if tmp in (0,1,2):
		type=types[tmp]
		distri_codename=subprocess.check_output(['lsb_release', '-cs']).decode('utf-8').strip()
		url = f"https://security-metadata.canonical.com/oval/com.ubuntu.{distri_codename}.{type}.oval.xml.bz2"

		#Checking to see if the file already exists
		filename1=f'com.ubuntu.{distri_codename}.{type}.oval.xml.bz2'
		filename2=f'com.ubuntu.{distri_codename}.{type}.oval.xml'
		filepath1=os.path.join(dir, filename1)
		filepath2=os.path.join(dir, filename2)

		#In cazul in care fisierul arhivat se afla in director, verificam daca exista si fisierul dezarhivat
		if os.path.isfile(filepath1):
			if os.path.isfile(filepath2):
				error="The file exists in the current directory!"
				return type, distri_codename, error
			else:
				unzip_sintax=['bunzip2', filename1]
				unzip_data=subprocess.run(unzip_sintax, capture_output=True, text=True)
				new_filename=f'com.ubuntu.{distri_codename}.{type}.oval.xml'
				error=0
				return type, distri_codename, error

		#In cazul in care fisierul arhivat nu se afla in director, verificam daca exista doar fisierul dezarhivat
		else:
			if os.path.isfile(filepath2):
				error="The file exists in the current directory!"
				return type, distri_codename, error
			else:

				download_sintax=['wget', url]
				download_file=subprocess.run(download_sintax, capture_output=True, text=True)
				unzip_sintax=['bunzip2', filename1]
				unzip_data=subprocess.run(unzip_sintax, capture_output=True, text=True)
				new_filename=f'com.ubuntu.{distri_codename}.{type}.oval.xml'
				error=0
				return type, distri_codename, error
	else:
		error="Incorect input!"
		type=0
		distri_codename=0
		return type, distri_codename, error

if __name__=="__main__":
	main()
