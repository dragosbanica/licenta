import subprocess
import os

def run_openscap():
    # Determină numele fișierului OVAL în funcție de versiunea Ubuntu
    distro_codename = subprocess.check_output(['lsb_release', '-cs']).decode('utf-8').strip()
    oval_file = f"com.ubuntu.{distro_codename}.usn.oval.xml"

    # Verifică dacă fișierul OVAL există
    if not os.path.isfile(oval_file):
        return f"OVAL file {oval_file} not found. Please download the correct OVAL file for your distribution."

    # Comandă pentru rularea OpenSCAP
    cmd = ['oscap', 'oval', 'eval', '--report', 'report.html', oval_file]

    # Execută comanda
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        return f"Scan completed successfully. Report saved to report.html."
    else:
        return f"Scan failed. Error: {result.stderr}"

# Exemplu de utilizare
if __name__ == '__main__':
    result = run_openscap()
    print(result)

