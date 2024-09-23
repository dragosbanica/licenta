import paramiko
import os
from datetime import datetime

def run_openscap_remote(ssh_client, type):
    """
    Functia care ruleaza OpenSCAP pe masina remote prin SSH si descarca rapoartele pe masina locala.
    ssh_client: Conexiune SSH deschisa cu masina remote.
    """

    # Determinam versiunea Ubuntu pentru fisierul OVAL corect
    stdin, stdout, stderr = ssh_client.exec_command("lsb_release -cs")
    distro_codename = stdout.read().decode('utf-8').strip()

    # Numele fisierului OVAL
    oval_file = f"com.ubuntu.{distro_codename}.{type}.oval.xml"

     # Verificam daca fisierul OVAL exista pe masina remote
    check_cmd = f"test -f {oval_file} && echo 'Found' || echo 'Not found'"
    stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
    file_exists = stdout.read().decode('utf-8').strip()

    # Dacă fisierul nu exista, il descarcam si il dezarhivam
    if file_exists != 'Found':
        # URL-ul de unde descarcam fisierul OVAL
        url = f"https://security-metadata.canonical.com/oval/com.ubuntu.{distro_codename}.{type}.oval.xml.bz2"
        filename_bz2 = f"com.ubuntu.{distro_codename}.{type}.oval.xml.bz2"

        # Comanda pentru descarcare
        download_cmd = f"wget {url}"
        stdin, stdout, stderr = ssh_client.exec_command(download_cmd)
        stdout.channel.recv_exit_status()  # Asteptam finalizarea
        download_error = stderr.read().decode('utf-8')

       # if download_error:
       #    return f"Download failed. Error: {download_error}", None, None

        # Dezarhivam fisierul .bz2
        unzip_cmd = f"bunzip2 {filename_bz2}"
        stdin, stdout, stderr = ssh_client.exec_command(unzip_cmd)
        stdout.channel.recv_exit_status()  # Asteptam finalizarea
        unzip_error = stderr.read().decode('utf-8')

        if unzip_error:
            return f"Unzipping failed. Error: {unzip_error}", None, None

        # Verificam daca fisierul a fost dezarhivat corect
        stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
        file_exists_after_unzip = stdout.read().decode('utf-8').strip()
        if file_exists_after_unzip != 'Found':
            return f"Failed to locate the OVAL file after download.", None, None


    # Cream numele fisierelor pentru rezultatele scanarii
    username = session['username']
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    filename_html = f"{username}_{timestamp}.html"
    filename_xml = f"{username}_{timestamp}.xml"

    # Calea locala pentru salvarea rapoartelor descarcate
    directory = os.path.join('generated_files', username)
    os.makedirs(directory, exist_ok=True)

    local_file_path_html = os.path.join(directory, filename_html)
    local_file_path_xml = os.path.join(directory, filename_xml)

    # Calea fisierelor remote
    remote_file_path_html = f"/tmp/{filename_html}"
    remote_file_path_xml = f"/tmp/{filename_xml}"

    # Comenzile pentru rularea OpenSCAP pe masina remote
    cmd1 = f"oscap oval eval --report {remote_file_path_html} {oval_file}"
    cmd2 = f"oscap oval eval --results {remote_file_path_xml} {oval_file}"

    # Executam comenzile pe masina remote
    stdin, stdout, stderr = ssh_client.exec_command(cmd1)
    stdout.channel.recv_exit_status()  # Asteptam finalizarea
    result1 = stderr.read().decode('utf-8')

    stdin, stdout, stderr = ssh_client.exec_command(cmd2)
    stdout.channel.recv_exit_status()  # Asteptam finalizarea
    result2 = stderr.read().decode('utf-8')

    # Verificam daca scanarea a avut succes
    if result1 or result2:
        return f"Scan failed. Errors: {result1 or result2}", None, None

    # Transferam fisierele de pe masina remote pe masina locala
    sftp = ssh_client.open_sftp()
    sftp.get(remote_file_path_html, local_file_path_html)
    sftp.get(remote_file_path_xml, local_file_path_xml)
    sftp.close()

    # Stergem fisierele de pe masina remote
    ssh_client.exec_command(f"rm {remote_file_path_html}")
    ssh_client.exec_command(f"rm {remote_file_path_xml}")

    return f"Scan completed successfully. Report saved as {filename_html} and {filename_xml}.", filename_html, filename_xml

