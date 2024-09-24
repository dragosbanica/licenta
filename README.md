# Sistem de management al vulnerabilitatilor 
Acest sistem foloseste instrumentul **OpenSCAP** si limbajul **OVAL (Open Vulnerability Assessment Language)** pentru scanarea vulnerabilitatilor sistemelor atat local cat si remote. Scanarea vulnerabilitatilor consta in verificarea versiunilor aplicatiilor si sistemelor de operare, astfel, daca se gasesc versiuni ale aplicatiilor care sunt cunoscute ca au anumite vulnerabilitati unde atacatorii pot profita, se va face un raport in care se identifica acele aplicatii, vulnerabilitatile cunoscute, gradul de severitate si se ofera solutii pentru rezolvarea acestor vulnerabilitati. Utilizatorii au o interfata web ca si consola principala unde se pot autentifica, inregistra, pot executa scanari atat locale cat si remote si pot vizualiza istoricul scanarilor. Sistemul a fost testat pe versiunile **Ubuntu 22.04 si 20.04**, pentru implementarea interfetei web, pe partea de frontend, am folosit limbajele **HTML** si **CSS**, iar pe partea de backend am folosit framework-ul **Flask** al limbajului **Python**. De asemenea, am creat scripturi Python pentru automatizarea descarcarii rapoartelor OVAL, efectuarea scanarii locale si remote si extragerea informatiilor generate in urma rapoartelor facute de OpenSCAP.

# Prezentarea generala a sistemului
- Utilizatorul acceseaza in browser adresa http://127.0.0.1:5000/login
- Se poate autentifica/inregistra
- Isi vede istoricul scanărilor dacă este cazul 
- Poate efectua o scanare locala sau remote
- În urma scanării vede raportul ce conține informații despre posibilele vulnerabilități și cum le poate rezolva
  
![image](https://github.com/user-attachments/assets/451d11b6-b9b5-4664-9a25-a3b5beb60825) 

# Descrierea arhitecturii sistemului
![image](https://github.com/user-attachments/assets/fc041119-8f6e-42c4-91bc-e1656f112bda)

# Interfata grafica
## Pagina de autentificare si de inregistrare
![image](https://github.com/user-attachments/assets/d8941165-98ca-46ae-952c-680c4764649c)

## Pagina principala (Dashboard)
![image](https://github.com/user-attachments/assets/1fa20fd7-bbe5-449e-aaa4-9e13b6d86019)

## Pagina de scanare
![image](https://github.com/user-attachments/assets/dfed3856-48ff-4225-b4b3-2f52a0efb5da)

## Pagina de scanare dupa efectuarea unei scanari
![image](https://github.com/user-attachments/assets/8dbc92e8-2e82-41db-9b2f-f9384f92493d)

## Pagina de vizualizare a unui raport
![image](https://github.com/user-attachments/assets/8da1ecda-1e9c-4fe2-aeab-099fbe7d8ce0)

# Bibliografie

About OVAL
https://oval.mitre.org/about/

OpenSCAP User Manual
https://static.open-scap.org/openscap-1.3/oscap_user_manual.html#_introduction
