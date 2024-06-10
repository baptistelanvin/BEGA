import json
import ssl
import socket
import smtplib
from email.mime.text import MIMEText
import requests
import OpenSSL
from datetime import datetime

class owl:
    
    def show_banner(self):
        banner = ("""
____________________________________________
               _         ,,_,,
              | |       ( o o )
  ___ _      _| |      /'` ' `'\      
 / _ \ \ /\ / / |      |'''''''|
| (_) | V  V /| |      |\\\\'''//|
 \___/ \_/\_/ |_|     ====w=w====
            
                    v.1.5 by Mikb
____________________________________________\n""")
        print(banner)  


    def owl_scan(self, 
                 host, 
                 email):
        
        """
        Cette fonction initialise l'objet en récupérant le nom d'hôte et l'adresse e-mail à utiliser pour le scan
        Elle crée également la structure de base pour les résultats.

        Parameters:
        host (str): Le nom d'hôte à scanner.
        email (str): L'adresse e-mail à utiliser pour le scan.

        Returns:
        filename (str): Le nom du fichier JSON généré.
        """
        
        self.host = host
        self.email = email
        # Liste des ports à scanner
        self.ports = [25, 
                      465, 
                      587, 
                      2525]

        # Mise en forme des résultats du scan
        results = {
            "Host": {
                "Name": host,
                "Port": {
                }
            }
        }

        # Boucle sur les ports de la liste ports
        for port in self.ports:
            if self.is_open(host, port):
                # Si le port est ouvert
                port_results = results['Host']['Port'][str(port)] = {'Status': 'open'}

                # Appel de check_clear_mail pour vérifier si le serveur SMTP prend en charge la communication en clair
                self.check_clear_mail(port, port_results)

                # Appel des deux fonctions pour vérifier si le serveur SMTP prend en charge la communication chiffrée
                self.check_implicit_tls(port, port_results)
                self.check_explicit_tls(port, port_results)

                # Appel de check_ssl pour vérifier si le serveur SMTP prend en charge SSL/TLS
                if port_results['Encrypted-Text'].get('Implicit-TLS', {}).get('Status') == 'supported':
                    self.check_ssl(port, port_results, encryption_key='Implicit-TLS')

                if port_results['Encrypted-Text'].get('Explicit-TLS', {}).get('Status') == 'supported':
                    self.check_ssl(port, port_results, encryption_key='Explicit-TLS')

            else:
                # Sinon
                results['Host']['Port'][str(port)] = {'Status': 'close'}

        return results


    def save_report(self,path,name,result):

        json_data = json.dumps(result, indent = 4)
        pathName = path + "/"+ name
        f = open(pathName,"w")
        f.write(json_data)
        f.close()
        return
    
    # Méthode qui vérifie si un port est ouvert sur un hôte donné
    def is_open(self, 
                host, 
                port):
        
        """
        Cette méthode vérifie si un port est ouvert pour un hôte donné.
        
        Parameters:
            host (str): Nom de l'hôte à scanner.
            port (int): Numéro du port à scanner.
        
        Returns:
            bool: True si le port est ouvert, False sinon.
        """
        
        # Création d'une socket IPv4
        sock = socket.socket(socket.AF_INET, 
                             socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            # Connection à l'hôte et au port donnés
            sock.connect((self.host, 
                          port))
            # Port ouvert
            return True
        except socket.error:
            # Port fermé
            return False
        finally:
            # Fermeture de la socket
            sock.close()

    # Méthode qui vérifie si un port est sécurisé avec SSL/TLS
    def check_ssl(self, port, results, encryption_key):
        """
        Cette fonction récupère, s'il y a, les informations de chiffrement du serveur SMTP sur un  port donné.

        Parameters:
            port (int): Le port sur lequel récupérer les informations de chiffrement.
            results (dict): Dictionnaire contenant les résultats du scan.
            encryption_key (str): Clé pour déterminer si la vérification doit être effectuée pour Implicit-TLS ou Explicit-TLS.

        Returns:
            results (dict): Dictionnaire contenant les résultats du scan.
        """

        try:
            if encryption_key == "Explicit-TLS":
                # Création d'un objet SMTP avec l'hôte et le port en entrée
                smtp = smtplib.SMTP(self.host, port, timeout=4)
                # Lancement d'une connexion SSL/TLS
                smtp.starttls()
                # Récupération du certificat du serveur
                server_cert = smtp.sock.getpeercert(True)
                # Récupération de la socket SSL/TLS
                ssl_socket = smtp.sock
                cipher_info = ssl_socket.cipher()

            elif encryption_key == "Implicit-TLS":
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                # Création du socket
                with socket.create_connection((self.host, port), timeout=2) as plain_socket:
                    with context.wrap_socket(plain_socket, server_hostname=self.host) as tls_socket:
                        cipher_info = tls_socket.cipher()
                        server_cert = tls_socket.getpeercert(True)

            cert_info = ssl.DER_cert_to_PEM_cert(server_cert)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_info)

            # Extraction du sujet du certificat
            subject = x509.get_subject()

            # Extraction de l'émetteur (issuer) du certificat
            issuer = x509.get_issuer()

            # Récupération de la date de début de validité
            start_date = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
            start_date_formatted = start_date.strftime('%b %d %H:%M:%S %Y GMT')

            # Récupération de la date de fin de validité
            end_date = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            end_date_formatted = end_date.strftime('%b %d %H:%M:%S %Y GMT')
            
            # Création d'un nouveau contexte SSL avec les options par défaut
            ssl_context = ssl.create_default_context()
            
            # Définition du protocole et des options pour le contexte SSL
            ssl_context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            
            # Récupération de la liste des ciphers pris en charge
            server_supported_ciphers = ssl_context.get_ciphers()

            supported_ciphers_dict = {}

            for server_cipher in server_supported_ciphers:
                server_cipher_name = server_cipher['name']
                server_cipher_protocol = server_cipher['protocol']


                for i in range(10, 14):
                    # URL de l'API pour récupérer la classification de sécurité
                    url = f"https://ciphersuite.info/api/cs/tls/{i}/"

                    # Obtenir la liste des suites de chiffrement TLS prises en charge
                    response = requests.get(url)

                    # Vérifier que la réponse est valide
                    if response.ok:
                        response_json = response.json()
                        tls_cipher_suites = response_json["ciphersuites"]

                        # Chercher server_cipher_name dans la liste des suites de chiffrement
                        for cipher_suite in tls_cipher_suites:
                            for cipher_name, cipher_data in cipher_suite.items():
                                if "openssl_name" in cipher_data and server_cipher_name in cipher_data["openssl_name"] \
                                        or "gnutls_name" in cipher_data and server_cipher_name in cipher_data["gnutls_name"]:
                                    server_cipher_security = cipher_data['security']
                                    break
                            else:
                                continue
                            break
                    else:
                        server_cipher_security = f"Erreur lors de l'accès à l'API pour TLS {i}: {response.status_code}"

                supported_ciphers_dict[server_cipher_name] = {
                    'Protocol': server_cipher_protocol,
                    'Security': server_cipher_security,
                }

            # Ajout des informations à "results"
            results['Encrypted-Text'][encryption_key] = {
                'Status': 'supported',
                'Cipher_list': supported_ciphers_dict
            }
                    
            for i in range(10, 14):
                    # URL de l'API pour récupérer la classification de sécurité
                url = f"https://ciphersuite.info/api/cs/tls/{i}/"

                # Obtenir la liste des suites de chiffrement TLS prises en charge
                response = requests.get(url)

                # Vérifier que la réponse est valide
                if response.ok:
                    response_json = response.json()
                    tls_cipher_suites = response_json["ciphersuites"]

                    # Chercher cipher_info[0] dans la liste des suites de chiffrement
                    for cipher_suite in tls_cipher_suites:
                        for cipher_name, cipher_data in cipher_suite.items():
                            if "openssl_name" in cipher_data and cipher_info[0] in cipher_data["openssl_name"] \
                                    or "gnutls_name" in cipher_data and cipher_info[0] in cipher_data["gnutls_name"]:
                                security = cipher_data['security']
                                break
                        else:
                            continue
                        break
                else:
                    security = f"Erreur lors de l'accès à l'API pour TLS {i}: {response.status_code}"

            # Ajout des informations à "results"
            results['Encrypted-Text'][encryption_key]['SSL-Session'] = {
                'Protocol': cipher_info[1],
                'Cipher': cipher_info[0],
                'Security': security,
                'Certificate Chain': {
                    'Subject': {
                        'Country': str(subject.countryName),
                        'State': str(subject.stateOrProvinceName),
                        'City': str(subject.localityName),
                        'Organization Name': str(subject.organizationName),
                        'Unit Name': str(subject.organizationalUnitName),
                        'Common Name': str(subject.commonName),
                        'Email': str(subject.emailAddress)
                    },
                    'Issuer': {
                        'Country': str(issuer.countryName),
                        'State': str(issuer.stateOrProvinceName),
                        'City': str(issuer.localityName),
                        'Organization Name': str(issuer.organizationName),
                        'Unit Name': str(issuer.organizationalUnitName),
                        'Common Name': str(issuer.commonName),
                        'Email': str(issuer.emailAddress)
                    },
                    "Validity": {
                        "Start": start_date_formatted,
                        "End": end_date_formatted
                    }
                },
                'Certificate': cert_info
            }
            # Fermeture de la connexion SMTP
            if encryption_key == "Explicit-TLS":
                smtp.quit()

            
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected):
            if encryption_key == "Explicit-TLS":
                if port == 465:
                    results['Encrypted-Text'][encryption_key] = {'Status': 'unsupported'}
                else:
                    # Si erreur de connexion SMTP
                    results['Error'] = f"Unable to get cipher information for {self.host}:{port}"
        except smtplib.SMTPNotSupportedError:
            if encryption_key == "Explicit-TLS":
                results['Encrypted-Text'][encryption_key] = {'Status': 'unsupported'}
        except ssl.SSLError as error_ssl:
            # Si erreur SSL/TLS
            results['Error SSL'] = str(error_ssl)

    def check_clear_mail(self, 
                         port, 
                         results):
        """
        Cette fonction vérifie si le serveur SMTP prend en charge la communication en clair.

        Parameters:
            port (int): Le port sur lequel vérifier la communication en clair.
            results (dict): Dictionnaire contenant les résultats du scan.

        Returns:
            results (dict): Dictionnaire contenant les résultats du scan.
        """

        # Création du socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_for_clear:
            socket_for_clear.settimeout(2)
            try:
                # Connexion au serveur SMTP
                socket_for_clear.connect((self.host, port))
                response = socket_for_clear.recv(1024).decode()
                if response[:3] != '220':
                    results['Clear-Text'] = {'Status': 'unsupported'}
                else:
                    # Envoi des commandes SMTP
                    socket_for_clear.sendall(b'EHLO test\r\n')
                    response = socket_for_clear.recv(1024).decode()
                    if response[:3] != '250':
                        results['Clear-Text'] = {'Status': 'unsupported'}
                    else:
                        socket_for_clear.sendall(f'MAIL FROM:<{self.email}>\r\n'.encode())
                        response = socket_for_clear.recv(1024).decode()
                        if response[:3] != '250':
                            results['Clear-Text'] = {'Status': 'unsupported'}
                        else:
                            socket_for_clear.sendall(b'QUIT\r\n')
                            results['Clear-Text'] = {'Status': 'supported'}                
                socket_for_clear.close()
                return results
            
            except socket.timeout:
                if port != 465:
                    results['Clear-Text'] = {'Status': 'timeout'}
                else:
                    results['Clear-Text'] = {'Status': 'unsupported'}
            except socket.error as e:
                results['Clear-Text'] = {'Status': 'error', 'Message': str(e)}
       
            
    def check_explicit_tls(self, 
                             port, 
                             results):
        
        """
        Cette fonction vérifie si le serveur SMTP prend en charge la communication chiffrée.
    
        Parameters:
            port (int): Le port sur lequel vérifier la communication chiffrée.
            results (dict): Dictionnaire contenant les résultats du scan.

        Returns:
            results (dict): Dictionnaire contenant les résultats du scan.
        """
        
        try:
            # Création d'un objet SMTP avec l'hôte et le port en entrée
            smtp = smtplib.SMTP(self.host, 
                                port, 
                                timeout=4)
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            if port != 465:
                results['Encrypted-Text']['Explicit-TLS'] = {'Status': 'supported'}
            else:
                results['Encrypted-Text']['Explicit-TLS'] = {'Status': 'supported but should not'}
            # Fermeture de la connexion SMTP
            smtp.quit()
            
        except smtplib.SMTPException:
            # Si erreur de connexion SMTP
            results['Encrypted-Text']['Explicit-TLS'] = {'Status': 'unsupported'}
            
    def check_implicit_tls(self, 
                           port, 
                           results):
        """
        Cette fonction vérifie si le serveur SMTP prend en charge l'implicit TLS.

        Parameters:
            port (int): Le port sur lequel vérifier l'implicit TLS.
            results (dict): Dictionnaire contenant les résultats du scan.

        Returns:
            results (dict): Dictionnaire contenant les résultats du scan.
        """

        results['Encrypted-Text'] = {}
        
        # Création du socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_for_implicit:
            socket_for_implicit.settimeout(2)
            try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    socket_for_implicit = context.wrap_socket(socket_for_implicit, server_hostname=self.host)
                    socket_for_implicit.connect((self.host, port))
                    response = socket_for_implicit.recv(1024).decode()
                    if response[:3] != '220':
                        results['Encrypted-Text']['Implicit-TLS'] = {'Status': 'unsupported'}
                    elif port == 465:
                        results['Encrypted-Text']['Implicit-TLS'] = {'Status': 'supported'}
                    else:
                        results['Encrypted-Text']['Implicit-TLS'] = {'Status': 'supported but should not'}                        
                    socket_for_implicit.close()
                    return results

            except socket.timeout:
                results['Encrypted-Text']['Implicit-TLS'] = {'Status': 'timeout'}
            except socket.error:
                results['Encrypted-Text']['Implicit-TLS'] = {'Status': 'unsupported'}