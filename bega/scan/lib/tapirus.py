#!/usr/bin/python3
from shodan import Shodan
import configparser
import json
from ipaddress import ip_address
import os
import whois
import bega.settings as settings
import sys
import io

class tapirus:

    # Fonction qui valide le format d'une addresse IP.
    # Retourne l'IP si valide sinon retourne None
    def validIPAddress(self, IP: str) -> str:
        try:
            if type(ip_address(IP)):
                return IP
        except ValueError:
            return None

    # Affiche la bannière tapirus.
    # Argument: chemin vers l'ascii art
    # Ne retourne rien
    def show_banner(self):
        banner = ("""
 ⠀⠀⠀⠀⣀⣀⣤⣤⣤⣤⣤⠀⣀⣀⣀
⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⡆⠸⣿⣿⣿⣷⣶⣤⣄⣾⣷⡄
⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡀⠀⠀⠀⠀⠀⠀ _____   ___  ______  _____ ______  _   _  _____
⠀⣤⣤⣤⣈⡉⠛⢿⣿⣿⣿⣿⣿⡆⢸⣿⣿⣿⣿⣿⣿⣿⣿⣧⣽⣿⣷⣄⠀⠀⠀⠀⠀|_   _| / _ \ | ___ \|_   _|| ___ \| | | |/  ___|
⠀⢿⠿⣿⣿⣿⣷⣤⡈⢻⣿⣿⣿⣇⠈⣿⣿⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀  | |  / /_\ \| |_/ /  | |  | |_/ /| | | |\ `--.
⠀ ⠀⢸⣿⣿⣿⣿⠇⠀⠛⠛⠛⠋⠀⢻⣿⣿⡟⢉⠀⠀⠈⠙⠛⠿⠏⣿⣷⠀⠀⠀⠀  | |  |  _  ||  __/   | |  |    / | | | | `--. \\
⠀⠀⢠⣿⣿⡿⠟⢁⡄⠀⠀⠀⠀⠀⠀⠈⣿⣿⡇⣾⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  | |  | | | || |     _| |_ | |\ \ | |_| |/\__/ /
⠀⠀⠸⣿⣿⠀⢸⣿⣇⠀⠀⠀⠀⠀⠀⠀⢹⣿⡇⠸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  \_/  \_| |_/\_|     \___/ \_| \_| \___/ \____/
⠀⠀⠀⠙⠛⠃⠀⠛⠛⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠀⠙⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀by Lotter v2.2

        """)
        print("\n\n")
        print(banner)
        print("\n\n")
        return

    # Fait appel à l'api shodan pour récupérer les infos sur les credits restants de scan.
    # Ne retourne rien
    def info_api(self):
        self.api.info()
        return

    # Réalise un scan IP grace a l'api shodan.
    # Argument: une IP valide
    # Retourne un dictionnaire avec les resultats du scan
    def host_scan(self, ip):
        result = {}

        # Scan IP de shodan
        try: host_scan_resp = self.api.host(ip)
        except: host_scan_resp = None
        
        # Scan whois
        try:
            sys.stdout = open(os.devnull, 'w')
            whois_resp = whois.whois(ip)
            sys.stdout = sys.__stdout__
        except:
             sys.stdout = sys.__stdout__
             return None

        if all(value is None for value in whois_resp.values()):
            whois_resp = None
        else:
            whois_resp = self.whois_datetime_formatter(whois_resp)

        result["whois_ip_scan"] = whois_resp
        
        if(host_scan_resp):
            result["shodan_ip_scan"] = host_scan_resp
        else:
            result["shodan_ip_scan"] = None

        return result


    # Réalise un scan de domaine grace a l'api shodan.
    # Argument: un domain
    # Retourne une liste d'IP et un dictionnaire avec les resultats du scan
    def domain_scan(self, domain):
                
        # Verifie si la clé est valide
        try:
            self.info_api()
        except Exception as e:
            raise

        result = self.api.dns.domain_info(domain=domain)
        # Scan whois
        sys.stdout = io.StringIO()
        whois_resp = whois.whois(domain)
        sys.stdout = sys.__stdout__
        whois_resp = self.whois_datetime_formatter(whois_resp)

        # Ajout du resultat du scan whois au dictionnaire du scan shodan en créant une clé "whois"
        result["whois_domain_scan"] = whois_resp

        ip_list = []
        # Affichage des résultats et récupération des ip associées aux noms de domaines.
        # Ajout de ces ip dans la liste ip_list[]
        for subdomain in result["data"]:
            if self.validIPAddress(subdomain["value"]):
                ip_list.append(subdomain["value"])

        return [*set(ip_list)],result

    # Transforme dans la réponse du scan Whois les datetimes en string formatés
    def whois_datetime_formatter(self, data_whois):
        # Pour le champ "creation_date"
        try: 
            # Si c'est une liste alors on modifie tous les éléments
            if isinstance(data_whois["creation_date"], list):
                for i in range(len(data_whois["creation_date"])):
                    data_whois["creation_date"][i] = data_whois["creation_date"][i].strftime("%Y-%m-%d %H:%M:%S")
            else:
                data_whois["creation_date"] = data_whois["creation_date"].strftime("%Y-%m-%d %H:%M:%S")
        except: pass

        # Pour le champ "expiration_date"
        try: 
            # Si c'est une liste alors on modifie tous les éléments
            if isinstance(data_whois["expiration_date"], list):
                for i in range(len(data_whois["expiration_date"])):
                    data_whois["expiration_date"][i] = data_whois["expiration_date"][i].strftime("%Y-%m-%d %H:%M:%S")
            else:
                data_whois["expiration_date"] = data_whois["expiration_date"].strftime("%Y-%m-%d %H:%M:%S")
        except: pass

        # Pour le champ "updated_date"
        try: 
            # Si c'est une liste alors on modifie tous les éléments
            if isinstance(data_whois["updated_date"], list):
                for i in range(len(data_whois["updated_date"])):
                    data_whois["updated_date"][i] = data_whois["updated_date"][i].strftime("%Y-%m-%d %H:%M:%S")
            else:
                data_whois["updated_date"] = data_whois["updated_date"].strftime("%Y-%m-%d %H:%M:%S")
        except: pass

        return data_whois

    # Permet de sauvgarder le rapport.
    def save_report(self,path,name,data):
        json_data = json.dumps(data, indent = 4)
        pathName = path + "/"+ name
        f = open(pathName,"w")
        f.write(json_data)
        f.close()
        return

    def __init__(self):

        ### GET API KEY ###
        # En premier dans l'argument si non renseigné dans le dossier config.ini
        if os.path.isfile(str(settings.BASE_DIR.parent)+"/config.ini"):
            config = configparser.ConfigParser()
            config.read(str(settings.BASE_DIR.parent)+"/config.ini")
            self.APIKEY = config['API_KEY']['shodan_api_key']
            self.api = Shodan(self.APIKEY)


    def __del__(self):
        # Suppression du fichier google-cookie qui se créer lors du scan shodan
        google_cookie = os.path.dirname(__file__)+"/.google-cookie"
        if os.path.isfile(google_cookie):
            os.remove(google_cookie)
