import requests
import time
import ssl
from urllib3.exceptions import InsecureRequestWarning
import json
from colorama import init
from colorama import Fore, Back, Style

init()
# Désactivation des avertissements de sécurité pour les requêtes SSL
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class goat:

    def show_banner(self):
        banner = ("""
____________________________________________
                   _  
                  | |
  __ _  ___   __ _| |_        (_(
 / _` |/ _ \ / _` | __|       /_/|_____/)
| (_| | (_) | (_| | |_        `  |      |
 \__, |\___/ \__,_|\__|          |''''''|
  __/ |                          w      w                
 |___/       v.2.1 by Mikb              
____________________________________________\n""")
        print(banner)    
    
    # Fonction pour effectuer la requête vers SSL Labs
    def request_api(self, payload={}):
        """
        Cette fonction effectue la requête vers SSL Labs.
    
        Parameters:
            payload (dict) : Définition des paramètres de la requête
        
        Returns:
            response_ssllabs.json() : Réponse du JSON
        """  
       
        # URL de la v3 de l'API SSLLabs
        url_ssllabs = 'https://api.ssllabs.com/api/v3/analyze'

        # Requête et gestion des exceptions
        try:
            response_ssllabs = requests.get(url_ssllabs, 
                                        params=payload, 
                                        verify=False)
        
        # Exception si réponse autre que 200 
        except requests.exceptions.RequestException:
            pass
    
        # Réponse JSON     
        return response_ssllabs.json()

    def get_information(self, bovidae):
    
        """
        Cette fonction récupère les noms des ciphers utilisés et y associe 
        un niveau de sécurité et une version du protocole utilisé.
    
        Parameters:
            filename (str): Nom du fichier JSON avec les données récupérées via l'API de SSLlabs.
        
        Returns:
            filename (str): Nom du fichier JSON.
        """
        if bovidae["status"] != "READY" or bovidae["endpoints"][0]["statusMessage"] != "Ready":
            return bovidae
        
        i = 0
        # Boucle endpoints
        for endpoint in bovidae["endpoints"]:
            # Boucle sur les suites
            y = 0
            for suite in endpoint["details"]["suites"]:
                # Boucle sur les listes dans chaque suite
                z = 0
                for lists in suite["list"]:
                    # Récupération du nom du cipher
                    cipher_suite_name = lists ["name"]
                    # Génération de l'URL API à partir du nom du cipher
                    url_ciphersuite = f'https://ciphersuite.info/api/cs/{cipher_suite_name}'
                    # Requête API pour récupérer la sécurité du cipher
                    response_ciphersuite = requests.get(url_ciphersuite)   
                    # Chargement des données
                    try:
                        caprini = response_ciphersuite.json()
                    except Exception:
                        bovidae["endpoints"][i]["details"]["suites"][y]["list"][z]["security"] = "insecure"
                    else:
                        # Mise à jour des données dans "bovidae" avec la sécurité du cipher
                        bovidae["endpoints"][i]["details"]["suites"][y]["list"][z]["security"] = caprini[cipher_suite_name]["security"]
                    # Incrémentation de l'index de liste
                    z += 1
                # Incrémentation de l'index de suite
                y += 1    
            i += 1
        # Retourne 'bovidae'
        return bovidae

    def save_report(self,path,name,bovidae):

        json_data = json.dumps(bovidae, indent = 4)
        pathName = path + "/"+ name
        f = open(pathName,"w")
        f.write(json_data)
        f.close()
            
        return
            
        
    
    def new_scan(self, host, table_result_by_ip):
        """
        Cette fonction effectue le scan de 'host' et écrit une première fois dans le JSON.

        Parameters:
            host (str): Nom de l'host à scanner.
            publish (str) : "on" pour publication des résultats en public, la valeur par défaut est "off"
            startNew (str) :  "on" pour lancer un nouveau scan.
            all (str) : "on" pour retourner des informations complètes; "done", pour les renvoyer uniquement si le scan est terminée (statut READY ou ERROR)
            ignoreMismatch (str) : "on" pour continuer les scans si le certificat du serveur ne correspond pas au host, "off" par défaut
        
        Returns:
            filename (str): Nom du fichier JSON avec les données récupérées via l'API de SSLlabs.
        """    

        self.host = host
        # Définition des paramètres de la requête
        payload = {
            'host': host,
            'publish':'on', 
            'startNew':'off',
            'all':'done',
            'fromCache':'on',
            'maxAge': 6, 
            'ignoreMismatch':'on'
        }


        
        points = ["   ",".  ",".. ","..."]
        points_i = 1
        save_last_ip = ""
        new_scan = False
        nb_ip = 0
        already_scanned = []
        to_be_scanned = []
        time.sleep(0.5)
        
        # Appel de la fonction `request_api` (à enlever ?)
        capra = self.request_api(payload)




        if 'errors' in capra:
            return False,0,capra['errors']

        try:
            # Appel de l'API tant que le statut de la requête n'est pas 'READY' ou 'ERROR'    
            while capra['status'] != 'READY' and capra['status'] != 'ERROR':
                
                # on parcourt les endpoints
                if "endpoints" in capra and capra["endpoints"]:
                    for endpoint in capra["endpoints"]:
                        if "ipAddress" in endpoint and endpoint["ipAddress"]:
                            # si l'ip n'est pas déjà dans la liste des ip à scanner
                            if not endpoint["ipAddress"] in to_be_scanned:
                                # on ajoute l'ip à la liste des ip à scanner
                                to_be_scanned.append(endpoint["ipAddress"])
                                #si l'ip est dans la liste table_result_by_ip
                                if endpoint["ipAddress"] in table_result_by_ip:
                                    # on ajoute l'ip à la liste des ip déjà scannées
                                    already_scanned.append(endpoint["ipAddress"])

                # si la liste des ip deja scannées est égale à la liste des ip à scanner et que la liste des ip à scanner n'est pas vide
                if already_scanned == to_be_scanned and to_be_scanned != []:
                    if "status" in capra and capra["status"]:
                        # on met le statut à READY
                        capra["status"] = "READY"
                        endpoints = []
                        for ip_to_scan in to_be_scanned:
                            # ajout du endpoint avec les données de la table table_result_by_ip
                            endpoints.append(table_result_by_ip[ip_to_scan])
                        capra["endpoints"] = endpoints
                        # on quitte la boucle
                        break


                new_scan = True
                time.sleep(0.5)
                capra = self.request_api(payload)
    
                if "endpoints" in capra:
                    for endpoint in capra["endpoints"]:
                            if endpoint["statusMessage"] == "In progress":
                                
                                if save_last_ip != endpoint["ipAddress"]:
                                    if save_last_ip != "":
                                        print("\033[K",Fore.GREEN+Style.DIM+" ├───"+Style.RESET_ALL,save_last_ip," 100%")
                                    save_last_ip = endpoint["ipAddress"]
                                    nb_ip += 1
                                    
                                if points_i == 3:
                                    points_i = 0
                                else:
                                    points_i += 1
                                
                                
                                if "progress" in endpoint:
                                    print("\033[K",Fore.GREEN+Style.DIM+" ├───"+Style.RESET_ALL,save_last_ip," "+str(endpoint["progress"])+"%",points[points_i],Fore.GREEN+" "+endpoint["statusDetails"]+Style.RESET_ALL,end="\r")
                                else:
                                    print("\033[K",Fore.GREEN+Style.DIM+" ├───"+Style.RESET_ALL,endpoint["ipAddress"]," "+str(0)+"%",points[points_i],Fore.GREEN+" "+endpoint["statusDetails"]+Style.RESET_ALL,end="\r")
                            
            if save_last_ip != "":
                print("\033[K",Fore.GREEN+Style.DIM+" ├───"+Style.RESET_ALL,save_last_ip," 100%")
                                    
        except Exception as e:
            return False,0,"Error"    


        # Appel de la fonction `get_information`  
        data = self.get_information(capra)
        return new_scan,nb_ip,data