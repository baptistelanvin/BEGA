from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render, redirect
from scan.forms import ScanForm
from scan.models import Scan, Report
from django.contrib.auth.decorators import login_required, permission_required
from .lib.badger import badger as badger
from .lib.tapirus import tapirus as tapirus
from .lib.goat import goat as goat
from .lib.kangaroo import kangaroo as kangaroo
from .lib.owl import owl  as owl
from colorama import init
from colorama import Fore, Style
import argparse
import datetime
import os
import time
import re
import dns.resolver
import json
import ipaddress
from signal import signal, SIGINT
import sys
import bega.settings as settings
import ipaddress

def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def home(request):
   return render(request,'scan/home.html')

def legal(request):
    return render(request,'scan/legal.html')


@login_required
@permission_required('scan.create', raise_exception=True)
def scan_create(request):
    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            scan = form.save()
            return redirect('scan-detail', scan.id)
    else:
        form = ScanForm()

    return render(request,
            'scan/scan_create.html',
            {'form': form})

@login_required
def scan_list(request):
    if request.user.is_superuser:
        scans = Scan.objects.all()
    else:
        scans = Scan.objects.filter(user=request.user)
    
    return render(request, 'scan/scan_list.html', {'scans': scans})

    

@login_required
def scan_detail(request, id):
   scan = Scan.objects.get(id=id)
   return render(request,
          'scan/scan_detail.html',
         {'scan': scan})

@login_required
def scan_update(request, id):
    scan = Scan.objects.get(id=id)
    if request.method == 'POST':
        form = ScanForm(request.POST, instance=scan)
        if form.is_valid():
            form.save()
            return redirect('scan-detail', scan.id)
    else:
        form = ScanForm(instance=scan)
    return render(request,
        'scan/scan_update.html',
            {'form': form})

@login_required
def scan_delete(request, id):
    scan = Scan.objects.get(id=id)

    if request.method == 'POST':
        scan.delete()
        return redirect('scan-list')

    return render(request,
                    'scan/scan_delete.html',
                    {'scan': scan})


@login_required
def report_list(request):
    if request.user.is_superuser:
        reports = Report.objects.all()
    else:
        reports = Report.objects.filter(user=request.user)
    
    return render(request, 'scan/report_list.html', {'reports': reports})

@login_required
def report_detail(request, id):
    report = get_object_or_404(Report, id=id)
    domain = report.data.get('tapirus', {}).get('domain', {})
    badger_data = report.data.get('badger', {}).get(report.scan.domain_name, {})

    for email_info in badger_data.get('emails_leaked', []):
        email_info['total_leaks'] = len(email_info.get('leaks_with_passwords', [])) + len(email_info.get('leaks_without_passwords', []))

    date = '-'.join(report.name.split('-')[0:6])
    path =  f"{settings.BASE_DIR.parent}/reports/{report.name}/{date}-shodan-{report.scan.domain_name}.json"
    with open(path) as f:
        data_shodan = json.load(f)
    
    data_shodan= data_shodan['data']
    table_ip = dict()
    for element in data_shodan:
        if element['subdomain'] != "" and (is_valid_ip(element['value'])):
            if element['value'] in table_ip:
                table_ip[element['value']].append(element['subdomain'])
            else : 
                table_ip[element['value']] =  [element['subdomain']]
    
    path =  f"{settings.BASE_DIR.parent}/reports/{report.name}/{date}-shodan-{report.scan.domain_name}.json"
    with open(path) as f:
        data_shodan = json.load(f)
    


    return render(request,
          'scan/report_detail.html',
         {'report': report, 'domain' : domain,'badger': badger_data, 'table_ip' : table_ip})

@login_required
def report_delete(request, id):
    report = Report.objects.get(id=id)

    if request.method == 'POST':
        report.delete()
        return redirect('report-list')

    return render(request,
                    'scan/report_delete.html',
                    {'report': report})

# fonction pour l'appel de tapirus et traitement / affichage des résultats.
# domainName peut être un nom de domaine ou une lise d'ip
def start_tapirus_scan(domainName, isAnIpScan, timestamp, tapir, dir_path):

    print(Fore.GREEN+" [+]"+Fore.RESET+" Starting Shodan scan(s)...")
    
    ################################################
    # debut section scan de domaine

    # si l'argument domainName n'est pas une ip, on lance le scan de domaine
    if not isAnIpScan: 
        print(Fore.GREEN+Style.DIM+"  ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" domain scan..."+Fore.CYAN+" "+domainName+Fore.RESET)

        try:
            # on lance le scan de domaine
            # retourne la liste d'ip pour lancer le scan shodan ip et un dictionnaire de résultats du scan de domaine
            all_ip,result_domain_scan = tapir.domain_scan(domainName)
        except Exception as e:
            # si l'erreur est "Invalid API key", on affiche un message d'erreur
            if str(e) == "Invalid API key":
                print("\x1b[A\x1b[F\033[2K",Fore.GREEN+"[+]"+Fore.RESET+" Starting Shodan failed !",Fore.RED+"[Invalid API key]"+Fore.RESET,end="\n\033[2K")
            # sinon on affiche une erreur générique
            else:
                print("\x1b[A\x1b[F\033[2K",Fore.GREEN+"[+]"+Fore.RESET+" Starting Shodan failed !",Fore.RED+"["+str(e)+"]"+Fore.RESET,end="\n\033[2K")
            return None
        else:
            # si le scan de domaine s'est bien passé, on affiche un message de réussite
            print("\x1b[F" +Fore.GREEN+Style.DIM+"  ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" domain scan" +Fore.CYAN+" "+domainName+ Fore.GREEN + " [OK]"+Fore.RESET)

        # on initialise le dictionnaire de résultats du scan IP
        result_domain_scan["dataSubdomainsIPscan"] = {}
    else:
        # on initialise le dictionnaire de résultats du scan IP
        result_domain_scan = {}
        result_domain_scan["dataSubdomainsIPscan"] = {}
        # si l'argument domainName est une liste d'ip, on initialise la liste d'ip interne avec cette liste
        all_ip = domainName
    
    print(Fore.GREEN+Style.DIM+"  ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" ip scans ("+str(len(all_ip))+") limit 5: " + Fore.RESET)
    
    #fin de la section scan de domaine
    ################################################


    ################################################
    # section scan d'ip
    # boucle sur chaque ip
    for i, ip in enumerate(all_ip):
        
        #### ADD FOR TEST ####
        if i > 4:
            break

        print(Fore.GREEN+Style.DIM+"  │  ├─ "+Style.RESET_ALL+Fore.RESET+Fore.CYAN + ip + Fore.RESET)
        
        #getion de l'affichage des resultats
        dot = ' │  ├─ '
        if i == len(all_ip) - 1:
            dot = ' │  └─ '

        try:
            # on lance le scan shodan ip
            result = tapir.host_scan(ip)
        except:
            # si erreur, on affiche un message d'erreur
            print("\x1b[F","{:<45} {:<5}".format(Fore.GREEN+Style.DIM+dot+Style.RESET_ALL+Fore.RESET+Fore.CYAN + ip , Fore.RED + " [ERROR]"+Fore.RESET))

        # si le resultat n'est pas vide, on l'ajoute au dictionnaire de résultats du scan de domaine
        if result:
            print("\x1b[F","{:<45} {:<5}".format(Fore.GREEN+Style.DIM+dot+Style.RESET_ALL+Fore.RESET+Fore.CYAN + ip , Fore.GREEN + " [OK]"+Fore.RESET))
            result_domain_scan["dataSubdomainsIPscan"][str(ip)] = result
        # sinon on affiche un message d'erreur
        else:
            print("\x1b[F","{:<45} {:<5}".format(Fore.GREEN+Style.DIM+dot+Style.RESET_ALL+Fore.RESET+Fore.CYAN + ip , Fore.RED + " [NO RESULT]"+Fore.RESET))
    # fin de la section scan d'ip
    ################################################

    # si uniquement des ip ont été scannées, on modifie le nom du rapport
    if isAnIpScan:    
        name_report = timestamp+"-shodan-ScanIP.json"
    else:
        name_report = timestamp+"-shodan-" + domainName+".json"

    # on sauvegarde le rapport    
    print(Fore.GREEN+" [+]"+Fore.RESET+" Saving report...")
    tapir.save_report(dir_path,name_report,result_domain_scan)
    print("\x1b[F"+Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" 1 report have been saved in \"" + dir_path + "/" + name_report+"\"")

    # on retourne le dictionnaire de résultats du scan Shodan
    return result_domain_scan

# fonction d'appel du scan goat pour un seul domaine
# domainName : nom de domaine
# table_result_by_ip : dictionnaire de résultats du scan shodan
def goat_scan(domainName, table_result_by_ip, goa, timestamp):
    print("\033[2K"+Fore.GREEN+Style.DIM+"  ├─ "+Style.RESET_ALL+Fore.CYAN+domainName+Fore.RESET)

    # on lance le scan goat
    try:
        new_scan,nb_ip,result_goat_scan = goa.new_scan(domainName,table_result_by_ip)
    except Exception as e:
        # si erreur, on definit les variables de retour
        new_scan,nb_ip,result_goat_scan = False,0,"Error"

    # si le scan goat a retourné une erreur, on affiche un message d'erreur
    if result_goat_scan == "Error":
        # different affichage si le domaine est nouveau ou non
        if new_scan:
            print("\033[A\033[F\033[2K","{:<52} {:<5}".format(Fore.GREEN+Style.DIM+" ├─ "+Style.RESET_ALL+Fore.CYAN+domainName+Fore.RESET,Fore.MAGENTA+" [Error]"+Fore.RESET))
        else:
            print("\033[A\033[2K","{:<52} {:<5}".format(Fore.GREEN+Style.DIM+" ├─ "+Style.RESET_ALL+Fore.CYAN+domainName+Fore.RESET,Fore.MAGENTA+" [Error]"+Fore.RESET))
        # on retourne les variables de retour
        return True, result_goat_scan

    # on recupere le status du scan goat si il n'est pas defini a READY
    status = ""
    if "status" in result_goat_scan and result_goat_scan["status"] != "READY":
        status = result_goat_scan["statusMessage"]
    
    # on recupere le status des endpoints du scan goat si il n'est pas defini a READY
    if "endpoints" in result_goat_scan:
        if result_goat_scan["endpoints"][0]["statusMessage"] != "Ready":
            status = result_goat_scan["endpoints"][0]["statusMessage"]
                    

    # si le scan goat a retourné un status d'erreur, on l'affiche
    if status != "":
        if new_scan:
            print("\033[A\033[2K","{:<52} {:<5}".format(Fore.GREEN+Style.DIM+" ├─ "+Style.RESET_ALL+Fore.CYAN+domainName+Fore.RESET,Fore.RED+" ["+status+"]"+Fore.RESET))
        else:
            print("\033["+str(nb_ip+1)+"A\r\033[2K","{:<52} {:<5}".format(Fore.GREEN+Style.DIM+" ├─ "+Style.RESET_ALL+Fore.CYAN+domainName+Fore.RESET,Fore.RED+" ["+status+"]"+Fore.RESET),"\033["+str(nb_ip)+"B",end="\r")
        
        # on sauvegarde le rapport
        goat_save_report(domainName,result_goat_scan, goa, timestamp)
        return True, result_goat_scan


    # si new_scan est vrai, on affiche le message de succes
    if new_scan or nb_ip != 0:
        print("\033["+str(nb_ip+1)+"A\r\033[2K","{:<47} {:<5}".format(Fore.GREEN+Style.DIM+" ├─ "+Style.RESET_ALL+Fore.CYAN + domainName , Fore.GREEN + " [OK]"+Fore.RESET),"\033["+str(nb_ip)+"B")
    else:
        print("\033[A\033[2K","{:<47} {:<5}".format(Fore.GREEN+Style.DIM+" ├─ "+Style.RESET_ALL+Fore.CYAN + domainName , Fore.GREEN + " [OK]"+Fore.RESET))


    # on sauvegarde le rapport
    goat_save_report(domainName,result_goat_scan, goa, timestamp)

    # on retourne les variables de retour
    return True, result_goat_scan

# fonction permettant de sauvegarder le rapport du scan goat, un fichier par sous domaine
# domainName : nom de domaine
# result_goat_scan : dictionnaire de résultats du scan goat

def goat_save_report(domainName,result_goat_scan, goa, timestamp, dir_path):
    # on formate le nom du rapport
    name_report = timestamp+"-ssllabs-"+domainName+".json"
    dir_path_goat = dir_path + "/goat"
    # on cree le dossier goat s'il n'existe pas
    os.makedirs(dir_path_goat, exist_ok=True)
    # on sauvegarde le rapport
    goa.save_report(dir_path_goat,name_report,result_goat_scan)

# fonction permettant de preparer le lancement du scan goat
# domainName : nom de domaine
# shodan_result : dictionnaire de résultats du scan shodan
def start_goat_scan(domainName,shodan_result, goa, timestamp, dir_path):

    # si le scan shodan a échoué, on ne lance pas le scan goat
    if not shodan_result:
        print(Fore.GREEN+"\n [+]"+Fore.RESET+" Starting SSLlabs scan(s) failed !",Fore.RED+"[No Shodan scan]"+Fore.RESET)
        return

    # on récupère les sous-domaines que l'on copie dans une nouvelle liste
    #subdomain_and_domain = shodan_result["subdomains"].copy()
    subdomain_and_domain = shodan_result["subdomains"].copy()[0:5]

    # on supprime les sous-domaines qui sont "*"
    subdomain_and_domain = [x for x in subdomain_and_domain if x != "*"]

    # on récupère le domaine principal
    main_domain = shodan_result["domain"]

    # on assemble les sous-domaines avec le domaine principal pour avoir des noms de domaine complets
    for i in range(len(subdomain_and_domain)):
        subdomain_and_domain[i] += ("."+main_domain)
    subdomain_and_domain.insert(0,domainName)

    nb_saved_report = 0
    print(Fore.GREEN+"\n [+]"+Fore.RESET+" Starting",len(subdomain_and_domain),"SSLlabs scan(s)...")

    # en premier on lance un scan goat pour chaque sous-domaine sans attendre la fin du scan précédent. Cela permet de gagner du temps 
    for subdomain in subdomain_and_domain:
        time.sleep(0.5)
        
        # payload: 
        # publish a on pour publier le rapport dans la bdd ssllabs
        # startNew a off pour ne pas relancer un scan si un scan recent existe deja
        # all a done pour attendre le resultat complet du scan
        # fromCache a on pour utiliser le cache si un scan recent existe deja
        # maxAge a 6 , 6h max pour utiliser le cache
        # ignoreMismatch a on pour ignorer les certificats qui ne correspondent pas au domaine

        payload = {
        'host': subdomain,
        'publish':'on', 
        'startNew':'off',
        'all':'done',
        'fromCache':'on',
        'maxAge': 6, 
        'ignoreMismatch':'on'
        }
        rep = goa.request_api(payload)
        
    table_result_by_ip = {}

    # on lance un scan goat pour chaque sous-domaine en attendant la fin du scan précédent
    for subdomain in subdomain_and_domain:
        
        try:
            # la fonction goat_scan retourne un booléen indiquant si le scan a réussi et un dictionnaire contenant les résultats du scan
            success, result_ip = goat_scan(subdomain, table_result_by_ip, goa, timestamp)
        except:
            success= False
            result_ip = {}
            pass

        print(success, result_ip)

        # si le scan a réussi, on incrémente le nombre de rapport sauvegardé
        if success: nb_saved_report += 1

        # ajout des résultats du scan par ip dans la table des résultats globale
        if "endpoints" in result_ip and result_ip["endpoints"]:
            for endpoint in result_ip["endpoints"]:
                if endpoint["statusMessage"] == "Ready":
                    if not endpoint["ipAddress"] in table_result_by_ip:
                        table_result_by_ip[endpoint["ipAddress"]] = endpoint

    # on sauvegarde les résultats globaux dans un fichier json
    print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-] "+Fore.RESET+str(nb_saved_report)+" reports have been saved in \"" + dir_path + "\goat\\"+"\"")

# fonction permettant de lancer un scan goat
# shodan_result : dictionnaire de résultats du scan shodan

def start_owl_scan(shodan_result, timestamp, uwu, dir_path):

    # si le scan shodan a échoué, on ne lance pas le scan goat et on affiche un message d'erreur
    if not shodan_result:
        print(Fore.GREEN+"\n [+]"+Fore.RESET+" Starting MX scan(s) failed !",Fore.RED+"[No Shodan scan]"+Fore.RESET)
        return


    nb_report = 0
    nb_mx = 0

    # on compte le nombre de MX
    if "data" in shodan_result:
        for item in shodan_result["data"]:
            if "type" in item:
                if item["type"] == "MX":
                    nb_mx += 1

    # on affiche le nombre de MX a scanner
    print(Fore.GREEN+"\n [+]"+Fore.RESET+" Starting",str(nb_mx),"MX scan(s)...")

    # on lance un scan owl pour chaque MX
    if "data" in shodan_result:
        for item in shodan_result["data"]:
            if "type" in item:
                if item["type"] == "MX":
                    mx = item["value"]
                    print(Fore.GREEN+Style.DIM+"  ├──"+Style.RESET_ALL+Fore.RESET+" Scanning:",Fore.CYAN+"MX:"+mx+Fore.RESET,"...")
                    # on lance le scan owl avec le MX et l'adresse mail fournier.e2203147@etud.univ-ubs.fr
                    owl_result = uwu.owl_scan(mx,"fournier.e2203147@etud.univ-ubs.fr")
                    

                    for port in owl_result['Host']['Port'].values():
                        # si le port est ouvert, on affiche un message de succès
                        if port['Status'] != 'close':
                            print("\x1b[A","{:<71} {:<5}".format(Fore.GREEN+Style.DIM+" ├──"+Style.RESET_ALL+Fore.RESET+" Scanning:"+Fore.CYAN+" MX:"+mx+Fore.RESET,Fore.GREEN+"[OK]"+Fore.RESET))
                            break
                    # sinon on affiche un message d'erreur
                    else:
                        print("\x1b[A","{:<71} {:<5}".format(Fore.GREEN+Style.DIM+" ├──"+Style.RESET_ALL+Fore.RESET+" Scanning:"+Fore.CYAN+" MX:"+mx+Fore.RESET,Fore.RED+"[CLOSED]"+Fore.RESET))

                    # on sauvegarde le rapport dans un fichier json
                    name_report = timestamp+"-owl-"+mx+".json"
                    dir_path_owl = dir_path + "/owl"
                    os.makedirs(dir_path_owl, exist_ok=True)
                    uwu.save_report(dir_path_owl,name_report,owl_result)
                    # on incrémente le nombre de rapport sauvegardé
                    nb_report += 1
    # si le nombre de rapport sauvegardé est supérieur à 0, on affiche un message de succès
    if nb_report > 0:
        print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-] "+Fore.RESET+str(nb_report)+" reports have been saved in \"" + dir_path + "/owl/"+"\"")

# fonction permettant de lancer un scan kangaroo
# domain : domaine à scanner
# dkim (liste): [selector, domain] 
def start_kangaroo_scan(domain,dkim, kanga, timestamp, dir_path):

    nb_report = 0

    print(Fore.GREEN+"\n [+]"+Fore.RESET+" Starting DNS scan...")


    print(Fore.GREEN+Style.DIM+"  └──"+Style.RESET_ALL+Fore.RESET+" Scanning:",Fore.CYAN+domain+Fore.RESET,"...")
    try:
        # on lance le scan kangaroo avec le domaine et le dkim dans un try catch
        result_kangaroo_scan = kanga.start_scan(domain,"1.1.1.1",dkim)
        print("\x1b[A",Fore.GREEN+Style.DIM+" ├──"+Style.RESET_ALL+Fore.RESET+" Scanning: "+Fore.CYAN+domain+Fore.RESET,Fore.GREEN+" [OK]"+Fore.RESET)
        
        # on sauvegarde le rapport dans un fichier json
        name_report = timestamp+"-dnsrecords-"+domain+".json"
        dir_path_kangaroo = dir_path + "/kangaroo"
        os.makedirs(dir_path_kangaroo, exist_ok=True)
        kanga.save_report(dir_path_kangaroo,name_report,result_kangaroo_scan)
        # on incrémente le nombre de rapport sauvegardé
        nb_report += 1
    # si erreur dns.resolver.NXDOMAIN, on affiche un message d'erreur pour dire que l'enregistrement n'existe pas
    except dns.resolver.NXDOMAIN as e:
        print("\x1b[A\x1b[F\033[2K"+Fore.GREEN+" [+]"+Style.RESET_ALL+Fore.RESET+" Starting DNS scan failed ! "+Fore.RESET,Fore.RED+"[DNS query doesn't exist]"+Fore.RESET,end="\n\033[2K")    
        pass
    
    # sinon on affiche l'erreur
    except Exception as e: 
        print("\x1b[A\x1b[F\033[2K"+Fore.GREEN+" [+]"+Style.RESET_ALL+Fore.RESET+" Starting DNS scan failed ! "+Fore.RESET,Fore.RED+"["+str(e)+"]"+Fore.RESET,end="\n\033[2K")
        pass
    
    # si le nombre de rapport sauvegardé est supérieur à 0, on affiche un message de succès
    if nb_report > 0:
        print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-] "+Fore.RESET+str(nb_report)+" report have been saved in \"" + dir_path + "/kangaroo/"+"\"")

# fonction permettant de lancer un scan badger
# domain : domaine à scanner

def start_badger_scan(domain, pattern, badg, timestamp, args, dir_path):
    print(Fore.GREEN+"\n [+]"+Fore.RESET+" Starting mails scan...")

    # on formate le dork
    dork = "site:linkedin.com/in + intitle:"+str(".".join(list(domain.split("."))[:-1]))
    # argument pour limiter le nombre de résultat à 10 par défaut
    limit = args["limit"]

    print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Google dork:"+Fore.CYAN+" '"+dork+"'"+Fore.RESET+ " (limit: "+str(limit)+")")
    
    # on lance le scan badger avec le domaine et la limite 
    result_dorks = badg.perform_dorks(domain,limit)
    
    # si le nombre de résultat est supérieur à 0, on affiche un message de succès ainsi que le nombre de mails trouvés
    if type(result_dorks) != bool:
        if len(result_dorks) > 0:
            print("\x1b[F\033[2K",Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Google dork:"+Fore.CYAN+" '"+dork+"'"+Fore.GREEN+" [OK]"+Fore.RESET)
            print(Fore.GREEN+Style.DIM+"  │  └─ "+Style.RESET_ALL+Fore.RESET+Fore.WHITE + Style.DIM+"(" +str(len(result_dorks)) + " link(s) found)"+Fore.RESET)
        # sinon on affiche un message d'erreur
        elif len(result_dorks) == 0:
            print("\x1b[F\033[2K",Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Google dork:"+Fore.CYAN+" '"+dork+"'"+Fore.RED+" [No result]"+Fore.RESET)

    elif result_dorks == False:
        print("\x1b[F\033[2K",Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Google dork:"+Fore.CYAN+" '"+dork+"'"+Fore.RED+" [Too Many Requests]"+Fore.RESET)
        result_dorks = []

    # fonction qui permet d'extraire les noms des personnes depuis les liens linkedin
    extracted_names = badg.extract_names(domain, result_dorks)
    # fonction qui permet de formater des mails depuis les noms des personnes
    result_craft_mails = badg.craft_mails(extracted_names,domain,pattern)
    
    # lancement de emails finder
    print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Emails finder ...")
    result_emails_finder = badg.emails_finder(domain, False)

    # si le resultat de emails finder est supérieur à 0, on affiche un message de succès ainsi que le nombre d'emails trouvés
    if len(result_emails_finder) > 0:
        print("\x1b[F\033[2K",Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Emails finder" + Fore.GREEN + " [OK]"+Fore.RESET)
        print(Fore.GREEN+Style.DIM+"  │  └─ "+Style.RESET_ALL+Fore.RESET+Fore.WHITE + Style.DIM+"(" +str(len(result_emails_finder)) + " email(s) found)"+Fore.RESET+Style.RESET_ALL)
    # sinon on affiche un message d'erreur
    else:
        print("\x1b[F\033[2K",Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Emails finder:"+Fore.RED+" [NO RESULT]"+Fore.RESET)

    # on concatène les résultats de emails finder et de craft mails, on supprime les doublons et on trie la liste
    concat_all_emails = list(dict.fromkeys(result_emails_finder + [sous_liste[0] for sous_liste in result_craft_mails]))

    # on lance une recherche de mails dans le dossier de tous les résultats de Bega
    emails_searched = search_mails_in_file_results(domain, dir_path)
    # on concatène les résultats avec les résultats précédents, on supprime les doublons
    concat_all_emails = list(set(concat_all_emails + emails_searched))
    # on trie la liste
    concat_all_emails = sorted(concat_all_emails)

    # si la liste d'emails est supérieure à 0, on affiche un message de succès.
    if len(concat_all_emails) > 0:
        print(Fore.GREEN+Style.DIM+"  ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" HIBP scan ("+str(len(concat_all_emails))+"):")
        # on lance le scan HIBP avec la liste d'emails
        breaches,result_check_leaks = badg.check_leaks(concat_all_emails,None, True)
        
        # si le résultat est 'Error' 'ConnectTimeout' ou si le code de retour est 401, on affiche un message d'erreur
        if result_check_leaks == "Error":
            print("\x1b[F\033[2K\033[A",Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" HIBP scan failed !"+Fore.RED+"[ERROR] "+Fore.RESET)

        if result_check_leaks == "ConnectTimeout":
            print("\x1b[F\033[2K\033[A",Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" HIBP scan failed !"+Fore.RED+"[ERROR ConnectTimeout] "+Fore.RESET)      

        if "statusCode" in result_check_leaks and result_check_leaks["statusCode"] == 401:
            print("\x1b[F\033[2K\033[A",Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" HIBP scan failed !"+Fore.RED+"[ERROR] "+result_check_leaks["message"]+Fore.RESET)

        # creation du dossier badger
        name_report = timestamp+"-emails-"+domain+".json"
        dir_path_badger = dir_path + "/badger"
        os.makedirs(dir_path_badger, exist_ok=True)
        try:
            # on enregistre le rapport dans le dossier badger
            badg.make_report(dir_path_badger,name_report,domain, result_dorks, extracted_names, result_craft_mails, result_emails_finder, breaches, result_check_leaks)
            print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" 1 report have been saved in \"" + dir_path + "/badger/"+"\"")
        except Exception as e:
            return
    # si le nombre d'emails est égal à 0, on affiche un message d'erreur
    else:
        print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" HIBP scan: "+ Fore.RED+" [NO RESULT]"+Fore.RESET)
        return

# fonction qui permet de rechercher des mails dans des json dans un dossier
def search_mails_in_file_results(domain, folder):
    # regex pour trouver des mails
    regex = r'[a-zA-Z0-9._%+-]+@{}'.format(re.escape(domain))
    list_emails = []
    # on parcourt tous les fichiers du dossier folder et de ses sous-dossiers
    for root, dirs, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root, file)
            # on ouvre le fichier et on récupère son contenu
            with open(file_path, 'r') as f:
                contents = f.read()
                # on recherche les mails dans le contenu du fichier
                emails = re.findall(regex, contents)
                # on ajoute les mails trouvés dans la liste list_emails
                for mail in emails:
                    list_emails.append(mail)
    
    # on supprime les doublons et on trie la liste
    
    list_emails = sorted(set(list_emails))
    return list_emails

def analyze_results(domainName, isAnIpScan, dir_path, timestamp):
    print(Fore.GREEN+"\n [+]"+Fore.RESET+" Analyzing results...")
    
    # recuperation de tous les fichier dans le dossier dir_path à analyser
    all_files_path = []
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            file_path = os.path.join(root, file)
            all_files_path.append(file_path)

    # initialisation du dictioanire qui contiendra tous les resultats
    report_of_all_data = {}


    ################################################
    # debut section analyse des resultats de shodan

    print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Shodan:")
    

    #format du dictionnaire shodan_result{}:

    '''
    "tapirus": {
        "domain": {
            "domainScanned": "exemple.com",
            "subdomains_count": 1,
            "list_of_subdomains": [
                "sub.exemple.com"
            ],
            "how_many_vulns_by_ip": {
                "1.1.1.1": 10
            },
            "open_ports_by_ip": {
                "1.1.1.1": [
                    80,
                    443
                ]
            },
            "MX_count": 1,
            "NS_count": 2,
            "CNAME_count": 3,
            "SOA_count": 4
        }
    }
    '''

    # initialisation des variables par defaut
    shodan_result = {}
    
    subdomains_count = 0
    list_subdomains = []
    how_many_vulns_by_ip = {}
    open_ports_by_ip = {}
    open_ports = []
    mx_count = 0
    ns_count = 0
    cname_count = 0
    soa_count = 0

    # parcours de tous les fichiers
    for files in all_files_path:
        # si le fichier est un fichier shodan
        if str(timestamp+"-shodan") in files:
            # on l'ouvre et on le charge en json
            with open(files, 'r') as f:
                contents = f.read()
                shodan_file_data = json.loads(contents)
                
                # si les fichiers sont uniquement des scans de domaines
                if not isAnIpScan:
                    
                    # initialisation du dictioanire qui contiendra tous les resultats
                    shodan_scan_domain = {}

                    # recuperation du nombre de sous domaines et de leurs noms
                    # variables : subdomains_count, list_subdomains

                    if "subdomains" in shodan_file_data and shodan_file_data["subdomains"]:
                        subdomains_count += len(shodan_file_data["subdomains"])
                        for subdomain in shodan_file_data["subdomains"]:
                            list_subdomains.append(subdomain+"."+domainName)

                    # recuperation du nombre de vulnérabilités par ip
                    if "dataSubdomainsIPscan" in shodan_file_data and shodan_file_data["dataSubdomainsIPscan"]:
                        for ip,data_scan_ip in shodan_file_data["dataSubdomainsIPscan"].items():
                            if "shodan_ip_scan" in data_scan_ip and data_scan_ip["shodan_ip_scan"]:
                                if "vulns" in data_scan_ip["shodan_ip_scan"] and data_scan_ip["shodan_ip_scan"]["vulns"]:
                                    if len(data_scan_ip["shodan_ip_scan"]["vulns"]) > 0:
                                        how_many_vulns_by_ip[ip] = len(data_scan_ip["shodan_ip_scan"]["vulns"])

                    # recuperation du nombre d'enregistrements DNS par type
                    if "data" in shodan_file_data and shodan_file_data["data"]:
                        for data in shodan_file_data["data"]:
                            if "type" in data and data["type"]:
                                if data["type"] == "MX":
                                    mx_count += 1
                                
                                if data["type"] == "NS":
                                    ns_count += 1

                                if data["type"] == "CNAME":
                                    cname_count += 1
                                
                                if data["type"] == "SOA":
                                    soa_count += 1
                            
                            # recuperation du nombre de ports ouverts par ip
                            if "ports" in data and data["ports"] and "value" in data and data["value"]:
                                open_ports_by_ip[data["value"]] = data["ports"]

                    
                    # ajout des resultats dans le dictionnaire shodan_scan_domain
                    shodan_scan_domain["domainScanned"] = domainName 
                    shodan_scan_domain["subdomains_count"] = subdomains_count
                    shodan_scan_domain["list_of_subdomains"] = list_subdomains
                    shodan_scan_domain["how_many_vulns_by_ip"] = how_many_vulns_by_ip
                    shodan_scan_domain["open_ports_by_ip"] = open_ports_by_ip
                    shodan_scan_domain["MX_count"] = mx_count
                    shodan_scan_domain["NS_count"] = ns_count
                    shodan_scan_domain["CNAME_count"] = cname_count
                    shodan_scan_domain["SOA_count"] = soa_count
                    
                    # ajout des resultats dans le dictionnaire shodan_result avec la clé "nom_de_domaine"
                    if "domain" in shodan_file_data and shodan_file_data["domain"]:
                        shodan_result["domain"] = shodan_scan_domain
                
                # si les fichiers sont uniquement des scans d'ip
                else:
                    
                    # recuperation du nombre de vulnérabilités par ip et des ports ouverts par ip
                    if "dataSubdomainsIPscan" in shodan_file_data and shodan_file_data["dataSubdomainsIPscan"]:
                        for ip,data_scan_ip in shodan_file_data["dataSubdomainsIPscan"].items():
                            # initialisation du dictionnaire qui contiendra les données par ip
                            shodan_data_ip = {}
                            if "shodan_ip_scan" in data_scan_ip and data_scan_ip["shodan_ip_scan"]:
                                if "vulns" in data_scan_ip["shodan_ip_scan"] and data_scan_ip["shodan_ip_scan"]["vulns"]:
                                    if len(data_scan_ip["shodan_ip_scan"]["vulns"]) > 0:
                                        # ajout du nombre de vulnérabilités par ip
                                        how_many_vulns_by_ip[ip] = len(data_scan_ip["shodan_ip_scan"]["vulns"])
                            
                                if "data" in data_scan_ip["shodan_ip_scan"] and data_scan_ip["shodan_ip_scan"]["data"]:
                                    for dat in data_scan_ip["shodan_ip_scan"]["data"]:
                                        if "port" in dat and dat["port"]:
                                            # ajout des ports ouverts par ip
                                            open_ports.append(dat["port"])

                            # ajout des resultats dans le dictionnaire shodan_data_ip avec la clé "ip"
                            shodan_data_ip["how_many_vulns_by_ip"] = how_many_vulns_by_ip
                            shodan_data_ip["open_ports"] = open_ports
                            shodan_result[ip] = shodan_data_ip


    # si shodan_result n'est pas vide on affiche un message de succes
    if shodan_result:
        print("\x1b[F\033[2K","{:<40} {:<5}".format(Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Shodan",Fore.GREEN+"[OK]"+Fore.RESET))
    # sinon on affiche un message d'erreur
    else:
        print("\x1b[F\033[2K","{:<40} {:<5}".format(Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Shodan",Fore.YELLOW+"[Empty]"+Fore.RESET))      

    # fin de la section shodan
    ################################################

    ################################################
    # debut de la section analyse du scan ssl

    print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Goat:")


    #format du dictionnaire goat_result{}:

    '''
    "goat": {
        "sub.exemple.com": {
            "1.1.1.1": {
                "TLS_1.2": {
                    "secure": 5
                }
            }
        }
    }
    '''

    goat_result = {}

    # recuperation des fichiers de scan ssl
    for files in all_files_path:
        # si le fichier est un scan ssl
        if  str(timestamp+"-ssllabs") in files:
            # on ouvre le fichier et on recupere son contenu dans un dictionnaire
            with open(files, 'r') as f:
                contents = f.read()
                goat_file_data = json.loads(contents)

                if "endpoints" in goat_file_data and goat_file_data["endpoints"]:
                    domain_scan_ssl = {}
                    ready = False
                    # on parcours les endpoints du scan
                    for endpoint in goat_file_data["endpoints"]:
                        # si le scan est terminé
                        if "statusMessage" in endpoint and endpoint["statusMessage"] == "Ready":
                            ip_endpoint_scan_ssl = {}
                            ready = True
                            if "details" in endpoint and "suites" in endpoint["details"] and endpoint["details"]["suites"]:
                                # on parcours les suites de chiffrement du scan
                                for suite in endpoint["details"]["suites"]:
                                    tls_version_scan = {}
                                    if "list" in suite and suite["list"]:
                                        # on parcours les ciphers de la suite de chiffrement
                                        for cipher in suite["list"]:
                                            if 'name' in cipher and 'security' in cipher and cipher["name"] and cipher["security"]:
                                                if cipher["security"] in tls_version_scan:
                                                    # on ajoute 1 au nombre de fois que le cipher est utilisé
                                                    tls_version_scan[cipher["security"]] += 1
                                                else:
                                                    # on initialise le nombre de fois que le cipher est utilisé à 1
                                                    tls_version_scan[cipher["security"]] = 1
                                        protocol_name = "unknow_protocol_name"
                                        if "protocols" in endpoint["details"] and endpoint["details"]["protocols"]:
                                            # on parcours les protocoles du scan
                                            for proto in endpoint["details"]["protocols"]:
                                                # si l'id du protocole est le même que celui de la suite de chiffrement
                                                if proto["id"] == suite["protocol"]:
                                                    # on cree le nom du protocole
                                                    protocol_name = "TLS_"+proto["version"]

                                        # on ajoute les resultats du scan ssl dans le dictionnaire ip_endpoint_scan_ssl avec la clé du nom du protocole
                                        if tls_version_scan != {}:
                                            ip_endpoint_scan_ssl[protocol_name] = tls_version_scan

                            # on ajoute les resultats du scan ssl dans le dictionnaire domain_scan_ssl avec la clé de l'ip
                            domain_scan_ssl[endpoint["ipAddress"]] = ip_endpoint_scan_ssl
                        
                        # si le scan a terminé
                        if ready:
                            # on ajoute les resultats du scan ssl dans le dictionnaire goat_result avec la clé du nom du domaine
                            goat_result[goat_file_data["host"]] = domain_scan_ssl

    # si goat_result n'est pas vide on affiche un message de succes
    if goat_result:
        print("\x1b[F\033[2K","{:<40} {:<5}".format(Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Goat",Fore.GREEN+"[OK]"+Fore.RESET))
    # sinon on affiche un message d'erreur
    else:
        print("\x1b[F\033[2K","{:<40} {:<5}".format(Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Goat",Fore.YELLOW+"[Empty]"+Fore.RESET))

    # fin de la section analyse du scan ssl
    ################################################

    ################################################
    # debut de la section analyse du scan Owl

    #format du dictionnaire owl_result{}:

    '''
    "owl": {
        "sub.exemple.com": {
            "open-ports": {
                "25": {
                    "Clear-Text": "supported",
                    "Implicit-TLS": "unsupported",
                    "Explicit-TLS": {
                        "SSL-Session": {
                            "Protocol": "TLSv1.3",
                            "Cipher": "TLS_AES_256_GCM_SHA384",
                            "Security": "recommended"
                        },
                        "TLSv1.2": {
                            "recommended": 3,
                            "secure": 5,
                            "weak": 6
                        },
                        "TLSv1.3": {
                            "recommended": 3
                        }
                    }
                }
            },
            "closed-ports": [
                "465",
                "587",
                "2525"
            ]
        },
    '''


    print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Owl:")

    
    owl_result = {}
    

    for files in all_files_path:
        # recuperation des fichiers de scan Owl et on les parcours
        if str(timestamp+"-owl") in files:
            # on ouvre le fichier et on recupere son contenu dans un dictionnaire
            with open(files, 'r') as f:
                contents = f.read()
                owl_data = json.loads(contents)
                
                if "Host" in owl_data and owl_data["Host"]:

                    if "Name" in owl_data["Host"] and owl_data["Host"]["Name"]:
                        owl_result_mx = {}

                        if "Port" in owl_data["Host"] and owl_data["Host"]["Port"]:
                            
                            open_ports = {}
                            closed_ports = []
                            
                            # on parcours les ports
                            for num_port,port_scan in owl_data["Host"]["Port"].items():
                                if "Status" in port_scan and port_scan["Status"]:
                                    # si le port est ouvert
                                    if port_scan["Status"] == "open":
                                        ports_scan = {}
                                        if "Clear-Text" in port_scan and port_scan["Clear-Text"]:
                                            if "Status" in port_scan["Clear-Text"] and port_scan["Clear-Text"]["Status"]:
                                                # recuperation du Clear-Text status
                                                ports_scan["Clear-Text"] = port_scan["Clear-Text"]["Status"]
                                        

                                        # section Implicit-TLS
                                        if "Encrypted-Text" in port_scan and port_scan["Encrypted-Text"]: 
                                            if "Implicit-TLS" in port_scan["Encrypted-Text"] and port_scan["Encrypted-Text"]["Implicit-TLS"]:
                                                if "Status" in port_scan["Encrypted-Text"]["Implicit-TLS"] and port_scan["Encrypted-Text"]["Implicit-TLS"]["Status"]:
                                                    # si Implicit-TLS est supporté
                                                    if port_scan["Encrypted-Text"]["Implicit-TLS"]["Status"] == "supported":
                                                        
                                                        implicit_tls = {}
                                                        ssl_session = {}

                                                        if "SSL-Session" in port_scan["Encrypted-Text"]["Implicit-TLS"] and port_scan["Encrypted-Text"]["Implicit-TLS"]["SSL-Session"]:
                                                            if "Protocol" in port_scan["Encrypted-Text"]["Implicit-TLS"]["SSL-Session"] and port_scan["Encrypted-Text"]["Implicit-TLS"]["SSL-Session"]["Protocol"]:
                                                                # recuperation du protocol
                                                                ssl_session["Protocol"] = port_scan["Encrypted-Text"]["Implicit-TLS"]["SSL-Session"]["Protocol"]
                                                            if "Cipher" in port_scan["Encrypted-Text"]["Implicit-TLS"]["SSL-Session"] and port_scan["Encrypted-Text"]["Implicit-TLS"]["SSL-Session"]["Cipher"]:
                                                                # recuperation du cipher
                                                                ssl_session["Cipher"] = port_scan["Encrypted-Text"]["Implicit-TLS"]["SSL-Session"]["Cipher"]
                                                            if "Security" in port_scan["Encrypted-Text"]["Implicit-TLS"]["SSL-Session"] and port_scan["Encrypted-Text"]["Implicit-TLS"]["SSL-Session"]["Security"]:
                                                                # recuperation du niveau de securite
                                                                ssl_session["Security"] = port_scan["Encrypted-Text"]["Implicit-TLS"]["SSL-Session"]["Security"]

                                                        # si ssl_session n'est pas vide on l'ajoute au dictionnaire implicit_tls
                                                        if ssl_session != {}:
                                                            implicit_tls["SSL-Session"] = ssl_session

                                                        cipher_1_0 = {}
                                                        cipher_1_1 = {}
                                                        cipher_1_2 = {}
                                                        cipher_1_3 = {}

                                                        if "Cipher_list" in port_scan["Encrypted-Text"]["Implicit-TLS"] and port_scan["Encrypted-Text"]["Implicit-TLS"]["Cipher_list"]:
                                                            # on parcours les ciphers
                                                            for i,cipher_name in enumerate(port_scan["Encrypted-Text"]["Implicit-TLS"]["Cipher_list"]):
                                                                if "Protocol" in port_scan["Encrypted-Text"]["Implicit-TLS"]["Cipher_list"][cipher_name] and port_scan["Encrypted-Text"]["Implicit-TLS"]["Cipher_list"][cipher_name]["Protocol"]:
                                                                    if "Security" in port_scan["Encrypted-Text"]["Implicit-TLS"]["Cipher_list"][cipher_name] and port_scan["Encrypted-Text"]["Implicit-TLS"]["Cipher_list"][cipher_name]["Security"]:  
                                                                        # recuperation du protocol et du niveau de securite
                                                                        protocol = port_scan["Encrypted-Text"]["Implicit-TLS"]["Cipher_list"][cipher_name]["Protocol"]
                                                                        security = port_scan["Encrypted-Text"]["Implicit-TLS"]["Cipher_list"][cipher_name]["Security"]

                                                                        # on ajoute le cipher au dictionnaire correspondant au protocol
                                                                        if protocol == "TLSv1.0":
                                                                            if security in cipher_1_0:
                                                                                cipher_1_0[security] += 1
                                                                            else:
                                                                                cipher_1_0[security] = 1
                                                                        elif protocol == "TLSv1.1":
                                                                            if security in cipher_1_1:
                                                                                cipher_1_1[security] += 1
                                                                            else:
                                                                                cipher_1_1[security] = 1
                                                                        elif protocol == "TLSv1.2":
                                                                            if security in cipher_1_2:
                                                                                cipher_1_2[security] += 1
                                                                            else:
                                                                                cipher_1_2[security] = 1
                                                                        elif protocol == "TLSv1.3":
                                                                            if security in cipher_1_3:
                                                                                cipher_1_3[security] += 1
                                                                            else:
                                                                                cipher_1_3[security] = 1

                                                        # si cipher_1_0, cipher_1_1, cipher_1_2 ou cipher_1_3 n'est pas vide on l'ajoute au dictionnaire implicit_tls
                                                        if cipher_1_0 != {}: 
                                                            implicit_tls["TLSv1.0"] = cipher_1_0
                                                        if cipher_1_1 != {}: 
                                                            implicit_tls["TLSv1.1"] = cipher_1_1
                                                        if cipher_1_2 != {}:
                                                            implicit_tls["TLSv1.2"] = cipher_1_2
                                                        if cipher_1_3 != {}:
                                                            implicit_tls["TLSv1.3"] = cipher_1_3

                                                        # si implicit_tls n'est pas vide on l'ajoute au dictionnaire ports_scan
                                                        if implicit_tls != {}:
                                                            ports_scan["Implicit-TLS"] = implicit_tls

                                                    # si Implicit-TLS est non supporté
                                                    else:
                                                        ports_scan["Implicit-TLS"] = port_scan["Encrypted-Text"]["Implicit-TLS"]["Status"]

                                        # section Explicit-TLS
                                        if "Encrypted-Text" in port_scan and port_scan["Encrypted-Text"]:
                                            if "Explicit-TLS" in port_scan["Encrypted-Text"] and port_scan["Encrypted-Text"]["Explicit-TLS"]:
                                                if "Status" in port_scan["Encrypted-Text"]["Explicit-TLS"] and port_scan["Encrypted-Text"]["Explicit-TLS"]["Status"]:
                                                    # si Explicit-TLS est supporté
                                                    if port_scan["Encrypted-Text"]["Explicit-TLS"]["Status"] == "supported":
                                                        explicit_tls = {}
                                                        ssl_session = {}
                                                        if "SSL-Session" in port_scan["Encrypted-Text"]["Explicit-TLS"] and port_scan["Encrypted-Text"]["Explicit-TLS"]["SSL-Session"]:
                                                            if "Protocol" in port_scan["Encrypted-Text"]["Explicit-TLS"]["SSL-Session"] and port_scan["Encrypted-Text"]["Explicit-TLS"]["SSL-Session"]["Protocol"]:
                                                                # recuperation du protocol
                                                                ssl_session["Protocol"] = port_scan["Encrypted-Text"]["Explicit-TLS"]["SSL-Session"]["Protocol"]
                                                            if "Cipher" in port_scan["Encrypted-Text"]["Explicit-TLS"]["SSL-Session"] and port_scan["Encrypted-Text"]["Explicit-TLS"]["SSL-Session"]["Cipher"]:
                                                                # recuperation du cipher
                                                                ssl_session["Cipher"] = port_scan["Encrypted-Text"]["Explicit-TLS"]["SSL-Session"]["Cipher"]
                                                            if "Security" in port_scan["Encrypted-Text"]["Explicit-TLS"]["SSL-Session"] and port_scan["Encrypted-Text"]["Explicit-TLS"]["SSL-Session"]["Security"]:
                                                                # recuperation du niveau de securite
                                                                ssl_session["Security"] = port_scan["Encrypted-Text"]["Explicit-TLS"]["SSL-Session"]["Security"]

                                                        # si ssl_session n'est pas vide on l'ajoute au dictionnaire explicit_tls
                                                        if ssl_session != {}: 
                                                            explicit_tls["SSL-Session"] = ssl_session

                                                        cipher_1_0 = {}
                                                        cipher_1_1 = {}
                                                        cipher_1_2 = {}
                                                        cipher_1_3 = {}

                                                        if "Cipher_list" in port_scan["Encrypted-Text"]["Explicit-TLS"] and port_scan["Encrypted-Text"]["Explicit-TLS"]["Cipher_list"]:
                                                            # on parcours les ciphers
                                                            for i,cipher_name in enumerate(port_scan["Encrypted-Text"]["Explicit-TLS"]["Cipher_list"]):
                                                                if "Protocol" in port_scan["Encrypted-Text"]["Explicit-TLS"]["Cipher_list"][cipher_name] and port_scan["Encrypted-Text"]["Explicit-TLS"]["Cipher_list"][cipher_name]["Protocol"]:
                                                                    if "Security" in port_scan["Encrypted-Text"]["Explicit-TLS"]["Cipher_list"][cipher_name] and port_scan["Encrypted-Text"]["Explicit-TLS"]["Cipher_list"][cipher_name]["Security"]:  
                                                                        # recuperation du protocol et du niveau de securite
                                                                        protocol = port_scan["Encrypted-Text"]["Explicit-TLS"]["Cipher_list"][cipher_name]["Protocol"]
                                                                        security = port_scan["Encrypted-Text"]["Explicit-TLS"]["Cipher_list"][cipher_name]["Security"]

                                                                        # on ajoute le cipher au dictionnaire correspondant au protocol
                                                                        if protocol == "TLSv1.0":
                                                                            if security in cipher_1_0:
                                                                                cipher_1_0[security] += 1
                                                                            else:
                                                                                cipher_1_0[security] = 1
                                                                        elif protocol == "TLSv1.1":
                                                                            if security in cipher_1_1:
                                                                                cipher_1_1[security] += 1
                                                                            else:
                                                                                cipher_1_1[security] = 1
                                                                        elif protocol == "TLSv1.2":
                                                                            if security in cipher_1_2:
                                                                                cipher_1_2[security] += 1
                                                                            else:
                                                                                cipher_1_2[security] = 1
                                                                        elif protocol == "TLSv1.3":
                                                                            if security in cipher_1_3:
                                                                                cipher_1_3[security] += 1
                                                                            else:
                                                                                cipher_1_3[security] = 1

                                                        # si cipher_1_0, cipher_1_1, cipher_1_2 ou cipher_1_3 n'est pas vide on l'ajoute au dictionnaire explicit_tls
                                                        if cipher_1_0 != {}: 
                                                            explicit_tls["TLSv1.0"] = cipher_1_0
                                                        if cipher_1_1 != {}: 
                                                            explicit_tls["TLSv1.1"] = cipher_1_1
                                                        if cipher_1_2 != {}:
                                                            explicit_tls["TLSv1.2"] = cipher_1_2
                                                        if cipher_1_3 != {}:
                                                            explicit_tls["TLSv1.3"] = cipher_1_3

                                                        # si explicit_tls n'est pas vide on l'ajoute au dictionnaire ports_scan
                                                        if explicit_tls != {}:
                                                            ports_scan["Explicit-TLS"] = explicit_tls

                                                    # si Explicit-TLS est non supporté
                                                    else:
                                                        ports_scan["Explicit-TLS"] = port_scan["Encrypted-Text"]["Explicit-TLS"]["Status"]

                                        # si ports_scan n'est pas vide on l'ajoute au dictionnaire ports ouverts
                                        if ports_scan != {}:
                                            open_ports[num_port] = ports_scan

                                    # si le port est fermé
                                    elif port_scan["Status"] == "close":
                                        # on ajoute le port dans la liste des ports fermés
                                        closed_ports.append(num_port)

                            # ajout des ports ouverts et fermés au dictionnaire owl_result_mx
                            owl_result_mx["open-ports"] = open_ports
                            owl_result_mx["closed-ports"] = closed_ports
                        
                        # on ajoute le resultat du scan du mx dans le resultat de owl
                        owl_result[owl_data["Host"]["Name"]] = owl_result_mx
    
    # si owl_result n'est pas vide on affiche un message de succes
    if owl_result:
        print("\x1b[F\033[2K","{:<40} {:<5}".format(Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Owl",Fore.GREEN+"[OK]"+Fore.RESET))
    else:
        print("\x1b[F\033[2K","{:<40} {:<5}".format(Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Owl",Fore.YELLOW+"[Empty]"+Fore.RESET))

    # fin de la section owl
    ########################################


    ########################################
    # debut de la section kangaroo
    '''
    format du dictionnaire kangaroo_result:

    "kangaroo": {
        "exemple.com": {
            "SPF": true,
            "DKIM": true,
            "DMARC": {
                "record": true,
                "policy": "quarantine"
            }
        }
    }
    ''' 


    print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Kangaroo:")

    kangaroo_result = {}

    for files in all_files_path:

        if  str(timestamp+"-dnsrecords") in files:
            # recuperation des fichiers de scan DNS et on les parcours
            with open(files, 'r') as f:
                contents = f.read()
                kangaroo_data = json.loads(contents)

                kangaroo_data_domain = {}

                # on definit les variables spf, dkim et dmarc
                spf = False
                dkim = False
                dmarc = False
                
                # on parcours les enregistrements DNS
                # si SPF est present et qu'il y a un enregistrement
                if "SPF" in kangaroo_data and kangaroo_data["SPF"]:
                    # si Record est present et qu'il y a un enregistrement
                    if "Record" in kangaroo_data["SPF"] and kangaroo_data["SPF"]["Record"]:
                        # on definit spf a true
                        spf = True
                

                if "DKIM" in kangaroo_data and kangaroo_data["DKIM"]:
                    if "Record" in kangaroo_data["DKIM"] and kangaroo_data["DKIM"]["Record"]:
                        # on definit dkim a true si il y a un enregistrement DKIM
                        dkim = True

                if "DMARC" in kangaroo_data and kangaroo_data["DMARC"]:
                    if "Record" in kangaroo_data["DMARC"] and kangaroo_data["DMARC"]["Record"]:
                        # on definit dmarc a true si il y a un enregistrement de politque DMARC
                        if "p" in kangaroo_data["DMARC"] and kangaroo_data["DMARC"]["p"]:
                            # on definit la politique de DMARC
                            dmarc = {
                                "record": True,
                                "policy":kangaroo_data["DMARC"]["p"]
                            }
                        else:
                            # si pas de politique on definit dmarc a true et la politique a false
                            dmarc = {
                                "record": True,
                                "policy": False
                            }
                # si spf, dkim ou dmarc est present on ajoute les resultats au dictionnaire kangaroo_data_domain
                kangaroo_data_domain["SPF"] = spf
                kangaroo_data_domain["DKIM"] = dkim
                kangaroo_data_domain["DMARC"] = dmarc
                
                # si kangaroo_data_domain n'est pas vide on l'ajoute au dictionnaire kangaroo_result avec le domaine comme cle
                if "domain" in kangaroo_data and kangaroo_data["domain"]:
                    kangaroo_result[kangaroo_data["domain"]] = kangaroo_data_domain
    
    # si kangaroo_result n'est pas vide on affiche un message de succes
    if kangaroo_result:
        print("\x1b[F\033[2K","{:<40} {:<5}".format(Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Kangaroo",Fore.GREEN+"[OK]"+Fore.RESET))
    # si kangaroo_result est vide on affiche un message d'erreur
    else:
        print("\x1b[F\033[2K","{:<40} {:<5}".format(Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Kangaroo",Fore.YELLOW+"[Empty]"+Fore.RESET))

    # fin de la section kangaroo
    ########################################

    ########################################
    # debut de la section badger
    '''
    format du dictionnaire badger_result:

    "badger": {
    "exemple.com": {
        "nb_emails_leaked_with_password": 1,
        "nb_emails_leaked_without_password": 1,
        "emails_leaked": [
            {
                "email": "user1@exemple.com",
                "nb_leaks": 1,
                "leaks_without_passwords": [
                    "leak1"
                ]
            },
            {
                "email": "user2@exemple.com",
                "nb_leaks": 1,
                "leaks_without_passwords": [
                    "leak2"
                ]
            }
        ]
    }

    '''
    print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Badger:")

    badger_result = {}

    # on parcours les fichiers de scan badger
    for files in all_files_path:
        if  str(timestamp+"-emails") in files:
            # on ouvre le fichier et on le charge en json
            with open(files, 'r') as f:
                contents = f.read()
                badger_data = json.loads(contents)
                badger_domain_scan = {
                    "nb_emails_leaked_with_password": 0,
                    "nb_emails_leaked_without_password": 0,
                    "emails_leaked" : []
                }

                if "mails" in badger_data and badger_data["mails"]:
                    for mail in badger_data["mails"]:
                        if "leaks" in mail and mail["leaks"]:
                            # si leaks est different de SAFE et ERROR
                            if mail["leaks"] != "SAFE" and mail ["leaks"] != "ERROR":
                                # on parcours les leaks
                                for leak in mail["leaks"]:
                                    if "datasClasses" in leak and leak["datasClasses"]: 
                                        # si c'est un leak de mot de passe   
                                        if "Passwords" in leak["datasClasses"]:
                                            # on ajoute 1 au nombre de leaks avec mot de passe
                                           badger_domain_scan["nb_emails_leaked_with_password"] += 1
                                           break
                                        else:
                                            # on ajoute 1 au nombre de leaks sans mot de passe
                                            badger_domain_scan["nb_emails_leaked_without_password"] += 1
                                            break
                                
                                
                                list_names_of_leaks_with_passwords = []
                                list_names_of_leaks_without_passwords = []
                                
                                # on parcours les leaks
                                for leak in mail["leaks"]:
                                    if "Name" in leak and leak["Name"]:
                                        if "datasClasses" in leak and leak["datasClasses"]:    
                                            if "Passwords" in leak["datasClasses"]:
                                                # si c'est un leak de mot de passe on ajoute le nom du leak a la liste des leaks avec mot de passe
                                                list_names_of_leaks_with_passwords.append(leak["Name"])
                                            else:
                                                # si c'est un leak sans mot de passe on ajoute le nom du leak a la liste des leaks sans mot de passe
                                                list_names_of_leaks_without_passwords.append(leak["Name"])
                                        else:
                                            # si c'est un leak sans mot de passe on ajoute le nom du leak a la liste des leaks sans mot de passe
                                            list_names_of_leaks_without_passwords.append(leak["Name"])
                                        

                                # on ajoute l'email au dictionnaire badger_domain_scan
                                if "email" in mail and mail["email"]:
                                    badger_domain_scan["emails_leaked"].append({
                                        # on ajoute l'email
                                        "email": mail["email"],
                                        # on ajoute le nombre de leaks
                                        "nb_leaks": len(mail["leaks"])
                                    })

                                    # on ajoute les listes de leaks avec et sans mot de passe
                                    if list_names_of_leaks_with_passwords != []:
                                        badger_domain_scan["emails_leaked"][-1]["leaks_with_passwords"] = list_names_of_leaks_with_passwords
                                    if list_names_of_leaks_without_passwords != []:
                                        badger_domain_scan["emails_leaked"][-1]["leaks_without_passwords"] = list_names_of_leaks_without_passwords

                # on ajoute le resultat du scan au dictionnaire badger_result
                if "domain" in badger_data and badger_data["domain"]:
                    badger_result[badger_data["domain"]] = badger_domain_scan

    # on affiche un message de succes si badger_result n'est pas vide
    if badger_result:
        print("\x1b[F\033[2K","{:<40} {:<5}".format(Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Badger",Fore.GREEN+"[OK]"+Fore.RESET))
    # on affiche un message d'erreur si badger_result est vide
    else:
        print("\x1b[F\033[2K","{:<40} {:<5}".format(Fore.GREEN+Style.DIM+" ├─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" Badger",Fore.YELLOW+"[Empty]"+Fore.RESET))

    # fin du scan badger
    ########################################

    # on ajoute les resultat de tous les scans dans un dictionnaire
    report_of_all_data["tapirus"] = shodan_result
    report_of_all_data["goat"] = goat_result
    report_of_all_data["owl"] = owl_result
    report_of_all_data["kangaroo"] = kangaroo_result
    report_of_all_data["badger"] = badger_result
    # on convertit le dictionnaire en json
    json_report_of_all_data = json.dumps(report_of_all_data, indent = 4)

    #on sauvegarde le rapport complet dans un fichier timestamp-REPORT-BEGA.json
    name_report = timestamp+"-REPORT-BEGA.json"
    pathName = dir_path + "/"+ name_report
    f = open(pathName,"w") 
    f.write(json_report_of_all_data) 
    f.close()
    
    print(pathName)
    print(Fore.GREEN+Style.DIM+"  └─"+Style.RESET_ALL+Fore.GREEN+"[-]"+Fore.RESET+" 1 report have been saved in \"" + dir_path + "/" + name_report+"\"")
    return pathName

# fonction qui permet de lancer un scan specifique
def start_single_scan(domainName, args, isAnIpScan, timestamp, tapir, goa, uwu,kanga, badg, dir_path):
    print(dir_path)
    
    shodan_result = "NOTDEFINE"

    # si l'argument tapirus est a True, on lance le scan tapirus 
    if args["tapirus"]:
        shodan_result = start_tapirus_scan(domainName, isAnIpScan, timestamp, tapir, dir_path)

    # si l'argument goat est a True, on lance un scan tapirus puis un scan goat
    if args["goat"]:
        if shodan_result == "NOTDEFINE": shodan_result = start_tapirus_scan(domainName, isAnIpScan, timestamp, tapir,dir_path)
        # shodan_result = {}
        # shodan_result["subdomains"] = ["anapidae","ascelibrary.ezproxy","www"]
        # shodan_result["domain"] = "google.com"
        start_goat_scan(domainName,shodan_result, goa, timestamp, dir_path)
    
    # si l'argument owl est a True, on lance un scan tapirus puis un scan owl
    if args["owl"]:
        if shodan_result == "NOTDEFINE": shodan_result = start_tapirus_scan(domainName, isAnIpScan, timestamp, tapir, dir_path)
        start_owl_scan(shodan_result, timestamp, uwu, dir_path)

    # si l'argument kangaroo est a True, on lance un scan kangaroo
    if args["kangaroo"]:
        start_kangaroo_scan(domainName,args["DKIM"], kanga, timestamp,dir_path)

    # si l'argument badger est a True, on lance un scan badger
    if args["badger"]:
        start_badger_scan(domainName, args["pattern"], badg, timestamp, args, dir_path)

    # on analyse les resultats
    analyze_results(domainName, isAnIpScan, dir_path, timestamp)


@login_required
def report_create(request, id):
    scan = Scan.objects.get(id=id)
    args = {
        "limit":scan.limit,
        "DKIM": [None, None],
        "tapirus" :scan.tapirus,
        "goat" : scan.goat,
        "owl" : scan.owl,
        "kangaroo" : scan.kangaroo,
        "badger" : scan.badger,
        "pattern" :"",
        "modify" :"",
        "domainName" : list(scan.domain_name.split('|')),
    }
    print(args)
    
    #timestamp pour le nom du dossier
    first_timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    #supprime le fichier de cookie google si il existe, il est crée par le module googlesearch
    google_cookie = os.path.dirname(__file__)+"/.google-cookie"
    if os.path.isfile(google_cookie):
        os.remove(google_cookie)

    #si le fichier de config n'existe pas, on quitte le programme et on affiche un message d'erreur
    if not os.path.isfile(str(settings.BASE_DIR.parent)+"/config.ini"):
        print(Fore.RED+"\n[-]"+Fore.RESET+" No config.ini file found")
        quit()

    #sépare les domaines et les ips dans deux listes
    domainsList = []
    ipList = []
    ipListCIDR = []

    for element in args["domainName"]:
        try:
            ipaddress.ip_address(element)
            ipList.append(element)
        except ValueError:
            try:
                subIP = ipaddress.ip_network(element)
                for ip in subIP:
                    ipList.append(str(ip))
            except ValueError:
                domainsList.append(element)

    #si la liste d'ip n'est pas vide on lance un scan d'ip
    if ipList != []:
        isAnIpScan = True
        #on force le scan de tapirus uniquement
        args["tapirus"] = True
        #timestamp pour le nom du scan ip
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        #si un timestamp est passé en argument on l'utilise cela permet d'editer un report
        if args["modify"]: timestamp = args["modify"]
        
        #création du dossier de rapport et formatage du nom
        dir_name = timestamp + "-ScanIP"
        dir_path = str(settings.BASE_DIR.parent) + "/reports/" + dir_name
        print(dir_path)
        os.makedirs(dir_path, exist_ok=True)
        
        print(Fore.GREEN+"\n >>>"+Fore.RESET+" IP(s) scan ... " + Fore.RESET + "\n")
        
        #instanciation de la classe tapirus
        tapir = tapirus.tapirus()
        #lancement du scan
        start_tapirus_scan(ipList, isAnIpScan, timestamp, tapir, dir_path)
        #analyse les résultats pour le rapport final de bega
        #None correspond au nom de domaine, il n'y en a pas dans le cas d'un scan d'ip
        #dir_path correspond au chemin du dossier de rapport
        analyze_results(None, isAnIpScan, dir_path, timestamp)
        
        #si on est au dernier scan on affiche une ligne de séparation
        if  domainsList != []:
            cols, rows = os.get_terminal_size()
            print("\n"+"─" * cols)
            
    # on parcours la liste des domaines
    for domainName in domainsList:
        # ce n'est pas un scan d'ip
        isAnIpScan = False
        #timestamp pour le nom du scan
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        #si un timestamp est passé en argument on l'utilise cela permet d'editer un report
        if args["modify"]: timestamp = args["modify"]
        # on formate le nom du dossier de rapport
        dir_name = timestamp + "-BegaScan-" + domainName
        
        #si on a plusieurs domaines on crée un dossier pour chaque domaine
        if len(args["domainName"]) > 1 :
            dir_path = str(settings.BASE_DIR.parent) + "/reports/" + first_timestamp+"-MultipleReports/"+dir_name
        else:
            dir_path = str(settings.BASE_DIR.parent) + "/reports/" + dir_name
        
        #on crée le dossier de rapport
        os.makedirs(dir_path, exist_ok=True)
        

        print(Fore.GREEN+"\n >>>"+Fore.RESET+" Domain name: " + Fore.CYAN + domainName + Fore.RESET + "\n")

        #instanciation des classes
        tapir = tapirus()
        goa = goat()
        uwu = owl()
        kanga = kangaroo()
        badg = badger()

        # si un argument de scan est a True on lance le scan correspondant
        if args["tapirus"] or args["goat"] or args["owl"] or args["kangaroo"] or args["badger"]:
            start_single_scan(domainName, args, isAnIpScan, timestamp, tapir, goa, uwu,kanga, badg, dir_path)
        # sinon on lance tous les scans
        else:
            shodan_result = start_tapirus_scan(domainName, isAnIpScan, timestamp, tapir, dir_path)

            #### ADD FOR TEST ####
            shodan_result["subdomains"] = ["anapidae","ascelibrary.ezproxy","www"]

            start_goat_scan(domainName,shodan_result, goa, timestamp, dir_path)
            # start_owl_scan(shodan_result,timestamp, uwu, dir_path)
            # start_kangaroo_scan(domainName,args.DKIM, kanga, timestamp, dir_path)
            start_badger_scan(domainName, args["pattern"], badg, timestamp, args, dir_path)

            # on analyse les resultats
            analyze_results(domainName, isAnIpScan, dir_path, timestamp)

        # si on est au dernier scan on affiche une ligne de séparation
        if domainName != domainsList[-1]:
            cols, rows = os.get_terminal_size()
            print("\n"+"─" * cols)
    
    data_file = dir_path + "/"+ timestamp+"-REPORT-BEGA.json"
    report = Report()
    report.name = dir_name
    report.date = timestamp
    with open(data_file, 'r') as file_data:
            report.data = json.load(file_data)
    report.scan = scan
    report.user = scan.user
    report.save()
    reports = Report.objects.filter(user=request.user)
    
    return render(request, 'scan/report_list.html', {'reports': reports})
