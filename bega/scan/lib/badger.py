#!/usr/bin/python3
import time
import configparser
from googlesearch import search
from colorama import Fore,Style
from emailfinder.extractor import *
import requests
import time
import os
import io
import sys
import json
import urllib
import bega.settings as settings

class badger:

    def show_banner(self):
        
        banner = ("""
    _               _                 
    | |             | |                
    | |__   __ _  __| | __ _  ___ _ __ 
    | '_ \ / _` |/ _` |/ _` |/ _ \ '__|
    | |_) | (_| | (_| | (_| |  __/ |   
    |_.__/ \__,_|\__,_|\__, |\___|_|   
                        __/ |          
                       |___/ 
        version 2.1           by Lotter
        """)

        print("\033[1;34;40m"+banner,end="\033[0;37;40m\n")
        return


    def exit_script(self):
        google_cookie = os.path.dirname(__file__)+"/.google-cookie"
        if os.path.isfile(google_cookie):
            os.remove(google_cookie)

    # Gets the api key in the argument and otherwise in the config file
    # Return apikey string
    def get_apikey(self, key):
        if key == None: 
            config = configparser.ConfigParser() 
            config.read(str(settings.BASE_DIR.parent)+"/config.ini")
            apikey = config['API_KEY']['hibp_api_key'] 
            return apikey
        else:
            return key
                
    # Use google search to retrieve links from google dorks results
    # Return list of linkedin profile url
    def perform_dorks(self, domain,max):
        self.dork = "site:linkedin.com/in + intitle:"+str(".".join(list(domain.split("."))[:-1]))
        i = 0

        result = []
        try:
            for j in search(self.dork, lang='fr', stop=int(max), pause=10):
                i += 1
                result.append(j)
        except urllib.error.HTTPError :
            return False

        return result

    # Extract the first and last name from a linkedin link
    # Return list of list of first and last name
    def extract_names(self, domain, result_dorks):
        all_names=[]
        domain_without_dot = str(".".join(list(domain.split("."))[:-1]))
        for link in result_dorks:
            name = []
            for item in link.split("/")[4].split("-"):
                if not any(i.isdigit() for i in item):
                    name.append(item.replace("\n",""))
        
            if domain_without_dot in name:
                name_without_domain = name.copy()
                name_without_domain.remove(domain_without_dot)
                all_names.append(name_without_domain)
            all_names.append(name)

        all_names = list(set(tuple(x) for x in all_names))
        all_names.sort()
        return all_names

    # Create emails from a simple name or surname. Or from a composition of composed or simple first name. It uses the domain name of the company. You must comment or decomment according to the number of possibilities that you want.
    # Return list of crafted mails
    def craft_mails(self, extracted_names,domain, pattern_given):
        return_craft_mails = []

        for identity in extracted_names:
            if len(identity) == 1:
                
                #{first}@domain
                pattern = "{first}@domain"
                return_craft_mails.append([identity[0]+"@"+domain,pattern])

            elif len(identity) == 2:
                if pattern_given:
                    craft_mail = pattern_given.replace("{first}",identity[0])
                    craft_mail = craft_mail.replace("{last}",identity[1])
                    craft_mail = craft_mail.replace("{f}",identity[0][0])
                    craft_mail = craft_mail.replace("{l}",identity[1][0])

                    return_craft_mails.append([craft_mail+"@"+domain,pattern_given])
                else:
                    #{f}{last}@domain
                    # pattern = "{f}{last}@domain"
                    # return_craft_mails.append([identity[0][0]+identity[1]+"@"+domain,pattern])

                    #{f}.{last}@domain
                    # pattern = "{f}.{last}@domain"
                    # return_craft_mails.append([identity[0][0]+"."+identity[1]+"@"+domain,pattern])
                    
                    # #{first}{last}@domain
                    # pattern = "{first}{last}@domain"
                    # return_craft_mails.append([identity[0]+identity[1]+"@"+domain,pattern])
                    
                    #{first}.{last}@domain
                    pattern = "{first}.{last}@domain"
                    return_craft_mails.append([identity[0]+"."+identity[1]+"@"+domain,pattern])
                    
                    #{first}-{last}@domain
                    # pattern = "{first}-{last}@domain"
                    # return_craft_mails.append([identity[0]+"-"+identity[1]+"@"+domain,pattern])
                    
                    #{last}{first}@domain
                    # pattern = "{last}{first}@domain"
                    # return_craft_mails.append([identity[1]+identity[0]+"@"+domain,pattern])
                    
                    #{last}-{first}@domain
                    # pattern = "{last}{first}@domain"
                    # return_craft_mails.append([identity[1]+"-"+identity[0]+"@"+domain,pattern])

            
            elif len(identity) == 3:
                
                #{f1}{f2}{last}@domain
                pattern = "{f1}{f2}{last}@domain"
                return_craft_mails.append([identity[0][0]+identity[1][0]+identity[2]+"@"+domain,pattern])
                
                #{f1}{f2}-{last}@domain
                pattern = "{f1}{f2}-{last}@domain"
                return_craft_mails.append([identity[0][0]+identity[1][0]+'-'+identity[2]+"@"+domain,pattern])
                
                #{f1}{f2}.{last}@domain
                pattern = "{f1}{f2}.{last}@domain"
                return_craft_mails.append([identity[0][0]+identity[1][0]+'.'+identity[2]+"@"+domain,pattern])
                
                #{first1}-{first2}.{last}@domain
                pattern = "{first1}-{first2}.{last}@domain"
                return_craft_mails.append([identity[0]+'-'+identity[1]+'.'+identity[2]+"@"+domain,pattern])
                
                #{first1}.{first2}-{last}@domain
                pattern = "{first1}.{first2}-{last}@domain"
                return_craft_mails.append([identity[0]+'.'+identity[1]+'-'+identity[2]+"@"+domain,pattern])
                
                #{first1}{first2}.{last}@domain
                pattern = "{first1}{first2}.{last}@domain"
                return_craft_mails.append([identity[0]+identity[1]+'.'+identity[2]+"@"+domain,pattern])
                
                #{first1}{first2}-{last}@domain
                pattern = "{first1}{first2}-{last}@domain"
                return_craft_mails.append([identity[0]+identity[1]+'-'+identity[2]+"@"+domain,pattern])            
                
                #{first1}{first2}{last}@domain
                pattern = "{first1}{first2}{last}@domain"
                return_craft_mails.append([identity[0]+identity[1]+identity[2]+"@"+domain,pattern])
                
                #{first1}-{last1}{last2}@domain
                pattern = "{first1}-{last1}{last2}@domain"
                return_craft_mails.append([identity[0]+'-'+identity[1]+identity[2]+"@"+domain,pattern])
                
                #{first1}.{last1}{last2}@domain
                pattern = "{first1}.{last1}{last2}@domain"
                return_craft_mails.append([identity[0]+'.'+identity[1]+identity[2]+"@"+domain,pattern])
                
                #{f1}.{last1}{last2}@domain
                pattern = "{f1}.{last1}{last2}@domain"
                return_craft_mails.append([identity[0][0]+'.'+identity[1]+identity[2]+"@"+domain,pattern])


            elif len(identity) == 4:
                
                #{first1}-{first2}.{last1}@domain
                pattern = "{first1}-{first2}.{last1}@domain"
                return_craft_mails.append([identity[0]+'-'+identity[1]+'.'+identity[2]+"@"+domain,pattern])
                
                #{f1}{f2}.{last1}@domain
                pattern = "{f1}{f2}.{last1}@domain"
                return_craft_mails.append([identity[0][0]+identity[1][0]+'.'+identity[2]+"@"+domain,pattern])
                
                #{f1}-{f2}.{last1}@domain
                pattern = "{f1}-{f2}.{last1}@domain"
                return_craft_mails.append([identity[0][0]+'-'+identity[1][0]+'.'+identity[2]+"@"+domain,pattern])
                
                #{f1}{last1}@domain
                pattern = "{f1}{last1}@domain"
                return_craft_mails.append([identity[0][0]+identity[2]+"@"+domain,pattern])
                
                #{first1}.{last1}@domain
                pattern = "{first1}.{last1}@domain"
                return_craft_mails.append([identity[0]+'.'+identity[2]+"@"+domain,pattern])
        
        # Craft a list of used patterns
        self.patterns_crafted_mails = []
        if pattern_given:
            self.patterns_crafted_mails.append(pattern_given)
        else:
            for pat in return_craft_mails:
                self.patterns_crafted_mails.append(pat[1])
            self.patterns_crafted_mails = list(dict.fromkeys(self.patterns_crafted_mails))

        # Sorts and removes duplicates
        for i in range(len(return_craft_mails)):
            return_craft_mails[i][0] = return_craft_mails[i][0].lower()
        return_craft_mails.sort(key=lambda x: x[0])

        return return_craft_mails
        
    # Use email finder to retrieve valid emails from the internet
    # Return list of valid mails
    def emails_finder(self, domain, aff = True):
        
        if not aff:
            sys.stdout = io.StringIO()
        # Google search
        try: emails1 = get_emails_from_google(domain)
        except:
            emails1 = []
            pass

        # Bing search
        try: emails2 = get_emails_from_bing(domain)
        except:
            emails2 = []
            pass

        # Baidu search
        try: emails3 = get_emails_from_baidu(domain)
        except:
            emails3 = []
            pass

        if not aff:
            sys.stdout = sys.__stdout__

        emails = emails1 + emails2 + emails3
        emails = [x.lower() for x in emails]
        emails = [x.replace("x22","") for x in emails]
        emails = [x.replace("u003c","") for x in emails]
        emails = list(dict.fromkeys(emails))
        return emails

    # Takes as input the list of mails to check on the HIBP api and displays the result of the compromise.
    def check_leaks(self, mails, apikey, print_info = False):
        self.APIKEY = self.get_apikey(apikey)
        headers={'User-Agent':'badger','hibp-api-key':self.APIKEY}
        try:
            breaches = requests.get("https://haveibeenpwned.com/api/v3/breaches").json()
        except requests.exceptions.ConnectTimeout:
            return None,"ConnectTimeout"
        except:
            return None,"Error"
        
        result_check_leaks = {}

        i = 1
        for mail in mails:
            count_number = " ("+str(i).zfill(int(len(str(len(mails)))))+"/"+str(len(mails))+")"
            space = " "*(45-(len(mail)+len(count_number)))
            
            if i == len(mails):
                tab = "  │  └─"
            else:
                tab = "  │  ├─"

            if print_info: print(Fore.GREEN+Style.DIM+tab+Style.DIM+Fore.WHITE+count_number+Style.RESET_ALL,mail)
            time.sleep(6)
            r=requests.get("https://haveibeenpwned.com/api/v3/breachedaccount/"+mail, headers=headers)
            
            
            if r.status_code == 401:
                request_data = json.loads(r.text)
                return breaches,request_data

            informations = []
            if r.text == '':
                if print_info:
                    print("\x1b[F\033[2K"+Fore.GREEN+Style.DIM+tab+Style.DIM+Fore.WHITE+count_number+Style.RESET_ALL,mail,space,Fore.GREEN+"SAFE")
            else:
                compromised = [False,[]]
                for breache_name in r.json():
                    if 'Name' in breache_name:
                        breache_name = breache_name['Name']
                        for info_breache in breaches:
                            if info_breache['Name'] == breache_name:
                                datasClasses = []
                                info = {}
                                for data in info_breache["DataClasses"]:
                                    if data == "Passwords":
                                        compromised[0] = True
                                        compromised[1].append(info_breache["Name"])
                                    datasClasses.append(data)
                                info["Name"] = info_breache["Name"]
                                info["BreachDate"] = info_breache["BreachDate"]
                                info["datasClasses"] = datasClasses
                        
                        informations.append(info)
                
                if compromised[0]:
                    if print_info:
                        print("\x1b[F\033[2K"+Fore.GREEN+Style.DIM+tab+Style.DIM+Fore.WHITE+count_number+Style.RESET_ALL,mail,space,Fore.RED+"COMPROMISED (passwords in ",end="")
                        ii = 1
                        for elem in compromised[1]:
                            if ii == len(compromised[1]):
                                if print_info: print(Fore.RED + elem + ")")
                            else:
                                if print_info: print(Fore.RED + elem + ", ", end="")
                                ii+=1
                else:
                    if print_info:    
                        print("\x1b[F\033[2K"+Fore.GREEN+Style.DIM+tab+Style.DIM+Fore.WHITE+count_number+Style.RESET_ALL,mail,space,Fore.YELLOW+"LEAKED (nopass)")

            
            result_check_leaks[mail] = informations
            i+=1
        return breaches,result_check_leaks

    def make_report(self, path, name, domain, result_dorks, extracted_names, result_craft_mails, result_emails_finder, breaches, result_check_leaks):

        data_mails = []
        self.dork = "site:linkedin.com/in + intitle:"+str(".".join(list(domain.split("."))[:-1]))

        for item in result_emails_finder:
            if item in list(result_check_leaks.keys()):
                if result_check_leaks[item] != []:
                    dat = {
                        "email": item,
                        "source": "emailFinder",
                        "leaks": result_check_leaks[item]
                    }
                else:
                    dat = {
                        "email": item,
                        "source": "emailFinder",
                        "leaks": "SAFE"
                    }
            else: 
                dat = {
                    "email": item,
                    "source": "emailFinder",
                    "leaks": "ERROR"
                }     
            data_mails.append(dat)

        for item in result_craft_mails:
            if item[0] in list(result_check_leaks.keys()) and result_check_leaks[item[0]] != []:
                dat = {
                    "email": item[0],
                    "source": item[1],
                    "leaks": result_check_leaks[item[0]]
                }
            else:
                dat = {
                    "email": item[0],
                    "source": item[1],
                    "leaks": "SAFE"
                }            
            data_mails.append(dat)

        data_mails.sort(key=lambda x: x["email"])

        data = {
                    "domain": domain,
                    "google_dorks_result": {
                        "dorks" : self.dork,
                        "link_dorks": result_dorks,
                        "extracted_names": extracted_names,
                    },
                    "mails": data_mails,
                    "breaches": breaches
                }

        json_data = json.dumps(data, indent = 4)
        pathName = path + "/"+ name
        f = open(pathName,"w")
        f.write(json_data)
        f.close()
        return pathName
    
    def badgerScan(self,domain, max_elem=10, pattern=False):
        result_dorks = self.perform_dorks(domain,max_elem)
        extracted_names = self.extract_names(domain, result_dorks)
        result_craft_mails = self.craft_mails(extracted_names,domain,pattern)
        result_emails_finder = self.emails_finder(domain, False)
        concat_all_emails = list(dict.fromkeys(result_emails_finder + [sous_liste[0] for sous_liste in result_craft_mails]))
        breaches,result_check_leaks = self.check_leaks(concat_all_emails,None, False)
        self.make_report(domain, result_dorks, extracted_names, result_craft_mails, result_emails_finder, breaches, result_check_leaks)


    def __del__(self):
        # Suppression du fichier google-cookie qui se créer lors du scan shodan
        google_cookie = os.path.dirname(__file__)+"/.google-cookie"
        if os.path.isfile(google_cookie):
            os.remove(google_cookie)