import dns.resolver
import dns.reversename
from ipaddress import ip_address
import json

class kangaroo:

    def __init__(self):
        self.nameserver = ""
        self.domain = ""
        records_types = ["A", "AAAA", "CNAME", "NS", "MX", "PTR", "TXT", "SOA", "DMARC", "SPF"]
        for type in records_types:
            setattr(self, type.lower(), None)


    def start_scan(self,domain, nameserver=None,dkim=[None,None]):
        self.nameserver = nameserver
        self.domain = domain
        self.selector, self.dkim_domain = dkim
        self.resolver = dns.resolver.Resolver()
        if nameserver is not None:
            self.resolver.nameservers = [nameserver]
        
        # Lancement des requêtes pour récupérer les enregistrements DNS
        self.a_request()
        self.aaaa_request()
        self.cname_request()
        self.mx_request()
        self.ns_request()
        self.txt_request()
        self.ptr_request()
        self.soa_request()
        
        self.dmarc = DMARC(self.domain, self.nameserver)
        self.spf = SPF(self.domain, self.nameserver)
        self.dkim = DKIM(self.dkim_domain, self.selector, self.nameserver)
        
        # Formatage et sauvegarde des données en JSON
        data = self.create_json()
        return data

    # Affiche la bannière kangaroo.
    def show_banner(self):
        print("""
         |\\\\._         
         |   66__        _                                             
          \    _.P      | |                                            
      ,    `) (         | | ____ _ _ __   __ _  __ _ _ __ ___   ___    
      )\   / __\__      | |/ / _` | '_ \ / _` |/ _` | '__/ _ \ / _ \   
     / /  / -._);_)     |   < (_| | | | | (_| | (_| | | | (_) | (_) |  
    |  `\/  \ __|\      |_|\_\__,_|_| |_|\__, |\__,_|_|  \___/ \___/   
     \  ;    )  / )                       __/ |                        
      `\|   /__/ /__                     |___/                   V0.9.0
        `\______)___)   
        """)

# Fonction qui vérifie l'existance d'un nom de domaine
    def check_domain_exists(self):
        try:
            self.resolver.resolve(self.domain)
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoNameservers:
            return True
        except dns.resolver.NoAnswer:
            return True
        return True

# Fonction qui valide le format d'une addresse IP.
# Retourne l'IP si valide sinon retourne None
    def validIPAddress(self, IP: str) -> str:
        try:
            if type(ip_address(IP)):
                return True
        except ValueError:
            return False

# A request
    def a_request(self):
        try:
            # Effectuer une requête DNS de type A pour le nom de domaine
            answers = self.resolver.resolve(self.domain, 'A')
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise
        # except dns.resolver.LifetimeTimeout:
        #     pass
        # except dns.resolver.NoNameservers:
        #     pass
        except:
            raise
        else:
            self.a = []
            for answer in answers:
                self.a.append(answer.to_text())

# AAAA request
    def aaaa_request(self):
        try:
            # Effectuer une requête DNS de type A pour le nom de domaine
            answers = self.resolver.resolve(self.domain, 'AAAA')
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except dns.resolver.NXDOMAIN:
            raise
        except:
            raise
        else:
            self.aaaa = []
            for answer in answers:
                self.aaaa.append(answer.to_text())
                
# CNAME request
    def cname_request(self):
        try:
            # Effectuer une requête DNS de type CNAME pour le nom de domaine
            answers = self.resolver.resolve(self.domain, 'CNAME')
        except dns.resolver.NXDOMAIN:
            raise
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except:
            raise
        else:
            self.cname = []
            for answer in answers:
                self.cname.append(answer.to_text())

# NS request
    def ns_request(self):
        try:
            answers = self.resolver.resolve(self.domain,'NS')
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except dns.resolver.NXDOMAIN:
            raise
        except:
            raise
        else :
            self.ns = []
            for server in answers:
                self.ns.append(server.to_text())

# MX request
    def mx_request(self):
        try:
            answers = self.resolver.resolve(self.domain, 'MX')
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except dns.resolver.NXDOMAIN:
            raise
        except:
            raise
        else:
            i=0
            self.mx = []
            for rdata in answers:
                i+=1
                self.mx.append({"exchange name": str(rdata.exchange), "preference": rdata.preference})

# TXT request
    def txt_request(self):
        try:
            answers = self.resolver.resolve(self.domain,'TXT')
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            pass
        except dns.resolver.NXDOMAIN:
            raise
        except:
            raise
        else:
            self.txt = []
            for answer in answers:
                answer_txt = answer.to_text()
                if '" "' in answer_txt:
                    answer_txt=answer_txt.replace('" "', '')
                self.txt.append(answer_txt)

# PTR request
    def ptr_request(self):
        ### PTR ###
        self.a_request()
        if self.a != None:
            self.ptr = {}
            for ip in self.a:
                try:
                    no = dns.reversename.from_address(ip)
                except dns.resolver.NXDOMAIN:
                    raise
                except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    self.ptr = None
                except:
                    raise
                else:
                    try:
                        answers = self.resolver.resolve(no, 'PTR')
                    except dns.resolver.NXDOMAIN:
                        self.ptr = None
                    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                        self.ptr = None
                    except:
                        raise
                    else :
                        for rdata in answers:
                            self.ptr[ip] = rdata.to_text()

# SOA request
    def soa_request(self):
        try:
            answers = self.resolver.resolve(self.domain, 'SOA')
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except dns.resolver.NXDOMAIN:
            raise
        except:
            raise
        else:
            self.soa = {}
            answers = self.resolver.resolve(self.domain, 'SOA')
            for rdata in answers:
                self.soa["serial number"] = rdata.serial
                self.soa["responsible name"] = str(rdata.rname)
                self.soa["refresh"] = rdata.refresh
                self.soa["retry"] = rdata.retry
                self.soa["expire"] = rdata.expire
                self.soa["minimum"] = rdata.minimum
                self.soa["master name"] = str(rdata.mname)
# Saving datas to the JSON
    def spf_to_json(self, SPF):
        redirect_data = None
        if SPF.redirect is not None:
            redirect_data = self.spf_to_json(SPF.redirect)
            
        include_list = None
        if SPF.include is not None:
            include_list = []
            for objects in SPF.include:
                include_list.append(self.spf_to_json(objects))
            
        spf_include = {
                    "Domain" : SPF.domain,
                    "Record" : SPF.record,
                    "a" : SPF.a,
                    "mx" : SPF.mx,
                    "ptr" : SPF.ptr,
                    "ip4" : SPF.ip4,
                    "ip6" : SPF.ip6,
                    "exists" : SPF.exists,
                    "all" : SPF.all,
                    "exp" : SPF.exp,
                    "redirect" : redirect_data,
                    "include" : include_list
                }
        return spf_include
    
    def create_json(self):
        
        data_spf = self.spf_to_json(self.spf)
        
        data = {
            "domain" : self.domain,
            "A" : self.a,
            "AAAA" : self.aaaa,
            "CNAME" : self.cname,
            "NS" : self.ns,
            "MX" : self.mx, 
            "PTR" : self.ptr,
            "SOA" :  {
                "serial_number" : self.soa["serial number"],
                "responsible_name" : self.soa["responsible name"],
                "refresh" : self.soa["refresh"],
                "retry" : self.soa["retry"],
                "expire" : self.soa["expire"],
                "minimum" : self.soa["minimum"],
                "master_name" : self.soa["master name"]
            },
            "TXT" : self.txt,
            "DKIM" : {
                "Record" : self.dkim.record,
                "v": self.dkim.v,
                "p": self.dkim.p,
                "t": self.dkim.t,
                "g": self.dkim.g,
                "h": self.dkim.h,
                "k": self.dkim.k,
                "n": self.dkim.n,
                "s": self.dkim.s
            },
            "DMARC" : {
                "Record" : self.dmarc.record,
                "v" : self.dmarc.v,
                "p" : self.dmarc.p,
                "sp" : self.dmarc.sp,
                "pct" : self.dmarc.pct,
                "rua" : self.dmarc.rua,
                "ruf" : self.dmarc.ruf,
                "fo" : self.dmarc.fo,
                "rf" : self.dmarc.rf,
                "ri" : self.dmarc.ri,
                "adkim" : self.dmarc.adkim,
                "aspf" : self.dmarc.aspf
            },
            "SPF" : data_spf
        }
        
        return data

    def save_report(self,path,name,data): 
        json_data = json.dumps(data, indent = 4) 
        pathName = path + "/"+ name 
        f = open(pathName,"w") 
        f.write(json_data) 
        f.close() 
        return

class DMARC:

    def __init__(self, domain, nameserver):
        self.record = None
        self.domain = domain
        
        self.resolver = dns.resolver.Resolver()
        if nameserver is not None:
            self.resolver.nameservers = [nameserver]
            
        self.tags = ["v", "p", "sp", "pct", "rua", "ruf", 
                     "fo", "rf", "ri", "adkim", "aspf"]
        
        for tag in self.tags:
            setattr(self, tag, None)
        
        self.request()

# DMARC request
    def request(self):
        # Vérifier si le champ DMARC est présent dans le TXT
        self.record = None
        
        try:
            answers = self.resolver.resolve(self.domain,'TXT')
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            pass
        except dns.resolver.NXDOMAIN:
            raise
        except:
            raise
        else:
            for answer in answers:
                answer_txt = answer.to_text()
                if '" "' in answer_txt:
                    answer_txt=answer_txt.replace('" "', '')
                if answer_txt[1:-1].startswith("v=DMARC"):
                    self.record = answer_txt[1:-1]
                    self.parse_record(self.record)
                    return

        # Si le TXT est vide ou si DMARC n'est pas présent, tester le sous-domaine '_dmarc.<domain>'
        dmarc_subdomain = "_dmarc." + self.domain

        try:
            answers = self.resolver.resolve(dmarc_subdomain, 'TXT')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            pass
        except:
            raise
        else:
            for answer in answers:
                answer_txt = answer.to_text()
                # if '" "' in answer_txt:
                #     answer_txt=answer_txt.replace('" "', '')
                if answer_txt[1:-1].startswith("v=DMARC"):
                    self.record = answer_txt[1:-1]
                    self.parse_record(self.record)
                    return

    def parse_record(self, record_str):
        self.record = record_str
        # Isoler chaque tag du DMARC
        record_tags = self.record.split(";")
        for tag in record_tags:
            # Séparer le tag de sa valeur
            tag_parts = tag.strip().split("=")
            # Si le tag a une valeur associée
            if len(tag_parts) == 2:
                # Associer valeur à son attribut
                setattr(self, tag_parts[0].strip().lower(), tag_parts[1].strip())

class DKIM:
    def __init__(self, dkim_domain, selector, nameserver):
        self.record = None
        self.tags = ["v", "p", "t", "g", "h", "k", "n", "s"]
            # p (required), public key
            # v (recommended options), version
            # t (recommended options), ?
            # g (optional), granularity
            # h (optional), hash algorythm
            # k (optional), cryptographic algorythm
            # n (optional), comments
            # s (optional), type of service
        for tag in self.tags:
            setattr(self, tag, None)
            
        if dkim_domain is not None and selector is not None:
            self.dkim_domain = dkim_domain
            self.selector = selector
            self.domain = self.selector + "._domainkey." + self.dkim_domain
            
            self.resolver = dns.resolver.Resolver()
            if nameserver is not None:
                self.resolver.nameservers = [nameserver]
            self.request()
        
    def request(self):
        self.record = None
        try:
            answers = self.resolver.resolve(self.domain,'TXT')
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            pass
        except dns.resolver.NXDOMAIN:
            raise
        except:
            raise
        else:
            for answer in answers:
                answer_txt = answer.to_text()
                if '" "' in answer_txt:
                    answer_txt=answer_txt.replace('" "', '')
                if answer_txt[1:-1].startswith("v=DKIM1"):
                    self.record = answer_txt[1:-1]
                    self.parse_record(self.record)
                    return
    
    def parse_record(self, record_str):
        self.record = record_str
        # Isoler chaque tag du DKIM
        record_tags = self.record.split(";")
        for tag in record_tags:
            # Séparer le tag de sa valeur
            tag_parts = tag.strip().split("=")
            # Si le tag a une valeur associée
            if len(tag_parts) == 2:
                # Associer valeur à son attribut
                setattr(self, tag_parts[0].strip().lower(), tag_parts[1].strip())

class SPF:

    def __init__(self, domain, nameserver):
        self.record = None
        self.domain = domain
        
        self.resolver = dns.resolver.Resolver()
        if nameserver is not None:
            self.resolver.nameservers = [nameserver]
            
        self.tags = ["v", "a", "mx", "ptr", "ip4", "ip6", "exists", "all", "redirect", "exp", "include"]
        for tag in self.tags:
            setattr(self, tag, None)
        self.request()
        
        if self.redirect is not None:
            self.redirect = SPF(self.redirect, nameserver)
        
        if self.include is not None:
            for i in range(len(self.include)):
                self.include[i] = SPF(self.include[i], nameserver)

    def request(self):
        self.record = None
            
        try:
            answers = self.resolver.resolve(self.domain,'TXT')
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            pass
        except dns.resolver.NXDOMAIN:
            raise
        except:
            raise
        else:
            for answer in answers:
                answer_txt = answer.to_text()
                if '" "' in answer_txt:
                    answer_txt=answer_txt.replace('" "', '')
                if answer_txt[1:-1].startswith("v=spf1"):
                    self.record = answer_txt[1:-1]
                    break
        self.parse_record(self.record)
        

    def parse_record(self, record_str):
        self.record = record_str
        if self.record is not None:
            records_list = ["all", "mx", "ptr","ip4", "ip6", "exists", "exp","redirect", "include"]
            for item in records_list:
                if item in self.record:
                    setattr(self, item, {})
            if " a " in self.record or "a:" in self.record or "a/" in self.record:
                self.a = {}

            # Isoler chaque tag du SPF
            record_tags = self.record.split()

            name_sign = ["pass", "fail","softfail","neutral"]
            for tag in record_tags:
                for i,sign in enumerate(["+", "-", "~", "?"]): 

                    if tag[0] == sign:
                        if tag[1:] == "all":
                            try:
                                self.all[name_sign[i]].append(tag[1:])
                            except:
                                self.all[name_sign[i]] = []
                                self.all[name_sign[i]].append(tag[1:])
                        
                        if tag[1:] == "a" or tag[1:].startswith("a:") or tag[1:].startswith("a/"):
                            # Si a:domain ou a:ip on garde seulement le domain ou l'ip
                            if tag[1:].startswith("a:"):
                                try:
                                    self.a[name_sign[i]].append(tag[1:].split(":")[1])
                                except:
                                    self.a[name_sign[i]] = []
                                    self.a[name_sign[i]].append(tag[1:].split(":")[1])
                            else:
                                try:
                                    self.a[name_sign[i]].append(tag[1:])
                                except:
                                    self.a[name_sign[i]] = []
                                    self.a[name_sign[i]].append(tag[1:])

                        if tag[1:] == "mx" or tag[1:].startswith("mx:") or tag[1:].startswith("mx/"):
                            # Si a:domain ou a:ip on garde seulement le domain ou l'ip
                            if tag[1:].startswith("mx:"):
                                try:
                                    self.mx[name_sign[i]].append(tag[1:].split(":")[1])
                                except:
                                    self.mx[name_sign[i]] = []
                                    self.mx[name_sign[i]].append(tag[1:].split(":")[1])
                            else:
                                try:
                                    self.mx[name_sign[i]].append(tag[1:])
                                except:
                                    self.mx[name_sign[i]] = []
                                    self.mx[name_sign[i]].append(tag[1:])
                        
                        if tag[1:] == "ptr" or tag[1:].startswith("ptr:") or tag[1:].startswith("ptr/"):
                            # Si a:domain ou a:ip on garde seulement le domain ou l'ip
                            if tag[1:].startswith("ptr:"):
                                try:
                                    self.ptr[name_sign[i]].append(tag[1:].split(":")[1])
                                except:
                                    self.ptr[name_sign[i]] = []
                                    self.ptr[name_sign[i]].append(tag[1:].split(":")[1])
                            else:
                                try:
                                    self.ptr[name_sign[i]].append(tag[1:])
                                except:
                                    self.ptr[name_sign[i]] = []
                                    self.ptr[name_sign[i]].append(tag[1:])

                        if tag[1:].startswith("ip4:"):
                            try:
                                self.ip4[name_sign[i]].append(tag[1:].split(":")[1])
                            except:
                                self.ip4[name_sign[i]] = []
                                self.ip4[name_sign[i]].append(tag[1:].split(":")[1])
                        
                        if tag[1:].startswith("ip6:"):

                            try:
                                self.ip6[name_sign[i]].append(tag[1:].split("ip6:")[-1])
                            except:
                                self.ip6[name_sign[i]] = []
                                self.ip6[name_sign[i]].append(tag[1:].split("ip6:")[-1])
                            
                        if tag[1:].startswith("exists:"):
                            try:
                                self.exists[name_sign[i]].append(tag[1:].split(":")[1])
                            except:
                                self.exists[name_sign[i]] = []
                                self.exists[name_sign[i]].append(tag[1:].split(":")[1])
                                
                else:
                    if tag == "all":
                        try :
                            self.all["pass"].append(tag)
                        except:
                            self.all["pass"] = []
                            self.all["pass"].append(tag)
                            
                    if tag == "a" or tag.startswith("a:") or tag.startswith("a/"):
                        # Si a:domain ou a:ip on garde seulement le domain ou l'ip
                        if tag.startswith("a:"):
                            try:
                                self.a["pass"].append(tag.split(":")[1])
                            except:
                                self.a["pass"] = []
                                self.a["pass"].append(tag.split(":")[1])
                        else:
                            try:
                                self.a["pass"].append(tag)
                            except:
                                self.a["pass"] = []
                                self.a["pass"].append(tag)
                    
                    if tag == "mx" or tag.startswith("mx:") or tag.startswith("mx/"):
                        # Si a:domain ou a:ip on garde seulement le domain ou l'ip
                        if tag.startswith("mx:"):
                            try:
                                self.mx["pass"].append(tag.split(":")[1])
                            except:
                                self.mx["pass"] = []
                                self.mx["pass"].append(tag.split(":")[1])
                        else:
                            try:
                                self.mx["pass"].append(tag)
                            except:
                                self.mx["pass"] = []
                                self.mx["pass"].append(tag)
                        
                    if tag == "ptr" or tag.startswith("ptr:") or tag.startswith("ptr/"):
                        # Si a:domain ou a:ip on garde seulement le domain ou l'ip
                        if tag.startswith("ptr:"):
                            try:
                                self.ptr["pass"].append(tag.split(":")[1])
                            except:
                                self.ptr["pass"] = []
                                self.ptr["pass"].append(tag.split(":")[1])
                        else:
                            try:
                                self.ptr["pass"].append(tag)
                            except:
                                self.ptr["pass"] = []
                                self.ptr["pass"].append(tag)
                                
                    if tag.startswith("ip4:"):
                        try:
                            self.ip4["pass"].append(tag.split(":")[1])
                        except:
                            self.ip4["pass"] = []
                            self.ip4["pass"].append(tag.split(":")[1])
                    
                    if tag.startswith("ip6:"):
                        try :
                            self.ip6["pass"].append(tag.split("ip6:")[-1])
                        except:
                            self.ip6["pass"] = []
                            self.ip6["pass"].append(tag.split("ip6:")[-1])
                    
                    if tag.startswith("exists:"):
                        try :
                            self.exists["pass"].append(tag.split(":")[1])
                        except:
                            self.exists["pass"] = []
                            self.exists["pass"].append(tag.split(":")[1])

                    if tag.startswith("exp="):
                        self.exp = tag.split("=")[1]
                    
                    if tag.startswith("redirect="):
                        self.redirect = tag.split("=")[1]
                    
                    if tag.startswith("include:"):
                        try :
                            self.include.append(tag.split(":")[1])
                        except:
                            self.include = []
                            self.include.append(tag.split(":")[1])