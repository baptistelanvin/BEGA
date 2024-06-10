# Guide d'installation et d'utilisation de BEGA

#### Projet 4A : Outil d'agrégation de données publiques à des fin d'audits d'entreprise



### 1. Installation Bega

------

##### Bega :

```
git clone https://github.com/baptistelanvin/BEGA
cd bega
```



##### Requirements :

```
pip install -r requirements.txt
```



### 2. Démarrage

------

Configuration des clés API Shodan et Have I Been Pwned dans le fichier **./bega/config.ini** : (à créer)

```
./config.ini

[API_KEY]
    shodan_api_key  =   Your_API_Key
    hibp_api_key    =   Your_API_Key
```

- Pour récupérer la [clé API Shodan](https://developer.shodan.io/)
- Pour récupérer la clé API HIBP, [s'inscrire](https://haveibeenpwned.com/API/Key) et regarder dans ses mails



### 3. Utilisation

------

- Lancer un scan complet sur un domaine ou une ip :

```
python bega.py domain.com
python bega.py ip
```



### 4. Options

------

- Mode multi-domaines et/ou IPs :

```
python bega.py domain1.com domain2.com 1.1.1.1 2.2.2.2/24 
```



- Sélection du scan à réaliser (possibilité d'en choisir plusieurs):

> - **-t, --tapirus**
> - **-g, --goat**
> - **-o, --owl**
> - **-k, --kangaroo**
> - **-b, --badger**

Lance un scan Goat et Kangaroo sur le domain "domain.com" :

```
python bega.py -gk domain.com
```



- **-l, --limit {"MAX-LIMIT"}** : pour définir le nombre de résultats désirés lors du Google Dork sur LinkedIn. Un trop grand nombre de résultats pourrait faire remonter une alerte "TooManyRequests" et vous bannir temporairement.
- **-d, --DKIM {"SELECTOR"} {"DOMAIN"}** : pour spécifier le DKIM.

Lance un scan Kangaroo en spécifiant le DKIM et un scan Badger avec une limite de 20:

```
python bega.py -d selector1 domain.com -l 20 -kb domain.com
```



- **-m, --modify {"YYYY-MM-DD-HH-MM-SS"}** : pour spécifier le timestamp du dossier à modifier associé à un scan passé.

```
python bega.py -m "2023-01-25-12-45-59" domain.com
```



### 5. Résultats

------

Les résultats des scans sont stockés dans le dossier ./bega/reports/ dans des dossiers référencés avec des timestamps.

> - **"YYYY-MM-DD-HH-MM-SS-BegaScan-domain.com"** Pour un scan de domaine simple.
> - **"YYYY-MM-DD-HH-MM-SS-MultipleReports"** Pour un scan de plusieurs domaines.
> - **"YYYY-MM-DD-HH-MM-SS-ScanIP"** Pour un scan de une ou plusieurs IP(s).

Architecture d'un dossier de report pour un scan de domaine simple (./bega/reports/):

```
YYYY-MM-DD-HH-MM-SS-BegaScan-domain.com/
├─── badger/
│    └─── YYYY-MM-DD-HH-MM-SS-emails-domain.com.json
│
├─── goat/
│    ├─── YYYY-MM-DD-HH-MM-SS-ssllabs-sub-domain1.com.json
│    ├─── YYYY-MM-DD-HH-MM-SS-ssllabs-sub-domain2.com.json
│    └─── ...
│
├─── kangaroo/
│    └─── YYYY-MM-DD-HH-MM-SS-dnsrecords-domain.com.json
│
├─── owl/
│    ├─── YYYY-MM-DD-HH-MM-SS-owl-mx1.domain.com.json
│    ├─── YYYY-MM-DD-HH-MM-SS-owl-mx2.domain.com.json
│    └─── ...
│
├─── YYYY-MM-DD-HH-MM-SS-REPORT-BEGA.json (report Bega)
└─── YYYY-MM-DD-HH-MM-SS-shodan-google.com.json (report Tapirus)
```



### 6. Aide

------

L'argument **-h** permet d'afficher le message d'aide suivant :

```
usage: bega.py [-h] [-l MAX-LIMIT] [-d SELECTOR DOMAIN] [-t] [-g] [-o] [-k] [-b] [-m TIMESTAMP] 
                domain or IP [domain or IP ...]

Bega

positional arguments:
  domain or IP          domain name of the company. (Multiple domains and IP are allowed)

options:
  -h, --help            show this help message and exit
  -l MAX-LIMIT, --limit MAX-LIMIT
                        Max search results for dorks. (Default: 10)
  -d SELECTOR DOMAIN, --DKIM SELECTOR DOMAIN
                        Checks DKIM record. Two values are required: selector and domain
  -t, --tapirus         tapirus scan
  -g, --goat            goat scan
  -o, --owl             owl scan
  -k, --kangaroo        kangaroo scan
  -b, --badger          badger scan. (These arguments can be combined like -tgokb)
  -m TIMESTAMP, --modify TIMESTAMP
                        timestamp of the folder to be modified. (e.g. -m "2023-12-20-20-55-00")
```



### 7. Utilisation du scanner de vulnérabilités WEB (Weasel)

------

Weasel est un outil d'automatisation du scanneur de vulnérabilités web [OWASP ZAPROXY](https://www.zaproxy.org/)

Il permet grâce à une seule ligne de commande de lancer un scan complet d'un site web et de générer un rapport.



#### Installation ZAPROXY

------

Le logiciel ZAPROXY version 2.15.0 est nécessaire pour l'utilisation de Weasel:

> [ZAPROXY 2.15.0](https://www.zaproxy.org/download/) (nécessite Java 11 JRE ou plus: [lien](https://www.java.com/fr/download/manual.jsp))



#### Installation Weasel

------

Weasel :

```
git clone https://github.com/Lotter-35/bega.git
cd weasel
```



Requirements :

```
pip install -r requirements.txt
```



#### Démarrage

------

Plateformes de tests à héberger pour commencer des attaques:

- [Bodgeit](https://github.com/psiinon/bodgeit) est une application web vulnérable recommandée lors des tests avec Zaproxy.
- [Juice-Shop](https://github.com/juice-shop/juice-shop) est la nouvelle version de Bodgeit.
- [DVWA](https://github.com/digininja/DVWA) une alternative d'application vulnérable.

Vous pouvez aussi l'utiliser sur n'importe quel site web où vous êtes autorisé à réaliser des tests de pénétration.



Il est nécessaire d'avoir accès à l'API ZAP.

- ZAPROXY version graphique en local :

  > zap.exe sur Windows
  > zaproxy sur Linux

- ZAPROXY version daemon :

Windows :

```
cd "C:\Program Files\OWASP\Zed Attack Proxy"
```

```
zap.bat -daemon
```



Linux :

```
java -jar zap-2.12.0.jar -daemon
```



#### Configuration de la clé API et du port du proxy

**(ZAP ne doit pas être lancé)**

------

Windows :

```
cd "C:\Program Files\OWASP\Zed Attack Proxy"
```

```
zap.bat -cmd -config api.key=YourApiKey -port 8090
```



Linux :

```
java -jar zap-2.12.0.jar -cmd -config api.key=YourApiKey -port 8090
```



Interface graphique :

```
API KEY : Tools -> Options -> API -> ApiKey
```

```
Proxy port : Tools -> Options -> Network -> Local Servers/Proxies -> Port
```



Par défault l'API est accessible en local à l'adresse suivante : http://127.0.0.1:8090/



#### Lancer le script

------

```
python weasel.py --apikey YourApiKey --proxy 127.0.0.1:8090
```

Le menu d'aide :

```
python weasel.py -h
```



| options :                                                    | description :                                                |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| -h, --help                                                   | Show this help message and exit                              |
| --apikey KEY                                                 | API key of ZAP API                                           |
| --proxy IP:PORT                                              | IP of OWASP proxy (default is 127.0.0.1:8090)                |
| --recreate                                                   | Re-create the whole session                                  |
| -t URL, --target URL                                         | URL of the target (e.g. http://local.test.com/target)        |
| --authMethod [METHOD]                                        | Select from : formBasedAuthentication / scriptBasedAuthentication / httpAuthentication manualAuthentication / jsonBasedAuthentication<br />(Currently, only "formBasedAuthentication" is working.) |
| --loginPage "URI"                                            | Page of the login (e.g. http://url/login.php --loginPage "/login.php") |
| -u USERNAME                                                  | Username used in login page (e.g. exampleUsername)           |
| -p PASSWORD                                                  | Password used in login page (e.g. examplePassword)           |
| --requestData "DATA"                                         | Request data for login (e.g. "username=exampleUsername&password=examplePassword") |
| --patLogIn "PATTERN"                                         | Pattern to indentify Logged In messages(e.g. "You are Logged in.") |
| --patLogOut "PATTERN"                                        | Pattern to identify Logged Out messages(e.g. "Sign in ?")    |
| --spider                                                     | Start SpiderScan ONLY                                        |
| --ascan                                                      | Start SpiderScan and ActiveScan both                         |
| --report [NAME or PATH]                                      | Generate report of the session (Default name: '{{yyyy-MM-dd-HH-mm-ss}}-ZAP-Report') |
| --templates [{traditional-json, traditional-md, traditional-pdf, traditional-xml, sarif-json, modern, traditional-html, high-level-report, traditional-xml-plus, risk-confidence-html, traditional-html-plus, traditional-json-plus}] | Print list of templates or modify it (Default: traditional-json-plus) |
| --display                                                    | Display the generated report                                 |
| --showconfig                                                 | Show current configuration                                   |



#### Scan Spider :

------

Un scan spider est un outil qui parcourt automatiquement les pages web d'un site en suivant les liens qui y sont présents.

Commande (scan spider + rapport):

```
python waesel.py --apikey YourApiKey --proxy 127.0.0.1:8090 --target http://127.0.0.1:8080 --spider --report --display
```



#### Active Scan :

------

Le scan actif ZAP, envoie des requêtes à l'application web et analyse les réponses pour identifier les vulnérabilités potentielles. Il est capable de découvrir un grand nombre de vulnérabilités, comme les injection SQL, XSS, les fuites de données, les vulnérabilités de type "Broken Access Control" ou encore les vulnérabilités d'autorisations.

Commande (scan actif + rapport):

```
python waesel.py --apikey YourApiKey --proxy 127.0.0.1:8090 --target http://127.0.0.1:8080 --ascan --report --display
```



#### Comment s'authentifier :

------

Pour le moment, seule la méthode d'authentification par formulaire est possible.

Il faut utiliser les arguments suivants :

> - --authMethod "formBasedAuthentication"
> - --loginPage "/login.php"
> - -u exampleUsername
> - -p examplePassword
> - --requestData "username=exampleUsername&password=examplePassword"
>   *Ceci est la donnée envoyée dans la requête post, générée par le formulaire lors de l'authentification.*

```
python waesel.py --apikey YourApiKey --proxy 127.0.0.1:8090 --target http://127.0.0.1:8080, 
--authMethod "formBasedAuthentication",
--loginPage "/login.php",
-u exampleUsername,
-p examplePassword,
--requestData "username=exampleUsername&password=examplePassword", 
--ascan --report --display
```



Optionnel si vous souhaitez connaitre l'état de l'authentification (Réussi ou non) :

> - --patLogIn "You are Logged in."
>
> - --patLogOut "Sign in ?"
>
>   *Il s'agit d'une chaine de charactère présente dans la page html permettant de différencier une page "authentifiée" d'une "non authentifiée"*

