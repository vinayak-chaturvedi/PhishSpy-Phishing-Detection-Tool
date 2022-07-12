import requests
import re, tldextract, whois, favicon, socket #pip install python-whois
import dns.resolver #pip install dnspython
import xmltodict
import tarfile
import os.path, time, datetime


suspectScore = 0

#for low and high severity suspecious : Score = Score + 1

#1
def checkIp(url):   #not critical (medium)
    global suspectScore
    checkIp=re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",url) or re.search("(([+-]?(?=\.\d|\d)(?:\d+)?(?:\.?\d*))(?:[eE]([+-]?\d+))?([a-zA-Z]+([+-]?(?=\.\d|\d)(?:\d+)?(?:\.?\d*))(?:[eE]([+-]?\d+))?)+)",url)
    if checkIp: # Ye Phishing Hai
        suspectScore = suspectScore + 3
        return True
    else:
        return False
#2
def checkUrlLength(url):    
    global suspectScore
    if len(url) < 54:
        return False
    elif(len(url)>=54 and len(url)<=75):
        suspectScore=suspectScore+2
        return True
    else:
        suspectScore=suspectScore+4
        return True
#3
def checkUrlSymbol(url):    #critical
    global suspectScore
    if "@" in url:
        suspectScore=suspectScore+5
        return True
    else:
        return False
#4
def checkDomainHyphen(url):     #not critical
    global suspectScore
    ext = (tldextract.extract(url)).domain
    if "-" in ext:
        suspectScore=suspectScore+2
        return True
    else:
        return False
#5
def checkDomainAge(url):       #critical
    global suspectScore
    try:
        w = whois.whois(url)
        w = w['creation_date']
        now = datetime.datetime.today()
        days = (now - w).days
        if days < 182:
            suspectScore=suspectScore+5
            return True
        else:
            return False
    except:
        return False
#6
def checkDomainExpiry(url):     #non critical
    global suspectScore
    try:
        w = whois.whois(url)
        w = w['creation_date']
        now = datetime.datetime.today()
        days = (now - w).days
        if days < 365:
            suspectScore=suspectScore+4
            return True
        else:
            return False
    except:
        return False

#7
def checkFaviconSource(url):        #critical
    global suspectScore
    givenUrl = (tldextract.extract(url)).domain
    icon = (tldextract.extract(favicon.get(url)[0][0])).domain
    if givenUrl != icon:
        suspectScore=suspectScore+5
        return True
    else:
        return False
#8
def checkShortenUrl(url):       #not critical
    global suspectScore
    sProviders=['T.LY', 'bit.ly', 'is.gd', 'Ow.ly', 'shrunken.com', 'p.asia', 'g.asia', '3.ly', '0.gp', '2.ly', '4.gp', '4.ly', '6.ly', '7.ly', '8.ly', '9.ly', '2.gp', '6.gp', '5.gp', 'ur3.us', 'tiny.cc', 'soo.gd', 'clicky.me', 'bl.ink', 'buff.ly', 'rb.gy', 't2mio', 'bit.do', 'cutt.ly', 'shorturl.at', 'urlzs.com', 'LinkSplit', 'short.io', 'kutt.it', 'switchy.io', 'han.gl', 'lh.ms']
    for i in sProviders:
        if i in url:
            suspectScore=suspectScore+3
            return True
        else:
            return False
#9
def checkOpenPorts(url):        #not critical
    global suspectScore
    if(tldextract.extract(url).subdomain):
        ip=tldextract.extract(url).subdomain+"."+tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    else:
        ip=tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    print(ip)
    portsToBeChecked=[21,22,23,80,443,445,1433,1521,3306,3389]
    OpenPortsShouldBe=[80,443]
    OpenPorts=[]
    for port in portsToBeChecked:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((ip, int(port)))
            OpenPorts.append(port)
        except:
            continue
    if(OpenPorts!=OpenPortsShouldBe):
        suspectScore=suspectScore+3
        return True
    else:
        return False
#10
def checkHttpsInDomain(url):        #critical
    global suspectScore
    if(tldextract.extract(url).subdomain):
        url=tldextract.extract(url).subdomain+"."+tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    else:
        url=tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    if "https" in url:
        suspectScore=suspectScore+5
        return True
    else:
        return False
#11
def checkDNSRecord(url):        #critical
    global suspectScore
    if(tldextract.extract(url).subdomain):
        url=tldextract.extract(url).subdomain+"."+tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    else:
        url=tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    if(dns.resolver.resolve(url, 'MX') or dns.resolver.resolve(url, 'A') or dns.resolver.resolve(url, 'NS')):
        return False
    else:
        suspectScore=suspectScore+5
        return True
#12
def checkDomainRank(url):       #critical
    global suspectScore
    url=tldextract.extract(url).domain+"."+tldextract.extract(url).suffix
    url='http://data.alexa.com/data?cli=100&dat=s&url='+str(url)
    response = requests.get(url)
    dict_data = xmltodict.parse(response.content)
    try:
        if(int(dict_data['ALEXA']['SD'][1]['REACH']['@RANK'])<100000):
            return False
        elif(int(dict_data['ALEXA']['SD'][1]['REACH']['@RANK'])>100000):
            suspectScore=suspectScore+5
            return True
    except:
        suspectScore=suspectScore+2
        return True
#13
def checkRedirection(url):     
    global suspectScore
    r = requests.get(url, allow_redirects=True)
    if(len(r.history)<=1):
        return False
    elif(len(r.history)>=2 and len(r.history)<4):
        suspectScore=suspectScore+2.5
        return True
    else:
        suspectScore=suspectScore+5
        return True
#14
def checkMaliciousIframe(url):      #critical
    global suspectScore
    r = requests.get(url)
    if('frameborder="0"' in r.text):
        suspectScore=suspectScore+5
        return True
    else:
        return False
#15
def checkRequestURL(url):     
    global suspectScore
    domain = (tldextract.extract(url)).domain + "." + (tldextract.extract(url)).suffix
    response = requests.get(url)
    response = response.text
    allurl=re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', response)
    relatedurl=[]
    nonrelatedurl=[]

    for i in allurl:
        if domain in i:
            relatedurl.append(i)
        else:
            nonrelatedurl.append(i)
    try:
        percentagerelatedurl=(((len(relatedurl)/len(allurl)))*100)
        percentagenonrelatedurl=(((len(nonrelatedurl)/len(allurl)))*100)
    except:
        return False
    if(percentagenonrelatedurl < 22):
        return False
    elif(percentagenonrelatedurl>=22 and percentagenonrelatedurl<=61):
        suspectScore=suspectScore+1
        return True
    else:
        suspectScore=suspectScore+4
        return True
#16

def checkPhishDatabase(url):        #most critical
    global suspectScore
    ti=time.ctime(os.path.getmtime("ALL-phishing-domains.tar.gz"))
    date_time_obj = datetime.datetime.strptime(ti, '%a %b %d %H:%M:%S %Y')

    now=datetime.datetime.today()
    days = (str((now - date_time_obj)).split())
    days=days[0].split(":")
    
    if (int(days[0])>=24):
        response=requests.get("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL-phishing-domains.tar.gz")
        open('ALL-phishing-domains.tar.gz', 'wb').write(response.content)
        (tarfile.open('ALL-phishing-domains.tar.gz')).extractall('./')

    domain = (tldextract.extract(url)).domain + "." + (tldextract.extract(url)).suffix
    phishdomain = open("ALL-phishing-domains.txt", "r")
    lines = set(phishdomain.read().splitlines())

    if domain in lines:
        suspectScore=suspectScore+5
        return True
    else:
        return False

#17
def checkSlashRedirection(url):     #non critical
    global suspectScore
    count=len(re.findall("//",url))
    if count>1:
        suspectScore=suspectScore+2
        return True   
    else:
        return False

#18
def checkSubdomainCount(url):       #non critical
    global suspectScore
    if(tldextract.extract(url).subdomain):
        url=(tldextract.extract(url).subdomain).split(".")
        subdomain=len(url)
        if subdomain>1:
            suspectScore=suspectScore+2
            return True
        else:
            return False
    else:
        return False

def run(url):
    global suspectScore
    summary = []
    if checkIp(url):
        summary.append("IP address is used as an alternative of the domain name in the URL, website containing IP address are generally phishing, trying to steal their personal information.")
    if checkUrlLength(url):
        summary.append("Phishing websites uses long URL to hide the doubtful part in the address bar.")
    if checkUrlSymbol(url):
        summary.append("Phishing websites generally contains symbols such as using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol.")
    if checkDomainHyphen(url):
        summary.append("The dash symbol is rarely used in legitimate URLs. Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage. ")
    if checkDomainAge(url):
        summary.append("Phishing websites mostly live for a short period of time. By reviewing our dataset, we find that the minimum age of the legitimate domain is 6 months")
    if checkDomainExpiry(url):
        summary.append("Based on the fact that a phishing website lives for a short period of time, we believe that trustworthy domains are regularly paid for several years in advance. In our dataset, we find that the longest fraudulent domains have been used for one year only.")
    if checkFaviconSource(url):
        summary.append("If the favicon is loaded from a domain other than that shown in the address bar, then the webpage is likely to be considered a Phishing attempt. ")
    if checkShortenUrl(url):
        summary.append("Mostly phishing website uses url shortening method.")
    if checkOpenPorts(url):
        summary.append("Several firewalls, Proxy and Network Address Translation (NAT) servers will, by default, block all or most of the ports and only open the ones selected. If all ports are open there is high chance og phishing website.")
    if checkHttpsInDomain(url):
        summary.append("The existence of HTTPS is very important in giving the impression of website legitimacy.")
    # if checkDNSRecord(url):
    #     result.append("For phishing websites, either the claimed identity is not recognized by the WHOIS database or no records founded for the hostname. If the DNS record is empty or not found then the website is considered as “Phishing”.")
    if checkDomainRank(url):
        summary.append("Checking the domain rank using Alexa. Websites having the alexa rank more than a lakh are generally phishing.")
    if checkRedirection(url):
        summary.append("The fine line that distinguishes phishing websites from legitimate ones is how many times a website has been redirected, phishing websites containing this feature have been redirected at least 4 times. ")
    if checkMaliciousIframe(url):
        summary.append("IFrame is an HTML tag used to display an additional webpage into one that is currently shown. Phishers can make use of the “iframe” tag and make it invisible i.e. without frame borders. In this regard, phishers make use of the “frameBorder” attribute which causes the browser to render a visual delineation.")
    if checkRequestURL(url):
        summary.append("Request URL examines whether the external objects contained within a webpage such as images, videos and sounds are loaded from another domain. In Phishing webpages, the webpage address and most of objects embedded within the webpage are from the external domain.")
    if checkPhishDatabase(url):
        summary.append("Checking the url in the databases containing list of phishing websites. ")
    if checkSlashRedirection(url):
        summary.append("The existence of “//” within the URL path means that the user will be redirected to another website. If the Position of the Last Occurrence of "//" in the URL > 7 → Phishing.")
    if checkSubdomainCount(url):
        summary.append("If the website contains more than one sub-domain then there is a high chance of phishing website.")
    return suspectScore, summary