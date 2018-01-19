import csv, json, struct, ipaddress, pycountry, ipwhois, sys, re, time, socket, os, datetime
from ipwhois import IPWhois
from ipwhois.utils import get_countries
from tld import get_tld

class SSHLog:
    """
        SSHLog Class
            - line [string]
            - date
                - datetime [datetime]
                - text [string]
                - integer [integer]
                - year [integer]
                - month [integer]
                - day [integer]
                - hour [integer]
                - minute [integer]
                - second [integer]
            - username[string]
            - source_ip
                - text [string]
                - integer [integer]
            - whois
                - country
                    - text [string(2)]
                    - integer [integer]
                - provider[string]
                - cidr [string]
                - tld [string]
            - success
                - text [string]
                - integer [integer]
    """
    
    def __init__(self, line, date, username, source_ip, success, auth_method):
        # from arguments
        self.line = line
        self.date = date
        self.date["integer"] = self.convert_date_to_unix()
        self.username = = username
        self.source_ip = dict()
        self.source_ip['text'] = source_ip
        self.source_ip['integer'] = self.convert_ip_to_integer()
        self.success = dict()
        self.success['text'] = success
        self.success['integer'] = 1 if success == "Accepted" else 0
        self.auth_method = dict()
        self.auth_method['text'] = "password" if success == "password" else "ssh_key"
        self.auth_method['integer'] = 0 if auth_method == "password" else 1
        self.whois = self.whois_from_ip()
        
        
    def convert_date_to_unix(self):
        """ convert log date to a unix timestamp """
        return int(time.mktime(self.date['datetime'].timetuple()))
    
    def whois_from_ip(self):
        """ return a dictionnary with : provider, cidr, country from self.source_ip """
        obj = IPWhois(self.source_ip['text'])
        results = obj.lookup_whois(False)
        d = dict()
        d['provider'] = results['nets'][0]['name']
        d['cidr'] = results['nets'][0]['cidr']
        d['country'] = dict()
        d['country']['text'] = results['asn_country_code']
        d['country']['integer'] = convert_country_iso_to_numeric(d['country']['text'])
        d['tld'] = self.get_tld_from_ip()
        return d
        
    def convert_ip_to_integer(self):
        """ convert self.source_ip to an integer """
        return int(ipaddress.IPv4Address(self.source_ip['text']))

    def get_tld_from_ip(self):
        fqdn = socket.getfqdn(self.source_ip['text'])
        tld = get_tld(fqdn, fix_protocol=True, fail_silently=True)
        return tld
    
    def to_dict(self):
        return vars(self)
    
    def to_json(self):
        return json.dumps(self.to_dict())
        
    def to_list(self):
        return self.to_dict().values()
        
    def __str__(self):
        return ";".join(self.to_list())


def convert_country_iso_to_numeric(country_iso):
    """ convert country_iso to numeric """
    try:
        numeric = pycountry.countries.get(alpha_2=country_iso).numeric
    except :
        numeric = -1
    return numeric

def parse_line(log_line):
    """ return SSHLog object from a log line """
    m = regex_log(log_line)
    if m is None:
        return
    now = datetime.datetime.now()
    log_date = dict()
    log_date['text'] = m.group(1)
    log_date['datetime'] = datetime.datetime.strptime(str(now.year)+' '+log_date['text'], '%Y %b %d %H:%M:%S')
    if log_date['datetime'] > now:
        log_date['datetime'] = log_date['datetime'].replace(year=now.year-1)
    log_date['year'] = log_date['datetime'].year
    log_date['month'] = log_date['datetime'].month
    log_date['day'] = log_date['datetime'].day
    log_date['hour'] = log_date['datetime'].hour
    log_date['minute'] = log_date['datetime'].minute
    log_date['second'] = log_date['datetime'].second
    log_success = m.group(2)
    log_auth_method = m.group(3)
    log_username = m.group(4)
    log_source_ip = m.group(5)
    return SSHLog(line=log_line,
        date=log_date,
        source_ip=log_source_ip,
        username=log_username,
        success=log_success,
        auth_method=log_auth_method)

def regex_log(log_line):
    """ return Regex object from the log line """
    m = re.search(r"([A-Za-z]{3}\s+[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) .+ (Failed) (.*) for invalid user (.*) from (.*) port", log_line)
    if m is None:
        m = re.search(r"([A-Za-z]{3}\s+[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) .+ (Failed) (.*) for (.*) from (.*) port", log_line)
        if m is None:
            m = re.search(r"([A-Za-z]{3}\s+[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) .+ (Accepted) (.+) for (.*) from (.*) port", log_line)
    # m.group(1, 2, 3, 4, 5)
    return m


