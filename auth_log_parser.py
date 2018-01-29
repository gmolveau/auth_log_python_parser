import json, struct, sys, re, time, socket, os, datetime
import ipaddress, pycountry, ipwhois, geoip2.database
from ipwhois import IPWhois
from ipwhois.utils import get_countries
from tld import get_tld

asn_reader = geoip2.database.Reader('dbs/geolite2_asn.mmdb')
# r = asn_reader.asn('2.2.2.2')
# r.country.iso_code -> 'US'
country_reader = geoip2.database.Reader('dbs/geolite2_country.mmdb')
# r = country_reader.country('1.1.1.1')
# r.autonomous_system_organization -> 'IBM'

class SSHLog:
    """
        SSHLog Class
            - line [string]
            - server_name [string]
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
            - invalid_user [integer]
            - username [string]
            - source_port [integer]
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
            - auth_method
                - text [string]
                - integer [integer]
            - success
                - text [string]
                - integer [integer]
    """
    
    def __init__(self, server_name, line, process, date, invalid_user, username, source_ip, source_port, success, auth_method, full):
        # from arguments
        self.line = line
        self.server_name = server_name
        self.date = date
        self.date["integer"] = self.convert_date_to_unix()
        self.invalid_user = invalid_user
        self.username = username
        self.source_port = source_port
        self.source_ip = dict()
        self.source_ip['text'] = source_ip
        self.source_ip['integer'] = self.convert_ip_to_integer()
        self.auth_method = dict()
        self.auth_method['text'] = "password" if success == "password" else "ssh_key"
        self.auth_method['integer'] = 0 if auth_method == "password" else 1
        self.success = dict()
        self.success['text'] = success
        self.success['integer'] = 1 if success == "Accepted" else 0
        if full:
            self.whois = self.whois_from_ip()
        
    def convert_date_to_unix(self):
        """ convert log date to a unix timestamp """
        return int(time.mktime(self.date['datetime'].timetuple()))
    
    def whois_from_ip(self):
        """ return a dictionnary with : provider, cidr, country from self.source_ip """
        d = dict()
        d['country'] = dict()
        d['country']['text'] = country_reader.country(self.source_ip['text']).country.iso_code
        d['country']['integer'] = convert_country_iso_to_numeric(d['country']['text'])
        try:
            d['provider'] = re.sub('[^0-9a-zA-Z]+', '',asn_reader.asn(self.source_ip['text']).autonomous_system_organization)
            d['cidr'] = ''
        except:
            try:
                obj = IPWhois(self.source_ip['text'])
                results = obj.lookup_whois(False)
                d['provider'] = re.sub('[^0-9a-zA-Z]+', '', results['nets'][0]['name'])
                d['cidr'] = results['nets'][0]['cidr'] 
            except:
                d['provider'] = ''
                d['cidr'] = ''
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

def parse_line(log_line, full=False):
    """ return SSHLog object from a log line """
    m = regex_log(log_line)
    if m is None:
        return
    now = datetime.datetime.now()
    log_date = dict()
    log_date['datetime'] = datetime.datetime.strptime(str(now.year)+' '+m['date'], '%Y %b %d %H:%M:%S')
    if log_date['datetime'] > now:
        log_date['datetime'] = log_date['datetime'].replace(year=now.year-1)
    log_date['text'] = log_date['datetime'].strftime("%Y-%m-%d %H:%M:%S")
    log_date['year'] = log_date['datetime'].year
    log_date['month'] = log_date['datetime'].month
    log_date['day'] = log_date['datetime'].day
    log_date['hour'] = log_date['datetime'].hour
    log_date['minute'] = log_date['datetime'].minute
    log_date['second'] = log_date['datetime'].second
    log_success = m['success']
    log_auth_method = m['auth_method']
    log_username = re.sub('[^0-9a-zA-Z_-]+', '', m['user'])
    log_source_ip = m['ip_address']
    invalid_user = 1 if m['invalid_user'] == "invalid user" else 0
    return SSHLog(line=log_line,
        process=m['process'],
        date=log_date,
        source_ip=log_source_ip,
        source_port=m['port_number'],
        invalid_user=invalid_user,
        username=log_username,
        success=log_success,
        auth_method=log_auth_method,
        server_name=m['server_name'],
        full=full)

def parse_file(log_file_path, full=False):
    if os.path.isfile(log_file_path):
        with open(log_file_path) as log_file:
            print("Reading file :", log_file.name)
            logs = []
            for log_line in log_file.readlines():
                sshLog = parse_line(log_line, full)
                if sshLog is not None:
                    logs.append(sshLog)    
            return logs

def parse_folder(logs_folder_path, full=False):
    logs = []
    if os.path.isdir(logs_folder_path):
        for log_file in os.listdir(logs_folder_path):
            log_file_path = os.path.join(logs_folder_path,log_file)
            if os.path.isfile(log_file_path):
                logs.extend( parse_file(log_file_path, full) )
    return logs

def regex_log(log_line):
    """ return Regex object from the log line """
    m = re.search(r"([A-Za-z]{3}\s+[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) (.*) (.*): (Failed|Accepted) (password|publickey|none) for(\s(invalid user)\s|\s)(.*) from (.*) port ([0-9]{1,5}) (.*)", log_line)
    if m is None:
        return m
    else :
        return {
            'date': m.group(1),
            'server_name': m.group(2),
            'process': m.group(3),
            'success': m.group(4),
            'auth_method': m.group(5),
            'invalid_user': m.group(7),
            'user': m.group(8),
            'ip_address': m.group(9),
            'port_number': m.group(10),
            'ssh2': m.group(11) 
        }


