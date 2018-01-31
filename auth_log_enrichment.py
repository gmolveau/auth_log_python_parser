import re
import socket
import time
import ipaddress
import pycountry
import ipwhois
import geoip2.database
from ipwhois import IPWhois
from ipwhois.utils import get_countries
from tld import get_tld

asn_reader = geoip2.database.Reader('./dbs/geolite2_asn.mmdb')
country_reader = geoip2.database.Reader('./dbs/geolite2_country.mmdb')


def enrich_logs(logs, verbose=False):
    for log in logs:
        enrich_log(log, verbose)


def enrich_log(log, verbose=False):
    # TODO : manage verbose
    log["source_ip"]["integer"] = convert_ip_to_integer(log["source_ip"]["text"])
    log["date"]["integer"] = convert_date_to_unix(log["date"]["datetime"])
    log["country"] = get_country(log["source_ip"]["text"])
    log["whois"] = whois_from_ip(log["source_ip"]["text"])
    if(verbose):
        print(
            "\n ~~~ Enrichment ~~~ \n"
            " country:",
            log["country"]["text"],
            "provider:",
            log["whois"]["provider"],
            "\n"
        )


def convert_ip_to_integer(ip):
    """ convert self.source_ip to an integer """
    return int(ipaddress.IPv4Address(ip))


def convert_date_to_unix(date):
    """ convert datetime type to a unix timestamp """
    return int(time.mktime(date.timetuple()))


def get_country(ip):
    d = dict()
    d['text'] = country_reader.country(ip).country.iso_code
    d['integer'] = convert_country_iso_to_numeric(d['text'])
    return d


def convert_country_iso_to_numeric(country_iso):
    """ convert country_iso to numeric """
    try:
        numeric = pycountry.countries.get(alpha_2=country_iso).numeric
    except:
        numeric = 0
    return numeric


def whois_from_ip(ip):
    """ return a dictionnary with : provider and cidr from IP adress """
    d = dict()
    try:
        d['provider'] = re.sub(
            '[^0-9a-zA-Z_-]+', '', asn_reader.asn(ip).autonomous_system_organization)
        d['cidr'] = ''
    except:
        try:
            obj = IPWhois(self.source_ip['text'])
            results = obj.lookup_whois(False)
            d['provider'] = re.sub('[^0-9a-zA-Z_-]+', '',
                                   results['nets'][0]['name'])
            d['cidr'] = results['nets'][0]['cidr']
        except:
            d['provider'] = ''
            d['cidr'] = ''
    return d


def get_tld_from_ip(ip):
    fqdn = socket.getfqdn(ip)
    tld = get_tld(fqdn, fix_protocol=True, fail_silently=True)
    return re.sub('[^0-9a-zA-Z_-]+', '', tld)
