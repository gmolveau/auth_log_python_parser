# Auth.log python parser

## Auth.log parser

Library to parse an `auth.log` type file and return a dictionnary describing the log.

The year of the log is set to the current year if it's possible.

## Auth.log enrichment

Library to enrich a log with `whois`, `geoip` ...

## Auth.log parser client

Command line tool which calls the `auth_log_parser` library to parse a folder/file and can also call the 
`auth_log_enrichment` to add datas to a log via `whois`, `country`, `geoip` ...

## How to use it ?

* clone the repo
* create a virtual env
* `pip install -r requirements.txt`
* `python3 auth_log_parser_client ./example -v -e`
