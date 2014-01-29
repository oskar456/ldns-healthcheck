DNS Healthcheck scripts
=======================

Tis repository contains some scripts to check health of DNS zones and DNS
servers.

 - `dnstrace.py` checks correct delegation of DNS zones specified on command
   line
 - `dnsservercheck.py` checks if specified zones are correctly delegated to
   specified DNS server

The scripts requires [ldnsx](https://github.com/colah/ldnsx) library to work

Typical usage
-------------

    xargs ./dnsservercheck.py server.example.com < list_of_domains.txt
    example.cz: server server.example.com. not in delegation nor zone apex
    example.com: server server.example.com. delegated, but not in zone apex
    example.net: server server.example.com. not in delegation nor zone apex

    List of domains, which should be deleted from server config:
    example.cz
    example.net
