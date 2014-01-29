#!/usr/bin/env python2
# vim: expandtab tabstop=4

# DNS Delegation checker
# Copyright Ondrej Caletka, CESNET 2014
# Licence: GNU GPLv2

from collections import defaultdict

import ldnsx
import sys

system_res = ldnsx.resolver();

def name2ipset(name):
    """Returns a set of IPv4 and IPv6 addresses associated with a name"""
    arecords = system_res.query(name, 'A').answer(rr_type="A")
    aaaarecords = system_res.query(name, 'AAAA').answer(rr_type="AAAA")
    results = set()
    for record in arecords:
        results.add(record['ip'])
    for record in aaaarecords:
        results.add(record['ip'])
    return results

def analyzeglues(gluename, glueips):
    """Analyze difference between GLUE records and actual values from DNS."""
    dnsips = name2ipset(gluename);
    #print "Glues for {}:\n{}\nDNS set for {}:\n{}\n".format(gluename, glueips, gluename, dnsips);
    missing_glues = dnsips - glueips;
    extra_glues = glueips - dnsips;
    if missing_glues:
        print "Missing glues for {}: {}".format(gluename, ", ".join(missing_glues))
    if extra_glues:
        print "Extra elues for {}: {}".format(gluename, ", ".join(extra_glues))


def checkglues(rrset):
    """Check GLUE records in ADDITIONAL section with actual values from DNS"""
    glues = defaultdict(set);
    for glue in rrset:
        glues[glue['owner']].add(glue['ip'])

    for gluename, glueips in glues.iteritems():
        analyzeglues(gluename, glueips);

def rrtoset(rrset):
    """Convert NS-type RRset to a set of NS servers."""
    result = set()
    for item in rrset:
        if item.rr_type() == "NS":
            result.add(item[4].lower());
    return result;

def tracens(server, domain):
    """
    Traces domain from the root down,
    watches for non delageted zones.
    
    Returns boolean status if zone should be removed from server config.
    False...zone should be kept in server config
    True ...zone should be deleted
    """
    if domain == ".": #Questions regarding root zone would not lead to a refferal answer
        return True
    res = ldnsx.resolver()
    my_res = ldnsx.resolver("j.root-servers.net");

    result = my_res.query(domain, "NS", flags=[]);
    if result is None:
        print "Error: root name server failure"
        sys.exit()

    loopcount = 0
    referrals = list();
    while result and not result.answer():
        #print "AUTHORITY\n{}\nADDITIONAL\n{}\n\n".format(result.authority(), result.additional())
        referral = result.authority(rr_type='NS')
        referrals.append(referral)
        if result.rcode() == "NXDOMAIN":
            print "{}: delegation ends at {}".format(domain,
                    result.authority().pop().owner())
            result = None;
            break

        result=None
        loopcount += 1
        if loopcount > 20:
                print "{}: Looping detected".format(domain)
                break

        #Iterate through referrals to find the longest chain
        for ns_rr in referral:
            ns = ns_rr[4]
            nsip4 = res.query(ns, 'A');
            nsip6 = res.query(ns, 'AAAA');
            if ( (not nsip4.answer(rr_type='A')) and
                 (not nsip6.answer(rr_type='AAAA')) ):
                print "{}: Invalid delegation to {}".format(domain,ns)
                continue

            my_res.drop_nameservers()
            my_res.add_nameserver(ns)
            r = my_res.query(domain, "NS", flags=[]);
            if not r:
                print "{}: Query failed on server {}".format(domain, ns)
            elif r.rcode() not in ("NOERROR", "NXDOMAIN"):
                print "{}: RCODE {} from server {}".format(domain, r.rcode(), ns)
    #Prefer refferals instead of final answers, if chain is not too long
            elif (result is None) or (result.answer() and (not r.answer())
                    and loopcount < 10 ): 
                result=r
                if not result.answer():
                    break #We have a referral already


    if result:
        lastref = referrals.pop()
        #print "Delegation:\n{}".format(lastref)
        #print "Final:\n{}".format(result.answer())
        if lastref[0].owner() == result.answer()[0].owner():
            delegation = rrtoset(lastref)
            final = rrtoset(result.answer())
            if server not in (delegation | final):
                print "{}: server {} not in delegation nor zone apex".format(domain, server)
                return True
            elif server not in delegation:
                print "{}: server {} in zone apex, but not in the delegation".format(domain, server)
            elif server not in final:
                print "{}: server {} delegated, but not in zone apex".format(domain, server)
        else:
            if server not in rrtoset(result.answer()):
                print "{}: subdomain on same server, {} not in apex".format(domain, server)
                return True

    #Result would be None if delegation chain is broken
    return False if result else True;



if __name__ == "__main__":
    if len(sys.argv) < 3:
        print "Usage: {} <server whose zones are checked> <domain name with NS record>...".format(sys.argv[0])
    else:
        server = sys.argv[1]
        if not server.endswith('.'):
            server = "{}.".format(server)
        todelete = list()
        for domain in sys.argv[2:]:
            status = tracens(server,domain);
            if status:
                todelete.append(domain);

        print "\nList of domains, which should be deleted from server config:"
        print "\n".join(todelete);

