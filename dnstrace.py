#!/usr/bin/env python2
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
        print "Extra Glues for {}: {}".format(gluename, ", ".join(extra_glues))


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
            result.add(item[4]);
    return result;

def tracens(domain):
    """Traces domain from the root down, notifying delegation and glue errors"""

    my_res = ldnsx.resolver("j.root-servers.net");

    result = my_res.query(domain, "NS", flags=[]);
    if result is None:
        print "Error: root name server failure"
        sys.exit()

    referrals = list();
    while result.answer() == []:
        my_res.drop_nameservers()
        for ns in result.authority(rr_type='NS'):
            my_res.add_nameserver(ns[4])
        #print "Referral:\n{}\nGLUES:\n{}\n****".format(result.authority(),
        #       result.additional())
        referrals.append(result.authority())
        checkglues(result.additional())
    
        result = my_res.query(domain, "NS", flags=[]);
        if result is None:
            print "Error: No data for {} !".format(domain)
            if referrals:
                print "Last referral was\n{}\n".format(referrals.pop())
            break
    
    if result:
        lastref = referrals.pop()
        #print "Delegation:\n{}".format(lastref)
        #print "Final:\n{}".format(result.answer())
        if lastref[0].owner() == result.answer()[0].owner():
            delegation = rrtoset(lastref)
            final = rrtoset(result.answer())
            missing_delegations = final - delegation
            extra_delegations = delegation - final
            if missing_delegations:
                print "Missing delegations for {}: {}".format(domain, ", ".join(missing_delegations))
            if extra_delegations:
                print "Extra delegations for {}: {}".format(domain, ", ".join(extra_delegations))



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: {} <domain name with NS record> ...".format(sys.argv[0])
    else:
        for domain in sys.argv[1:]:
            tracens(domain);



