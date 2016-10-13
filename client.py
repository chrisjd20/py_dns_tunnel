import logging,sys,random
from optparse import OptionParser
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP,UDP,DNS,DNSQR,DNSRR,sr


def client_scapy(sub_domain,dns_server,query_type="TXT"):
    """
       Args:
       dns_server - server to send dns request to
       sub_domain - domain to query
       query_type - type of DNS query A,TXT,CNAME..

       Returns:
       txt_data - the text in the TXT rdata field
    """

    print "Sending "+query_type+" record request for "+ sub_domain
    random_source_port = random.randint(10000,20000)
    dns_request = DNSQR(qtype=query_type, qname=sub_domain)
    ip_packet = IP(dst=dns_server)/UDP(sport=random_source_port,dport=53)/DNS(qd=dns_request)
    (answered_packets,unanswered_packets) = sr(ip_packet,verbose=True,timeout=1,iface="vmnet8",multi=True)
    txt_data=""
    for i in answered_packets:
        for p in i:
            if DNSRR in p:
                txt_data = p[DNSRR].fields['rdata']
    print txt_data
    return txt_data



def main():
    parser = OptionParser(usage="usage: %prog [options]",version="%prog 1.0")
    parser.add_option("-d", "--domain",type="string",dest="domain",help="domain to query")
    parser.add_option("-s", "--dns-server",type="string",dest="dns_server",help="dns server to send DNS request to")

    (options, args) = parser.parse_args()
    if options.domain is None or options.dns_server is None:
        parser.print_help()
    else:
        client_scapy(options.domain,options.dns_server)

if __name__ == '__main__':
    main()

