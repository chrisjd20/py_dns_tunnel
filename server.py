import logging, traceback, struct
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from optparse import OptionParser
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send,sniff, ICMP


def encode_rdata(rdata):
    for i in range(0, len(rdata), 0xff+1):
        rdata = rdata[:i] + chr(len(rdata[i:i+0xff])) + rdata[i:]
    return rdata


def server(pkt):
    try:
        print pkt.summary()
        source_ip = pkt[IP].src
        source_port = pkt[UDP].sport
        transaction_id = pkt[DNS].id
        qd = pkt[DNS].qd
        old_qtype = pkt[DNSQR].qtype
        subdomain = pkt[DNSQR].qname.split(".")[0] #the stuff to be sent back in the TXT field
        domain = ".".join(pkt[DNSQR].qname.split(".")[1:])
        an = DNSRR(rrname=pkt[DNSQR].qname, type="TXT", rclass=1, ttl=1000, rdata=encode_rdata(subdomain)) #response item encoded and placed in the rdata field
        ns = DNSRR(rrname=domain, type="NS", ttl=3600, rdata="ns."+domain)
        response_packet =  IP(dst=source_ip)/UDP(dport=source_port,sport=53)/DNS(aa=1,id=transaction_id, qr=1, rd=pkt[DNS].rd, ra=1, rcode=0, qd=qd, an=an, ancount=1,ns=ns)
        send(response_packet, verbose=True)
    except Exception,ex:
        traceback.print_exc()



def main():
    parser = OptionParser(usage="usage: %prog [options]",version="%prog 1.0")
    parser.add_option("-i", "--interface",type="string",dest="interface",help="network interface to run the DNS responding service")
    (options, args) = parser.parse_args()
    if options.interface is None:
        parser.print_help()
    else:
        sniff(iface=options.interface, filter="udp port 53",prn=server)

if __name__ == '__main__':
    main()
