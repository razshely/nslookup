import sys

i, o, e = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *

sys.stdin, sys.stdout, sys.stderr = i, o, e

FILEADDRESS = r"C:\Networks\work\address.txt"
RNDPORT = 55538
TIMEOT = 2
#open(PHOTO_PATH, 'rb').read(response)

def main():
    # First case when we choose nslookup in type A and if exits CNANE it print it
    adfile = open(FILEADDRESS, 'w')
    if len(sys.argv) == 2:
        cnameFlag = False
        ns_requst = sys.argv[1]
        packeta = IP(dst="8.8.8.8") / UDP(sport=RNDPORT) / DNS(qdcount=1) / DNSQR(qname=str(ns_requst))
        packet_request = sr1(packeta, verbose=0, timeout=TIMEOT)
        # check timeout
        if packet_request is None:
            print("Sorry be faster next time...")
        else:
            # check if reply is error
            if packet_request[DNS].rcode == 3:
                print("*** UnKnown can't find " + ns_requst + ": Non-existent domain")
            else:
                # check if CNAME exit
                for i in range(packet_request[DNS].ancount):
                    if packet_request[DNSRR][i].type == 5:
                        cnameFlag = True
                        break
                # CNAME exit case
                if cnameFlag:
                    firstAddress = ''
                    aliases = []
                    for i in range(packet_request[DNS].ancount):
                        if packet_request[DNSRR][i].type == 1:
                            firstAddress = packet_request[DNSRR][i].rrname.decode()
                            print('\n' + "Name:   " + packet_request[DNSRR][i].rrname.decode()[:-1])
                            print("Address:   " + packet_request[DNSRR][i].rdata)
                            adfile.write(packet_request[DNSRR][i].rdata + '\n')
                        else:
                            aliases.append(packet_request[DNSRR][i].rdata.decode())
                    print("Aliases:   " + ns_requst)
                    for i in range(len(aliases)):
                        if aliases[i] != firstAddress:
                            print('         ' + aliases[i][:-1])
                # CNAME not exit
                else:
                    print('\n' + "Name:   " + ns_requst)
                    for i in range(packet_request[DNS].ancount):
                        if i == 0:
                            print("Address:   " + packet_request[DNSRR][i].rdata)
                        else:
                            print("        " + packet_request[DNSRR][i].rdata)
                            adfile.write(packet_request[DNSRR][i].rdata + '\n')

    # if we sent -type=PTR and the second arg is valid
    elif len(sys.argv) == 3 and sys.argv[1] == "-type=PTR" and len(str(sys.argv[2]).split('.')) == 4:
        numbersIP = str(sys.argv[2]).split('.')
        reversIP = numbersIP[3] + '.' + numbersIP[2] + '.' + numbersIP[1] + '.' + numbersIP[0]
        packeta = IP(dst="8.8.8.8") / UDP(sport=RNDPORT) / DNS(qdcount=1) / DNSQR(qname=reversIP + ".in-addr.arpa.",
                                                                                  qtype="PTR")
        packet_request = sr1(packeta, verbose=0, timeout=TIMEOT)
        # check timeout
        if packet_request is None:
            print("Sorry be faster next time...")
        else:
            if packet_request[DNS].rcode == 3:
                print("*** UnKnown can't find " + reversIP + ".in-addr.arpa.: Non-existent domain")
            else:
                print(
                    packet_request[DNSRR].rrname.decode()[:-1] + "    name = " + packet_request[DNSRR].rdata.decode()[
                                                                                 :-1])
                adfile.write( packet_request[DNSRR].rdata.decode()[:-1] + '\n')
    # ERORR
    else:
        print("You enter incorrect parameters...")


if __name__ == '__main__':
    main()
