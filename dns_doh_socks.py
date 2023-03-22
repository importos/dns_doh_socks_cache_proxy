import socket
import socks
from dnslib import DNSRecord
import requests
import base64
import threading
import queue
from dnslib import QTYPE
from dnslib.server import RR

import time

# Define the DoH endpoint to use
DOH_URL = 'https://cloudflare-dns.com/dns-query'
socks_host = '192.168.15.77'
socks_port = 1080
proxies = {'http': "socks5://192.168.15.77:1080",'https':"socks5://192.168.15.77:1080"}

dns_cache ={
    1:{
    "time.ir.":DNSRecord(),
    },
    28:{},
}
cache_write_lock = threading.Lock()
cache_request = queue.Queue()
def cache_updater():
    while True:
        req = cache_request.get()

        request_b64 = base64.b64encode(req.pack()).decode()
        response = None
        try:
            print("doh",DOH_URL)
            response_data = requests.get(DOH_URL, params={'dns': request_b64}, timeout=10,proxies=proxies)
            print(response_data,response_data.content)
            response = DNSRecord.parse(response_data.content)
            print(response)
        except Exception as e:
            print("E"*30,1,e)
            pass
        if response == None:
            print('217.218.155.155')
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_socket.sendto(req.pack(), ('217.218.155.155', 53))
                client_socket.settimeout(10)
                response_data, _ = client_socket.recvfrom(8096)
                r1 = DNSRecord.parse(response_data)
                for record in r1.rr:
                    try:
                        print("NNNNN",req.q.qname,record,str(record.rdata))
                        if str(record.rdata).startswith("10."):
                            break
                    except Exception as e :
                        print("E"*30,2, e)
                else:
                    response=r1
            except Exception as e:
                pass
                print("E"*30,3, e)
        if response == None:
            print('1.1.1.1')
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client_socket.sendto(req.pack(), ('1.1.1.1', 53))
                client_socket.settimeout(10)
                response_data, _ = client_socket.recvfrom(8096)
                r1 = DNSRecord.parse(response_data)
                for record in r1.rr:
                    try:
                        print("NNNNN",req.q.qname,record,str(record.rdata))
                        if str(record.rdata).startswith("10."):
                            break
                    except Exception as e :
                        print("E"*30,4, e)
                else:
                    response = r1
            except Exception as e:
                pass
                print("E"*30,5, e)
        if response == None:
            continue
        # print("D"*30,response)
        # print("D"*30,response.rr)
        with cache_write_lock:
            dns_cache[req.q.qtype][req.q.qname]['reply']=response
            dns_cache[req.q.qtype][req.q.qname]['time']=time.time()

def get_from_cache(request):
    # print(request)
    # print(request.rr)
    # print(request.q)
    # print(dir(request.q))
    # print(request.q.qname)
    # # QTYPE[record['type']]
    # print(QTYPE[request.q.qtype])
    # print(dir(request))
    if request.q.qtype not in dns_cache:
        dns_cache[request.q.qtype]={}
    if request.q.qname not in dns_cache[request.q.qtype]:
        dns_cache[request.q.qtype][request.q.qname]={"reply":request.reply(),"time":0}
    cc = dns_cache[request.q.qtype][request.q.qname]
    print(request.q.qname,QTYPE[request.q.qtype],time.time()- cc['time'])
    if (time.time()- cc['time'])>60:
        cache_request.put(request)
        time.sleep(2)
        cc = dns_cache[request.q.qtype][request.q.qname]
    resp=cc['reply']
    # print("*"*30)
    # print(resp)
    # print(resp.rr)
    reply = request.reply()
    for record in resp.rr:
        # print(record)
        # rtype = QTYPE[record.q.qtype]
        # zone = "%s %s %s %s" % (str(record.q.qname),
        #                         record['TTL'],
        #                         rtype,
        #                         str(record['data']))
        # reply.add_answer(*RR.fromZone(zone))
        reply.add_answer(record)
    return reply
def proxy_dns(data, server_socket, client_address):
    # Set up the SOCKS5 proxy if necessary
    request = DNSRecord.parse(data)
    # Encode the DNS request as base64 for DoH

    # # Send the DoH request to the endpoint
    response = get_from_cache(request)

    # Decode the DoH response and extract the DNS message
    server_socket.sendto(response.pack(), client_address)
    return 
    response_b64 = response.content
    print(response_b64)
    response_data = response_b64.decode('base64')
    
    return response_data

def main():
    threading.Thread(target=cache_updater,daemon=True).start()
    threading.Thread(target=cache_updater,daemon=True).start()
    threading.Thread(target=cache_updater,daemon=True).start()
    threading.Thread(target=cache_updater,daemon=True).start()
    # Create a UDP socket to listen for DNS requests
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', 53))
    
    # Set up the SOCKS5 proxy if necessary

    # socks_port = False

    # if socks_host and socks_port:
    #     socks.set_default_proxy(socks.SOCKS5, socks_host, socks_port)
    #     socket.socket = socks.socksocket
    # request_b64 = 'tHIBAAABAAAAAAAABWNsb3VkCG1pa3JvdGlrA2NvbQAAAQAB'
    # print(requests.get(DOH_URL, params={'dns': request_b64}, timeout=30))
    # return 
    while True:
        # Receive a DNS request from a client
        data, client_address = server_socket.recvfrom(4096)

        threading.Thread(target=proxy_dns,args=(data, server_socket, client_address)).start()
        
        # Parse the DNS request using dnspython
        

                

        

if __name__ == '__main__':
    main()
