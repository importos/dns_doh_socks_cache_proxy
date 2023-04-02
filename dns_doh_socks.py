import socket
import socks
from dnslib import DNSRecord
import requests
import base64
import threading
import queue
from dnslib import QTYPE
from dnslib.server import RR
import logging

logging.basicConfig(level=logging.DEBUG,filename="/var/log/dns.log",)

import time

# Define the DoH endpoint to use
proxies = {'http': "socks5://192.168.15.77:1080",'https':"socks5://192.168.15.77:1080"}
CACHE_TIME = 60*60
TEMP_CACHE_TIME = CACHE_TIME - 50
dns_cache ={
    1:{
    "time.ir.":DNSRecord(),
    },
    28:{},
}
cache_write_lock = threading.Lock()
cache_request = queue.Queue(10000)
class base_resolver():
    def __init__(self,host) -> None:
        self._host = host
    def resolve(self,request_pack):
        raise Exception("Impliment")
    def __repr__(self) -> str:
        return "%s by %s"%(str(self.__class__),self._host)
    


class doh_resolver(base_resolver):
    def resolve(self,request_pack):
        request_b64 = base64.b64encode(request_pack).decode()
        response_data = requests.get(self._host, params={'dns': request_b64}, timeout=60,proxies=proxies)
        response = DNSRecord.parse(response_data.content)
        return response
    


class dns_resolver(base_resolver):
    def resolve(self,request_pack):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.sendto(request_pack, (self._host, 53))
        client_socket.settimeout(5)
        response_data, _ = client_socket.recvfrom(8096)
        r1 = DNSRecord.parse(response_data)
        for record in r1.rr:
            if str(record.rdata).startswith("10."):
                raise Exception("Bad Dns %s"%(self._host))
        else:
            return r1
RESOLVERS = [
    # dns_resolver("194.36.174.161"), #asia tech
    # dns_resolver("91.99.101.12"), #parsonline
    # dns_resolver("5.202.100.101"), #pishgaman
    dns_resolver("5.200.200.200"), # itc
    dns_resolver("1.1.1.1"), 
    dns_resolver("217.218.155.155"), #itc
    dns_resolver("8.8.8.8"),
    dns_resolver("194.225.62.80"), #daneshgah tehran
    doh_resolver("https://cloudflare-dns.com/dns-query"),
]
def resolver(request):

    response = None
    request_pack = request.pack()
    for resolver_object in RESOLVERS:
        t1= time.time()
        try:
            response = resolver_object.resolve(request_pack)
            if response != None:
                return response
        except Exception as e:
            pass
            logging.exception(" %s %s",resolver_object,request)     
        logging.debug("="*30+" %s %s",time.time()-t1,resolver_object)
def cache_updater():
    while True:
        req = cache_request.get()
        try:
            response = resolver(req)
            logging.debug("resolver %s" , response)
            if response == None:
                try:
                    cache_request.put(req,timeout=1)
                except:
                    logging.exception("put timeout")
                continue
            with cache_write_lock:
                dns_cache[req.q.qtype][req.q.qname]['reply']=response
                dns_cache[req.q.qtype][req.q.qname]['time']=time.time()
        except Exception as e:
            logging.exception("")
            response = None
            continue

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
        with cache_write_lock:
            dns_cache[request.q.qtype]={}
    if request.q.qname not in dns_cache[request.q.qtype]:
        try:
            request_pack = request.pack()
            responce = RESOLVERS[0].resolve(request_pack)
            if responce == None :
                responce = request.reply()
        except:
            responce = request.reply()
        with cache_write_lock:
            dns_cache[request.q.qtype][request.q.qname]={"reply":responce,"time":0}
    cc = dns_cache[request.q.qtype][request.q.qname]
    logging.debug("%s %s %s",request.q.qname,QTYPE[request.q.qtype],CACHE_TIME-(time.time()- cc['time']))
    if (time.time()- cc['time'])> CACHE_TIME:
        try:
            cache_request.put(request,timeout=1)
            with cache_write_lock:
                dns_cache[request.q.qtype][request.q.qname]['time']=time.time()-TEMP_CACHE_TIME
        except:
            pass
        # time.sleep(2)
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
    for i in range(30):
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
