# IPV6AUTOPTR #

This simple DNS server on Python that is designed to automatically generate PTR ipv6 records on the fly, dynamically.
This solution is needed primarily for ISP and Hosting Providers that have their own IPv6 subnets and who need automaticly per IPv6  PTR records (reverse DNS records) for customers and services.


> **Warning**
> 
> This mini DNS server can ONLY generate PTR for IPV6. He can't do anything else! This is its main function.


Python 3 is required for the script to work. As well as installing modules via pip3:
```
pip3 install dnslib
pip3 install ipaddress
```
... and etc modules

We also need a patch for the socket server module so that it can support ipv6 family. 
I used this patch: https://bugs.python.org/file35147/issue20215_socketserver.patch
for module in:
`/usr/lib/python3.9/socketserver.py`

I think I will place the patched file directly in the repository for those who encounter difficulties so that it can be replaced with the standard one that comes from OS packages.

### An example of how it works ###
```
nslookup -type=PTR 2a0a:8d80::251
╤хЁтхЁ:  safe.dns.yandex.ru
Address:  2a02:6b8::feed:bad

Non-authoritative answer:
1.5.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.d.8.a.0.a.2.ip6.arpa        name = 2a0a8d80000000000000000000000251.ip6.mydomain.net
```

```
nslookup -type=PTR 2a0a:8d80:0:a000::fefe
╤хЁтхЁ:  safe.dns.yandex.ru
Address:  2a02:6b8::feed:bad

Non-authoritative answer:
e.f.e.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.0.0.8.d.8.a.0.a.2.ip6.arpa        name = 2a0a8d800000a000000000000000fefe.ip6.mydomain.net
```

Each IPv6 for which an attempt is made to obtain a reverse DNS entry will automatically generate a response.

### Configuration ###
In the script itself, you must specify your IPv6 subnets, and your static domain as configuration:
```
# Set up subnets
subnets = ['2a0a:XXXX::/48', '2a0a:XXXX:0:a000::/64']

D = DomainName('ip6.mydomain.net.')
```

### Configuration Custom PTR ###
Custom PTR for customers and for each IPv6 / ip6.arpa

Completed example [/etc/ipv6autoptr.conf](https://github.com/meatlayer/ipv6autoptr/blob/main/ipv6autoptr.conf):

Examples rDNS PTR records for IPv6:
```
1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.d.8.a.0.a.2.ip6.arpa.  IN PTR custom-ptr.ip6.mydomain.net.
1.f.1.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.d.8.a.0.a.2.ip6.arpa.  IN PTR custom-ptr2.ip6.mydomain.net.
```
or IPv6 address = PTR:
```
2a0a:8d80::11 = 1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.d.8.a.0.a.2.ip6.arpa.

2a0a:8d80::f1f1 = 1.f.1.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.d.8.a.0.a.2.ip6.arpa.
```


An example of creating your own records that will not fall under the automatic generated

`/etc/ipv6autoptr.conf` format:
```
1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.d.8.a.0.a.2.ip6.arpa. = custom-ptr.ip6.mydomain.net
1.f.1.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.d.8.a.0.a.2.ip6.arpa. = custom-ptr2.ip6.mydomain.net
```


### How to run and create systemd service in OS Debian/Ubuntu ###
Create file:

`nano /etc/systemd/system/ipv6autoptr.service`

And save as:
```
[Unit]
Description=ipv6autoptr daemon
After=network.target

[Service]
Type=simple
WorkingDirectory=/usr/local/bin
ExecStart=/usr/bin/python3 /usr/local/bin/ipv6autoptr.py --udp --tcp --port 53 --verbose
ExecReload=/bin/kill -s HUP $MAINPID    
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```
If you want to disable logging to /var/log/syslog (journald)  itself for DNS server requests and responses, you can remove the --verbose option. Thus, slightly increasing performance. 

And run:
```
wget https://raw.githubusercontent.com/meatlayer/ipv6autoptr/main/ipv6autoptr.py -O /usr/local/bin/ipv6autoptr.py
chmod 755 /usr/local/bin/ipv6autoptr.py
touch /etc/ipv6autoptr.conf
systemctl daemon-reload
systemctl enable ipv6autoptr.service
systemctl start ipv6autoptr.service
systemctl status ipv6autoptr.service
```



