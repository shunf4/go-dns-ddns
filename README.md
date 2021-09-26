## Golang DNS Server that implements a key-value storage

To use it:

```
GDD_LISTEN_PORT=53 GDD_BASE_DOMAIN=ddns.example.com GDD_TOKEN=mytoken ./go-dns-ddns
```

```
dig +short A 127.0.0.1.key1.`date -u +%Y%m%d%H%M%S`.mytoken.ddns-set.ddns.example.com
dig +short A key1.`date -u +%Y%m%d%H%M%S`.mytoken.ddns-get.ddns.example.com

dig +short A abcdef.key1.`date -u +%Y%m%d%H%M%S`.mytoken.ddns-set.ddns.example.com
dig +short TXT key1.`date -u +%Y%m%d%H%M%S`.mytoken.ddns-set.ddns.example.com
```
