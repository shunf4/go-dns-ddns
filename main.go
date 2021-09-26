package main

import (
	"encoding/base32"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var registry = map[string]string{}

var setKeyPattern *regexp.Regexp
var getKeyPattern *regexp.Regexp

var nsRecords []string
var soaRecord string
var token string

const (
	DDNSQueryTypeInvalid = iota
	DDNSQueryTypeSet     = iota
	DDNSQueryTypeGet     = iota
)

func appendRR(m *dns.Msg, name string, dnsType string, value string) error {
	rr, err := dns.NewRR(fmt.Sprintf("%s %s %s", name, dnsType, value))
	if err == nil {
		m.Answer = append(m.Answer, rr)
		return nil
	} else {
		return err
	}
}

func truncateString(str string, num int) string {
	truncated := str
	if len(str) > num {
		truncated = str[0:num]
	}
	return truncated
}

func parseQuery(m *dns.Msg) {
	willInclNS := false
	willInclSOA := false
	for _, q := range m.Question {
		log.Printf("Query for %s %v\n", q.Name, q.Qtype)
		if q.Qtype != dns.TypeA &&
			q.Qtype != dns.TypeAAAA &&
			q.Qtype != dns.TypeANY &&
			q.Qtype != dns.TypeCNAME &&
			q.Qtype != dns.TypeNS &&
			q.Qtype != dns.TypeSOA &&
			q.Qtype != dns.TypeTXT {
			continue
		}

		if q.Qtype == dns.TypeNS || q.Qtype == dns.TypeANY {
			willInclNS = true
		}
		if q.Qtype == dns.TypeSOA || q.Qtype == dns.TypeANY {
			willInclSOA = true
		}
		willInclA := q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY
		willInclAAAA := q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY
		willInclCNAME := q.Qtype == dns.TypeCNAME || q.Qtype == dns.TypeANY
		willInclTXT := q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY

		key := ""
		val := ""
		queryToken := ""
		ddnsQueryType := DDNSQueryTypeInvalid

		if setKeyPattern.MatchString(q.Name) {
			matchResult := setKeyPattern.FindStringSubmatch(q.Name)
			if matchResult == nil || len(matchResult) != 4 {
				continue
			}
			val = matchResult[1]
			key = matchResult[2]
			queryToken = matchResult[3]
			ddnsQueryType = DDNSQueryTypeSet
		} else if getKeyPattern.MatchString(q.Name) {
			matchResult := getKeyPattern.FindStringSubmatch(q.Name)
			if matchResult == nil || len(matchResult) != 3 {
				continue
			}
			key = matchResult[1]
			queryToken = matchResult[2]
			ddnsQueryType = DDNSQueryTypeGet
		}
		if key == "" {
			continue
		}
		if queryToken != token {
			continue
		}

		switch ddnsQueryType {
		case DDNSQueryTypeSet:
			registry[key] = val
			log.Printf("Registry: set %s to %s\n", key, val)

			if willInclA {
				appendRR(m, q.Name, "A", "1.1.1.1")
			}
			if willInclAAAA {
				appendRR(m, q.Name, "AAAA", "2606:4700:4700::1111")
			}
			if willInclCNAME {
				appendRR(m, q.Name, "CNAME", truncateString("ok.home.arpa.", 255))
			}
			if willInclTXT {
				appendRR(m, q.Name, "TXT", truncateString("OK", 255))
			}

		case DDNSQueryTypeGet:
			val, ok := registry[key]
			var aVal, aaaaVal string
			if !ok {
				log.Printf("Registry: no entry for %s\n", key)
				continue
			}
			log.Printf("Registry: %s is %s\n", key, val)
			if isIPv4(val) {
				aVal = val
			} else {
				aVal = "1.1.1.1"
			}
			aaaaVal = "2606:4700:4700::1111"

			if willInclA {
				appendRR(m, q.Name, "A", aVal)
			}
			if willInclAAAA {
				appendRR(m, q.Name, "AAAA", aaaaVal)
			}
			if willInclCNAME {
				appendRR(m, q.Name, "CNAME", truncateString(base32.HexEncoding.EncodeToString([]byte(val))+".home.arpa.", 255))
			}
			if willInclTXT {
				appendRR(m, q.Name, "TXT", truncateString(val, 255))
			}
		}
	}
	if willInclNS {
		for _, ns := range nsRecords {
			rr, err := dns.NewRR(ns)
			if err == nil {
				m.Answer = append(m.Answer, rr)
			} else {
				log.Println(err.Error())
			}
		}
	}
	if willInclSOA {
		rr, err := dns.NewRR(soaRecord)
		if err == nil {
			m.Answer = append(m.Answer, rr)
		} else {
			log.Println(err.Error())
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	w.WriteMsg(m)
}

func isIPv4(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	}
	for i := 0; i < len(ip); i++ {
		switch ip[i] {
		case '.':
			return true
		case ':':
			return false
		}
	}
	return false
}

func main() {
	baseDomain := strings.TrimSpace(os.Getenv("GDD_BASE_DOMAIN"))
	listenPortStr := strings.TrimSpace(os.Getenv("GDD_LISTEN_PORT"))
	nsRecordsStr := strings.TrimSpace(os.Getenv("GDD_NS_RECORDS"))
	soaRecord = strings.TrimSpace(os.Getenv("GDD_SOA_RECORD"))
	token = strings.TrimSpace(os.Getenv("GDD_TOKEN"))
	if baseDomain == "" {
		baseDomain = "example.com"
	}
	if baseDomain[0] == '.' {
		baseDomain = baseDomain[1:]
	}
	if baseDomain[len(baseDomain)-1] != '.' {
		baseDomain = baseDomain + "."
	}
	if listenPortStr == "" {
		listenPortStr = "5353"
	}
	if nsRecordsStr == "" {
		nsRecordsStr = fmt.Sprintf("%s 30 IN NS dns1.%s;%s 30 IN NS dns2.%s", baseDomain, baseDomain, baseDomain, baseDomain)
	}
	nsRecords = strings.Split(nsRecordsStr, ";")
	if soaRecord == "" {
		soaRecord = fmt.Sprintf("%s 3600 IN SOA dns1.%s webadmin.%s 2020000001 300 300 2592000 7200", baseDomain, baseDomain, baseDomain)
	}
	if token == "" {
		token = "mytoken"
	}
	listenPort, err := strconv.Atoi(listenPortStr)
	if err != nil {
		log.Fatalf("Failed to parse listen port: %s\n ", err.Error())
	}
	// "\d+" part is nonce
	setKeyPattern = regexp.MustCompile(`^(?P<val>.+)\.(?P<key>[^\.]+)\.\d+\.(?P<token>\w+)\.ddns-set\.` + strings.ReplaceAll(baseDomain, `.`, `\.`) + `$`)
	getKeyPattern = regexp.MustCompile(`^(?P<key>[^\.]+)\.\d+\.(?P<token>\w+)\.ddns-get\.` + strings.ReplaceAll(baseDomain, `.`, `\.`) + `$`)

	// attach request handler func
	dns.HandleFunc(baseDomain, handleDnsRequest)

	// start server
	server := &dns.Server{Addr: ":" + strconv.Itoa(listenPort), Net: "udp"}
	log.Printf("Starting at :%d on %s\n", listenPort, baseDomain)
	err = server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
