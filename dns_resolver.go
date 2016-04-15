// Package dns_resolver is a simple dns resolver
// based on miekg/dns
package dns_resolver

import (
	"errors"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var dnsTimeout = 2 * time.Second

// DnsResolver represents a dns resolver
type DnsResolver struct {
	Servers         []string
	RetryTimes      int
	ReuseConnection bool
	r               *rand.Rand
	conns           map[string]*dns.Conn
}

// New initializes DnsResolver.
func New(servers []string) *DnsResolver {
	for i := range servers {
		servers[i] += ":53"
	}

	resolver := &DnsResolver{
		Servers:    servers,
		RetryTimes: len(servers) * 2,
	}
	resolver.r = rand.New(rand.NewSource(time.Now().UnixNano()))
	resolver.conns = make(map[string]*dns.Conn)

	return resolver
}

// NewFromResolvConf initializes DnsResolver from resolv.conf like file.
func NewFromResolvConf(path string) (*DnsResolver, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &DnsResolver{}, errors.New("no such file or directory: " + path)
	}
	config, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return nil, err
	}
	return New(config.Servers), nil
}

func (r *DnsResolver) getConnection(address string) (*dns.Conn, error) {
	conn, ok := r.conns[address]
	if !ok {
		c, err := dns.DialTimeout("udp", address, dnsTimeout)
		if err != nil {
			return nil, err
		}
		r.conns[address] = c
		conn = c
	}
	return conn, nil
}

// LookupHost returns IP addresses of provied host.
// In case of timeout retries query RetryTimes times.
func (r *DnsResolver) LookupHost(host string) (result []net.IP, err error) {
	in, err := r.performWithRetry(host, r.RetryTimes, dns.TypeA)

	if err != nil {
		return nil, err
	}
	for _, record := range in.Answer {
		if t, ok := record.(*dns.A); ok {
			result = append(result, t.A)
		}
	}
	return result, err
}

// LookupHostFull returns IP addresses and CNAMES of provied host.
// In case of timeout retries query RetryTimes times.
func (r *DnsResolver) LookupHostFull(host string) (result []net.IP, resultCname []string, err error) {
	in, err := r.performWithRetry(host, r.RetryTimes, dns.TypeA)
	if err != nil {
		return nil, nil, err
	}

	for _, record := range in.Answer {
		switch r := record.(type) {
		case *dns.A:
			result = append(result, r.A)
		case *dns.CNAME:
			resultCname = append(resultCname, r.Target)
		}
	}
	return result, resultCname, err
}

func (r *DnsResolver) performWithRetry(host string, triesLeft int, reqType uint16) (result *dns.Msg, err error) {
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{dns.Fqdn(host), reqType, dns.ClassINET}

	server := r.Servers[r.r.Intn(len(r.Servers))]

	var in *dns.Msg

	if r.ReuseConnection {
		connection, err := r.getConnection(server)
		if err != nil {
			return nil, err
		}
		connection.WriteMsg(m1)
		in, err = connection.ReadMsg()
	} else {
		in, err = dns.Exchange(m1, server)
	}

	if err != nil {
		if strings.HasSuffix(err.Error(), "i/o timeout") && triesLeft > 0 {
			triesLeft--
			return r.performWithRetry(host, triesLeft, reqType)
		}
		return result, err
	}

	if in != nil && in.Rcode != dns.RcodeSuccess {
		return result, errors.New(dns.RcodeToString[in.Rcode])
	}

	return in, nil
}
