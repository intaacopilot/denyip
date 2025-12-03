package denyIpPlugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type Checker struct {
	denyIPs    []*net.IP
	denyIPsNet []*net.IPNet
}

type Config struct {
	IPDenyList []string `json:"IPDenyList,omitempty"`
}

type denyIP struct {
	next    http.Handler
	checker *Checker
	name    string
}

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil || len(config.IPDenyList) == 0 {
		return nil, errors.New("IPDenyList cannot be empty")
	}

	checker, err := NewChecker(config.IPDenyList)
	if err != nil {
		return nil, err
	}

	return &denyIP{
		checker: checker,
		next:    next,
		name:    name,
	}, nil
}

func (a *denyIP) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqIPAddr := a.GetRemoteIP(req)

	for i := len(reqIPAddr) - 1; i >= 0; i-- {
		isBlocked, err := a.checker.Contains(reqIPAddr[i])
		if err != nil {
			fmt.Printf("Error checking IP: %v\n", err)
		}

		if isBlocked {
			fmt.Printf("denyIP: request denied [%s]\n", reqIPAddr[i])
			rw.WriteHeader(http.StatusForbidden)
			return
		}
	}

	a.next.ServeHTTP(rw, req)
}

func (a *denyIP) GetRemoteIP(req *http.Request) []string {
	var ipList []string

	xff := req.Header.Get("X-Forwarded-For")
	xffs := strings.Split(xff, ",")

	for i := len(xffs) - 1; i >= 0; i-- {
		ip := cleanIP(xffs[i])
		if ip != "" {
			ipList = append(ipList, ip)
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		ipList = append(ipList, cleanIP(req.RemoteAddr))
	} else {
		ipList = append(ipList, cleanIP(host))
	}

	return ipList
}

func cleanIP(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "[]")
	return s
}

func NewChecker(deniedIPs []string) (*Checker, error) {
	if len(deniedIPs) == 0 {
		return nil, errors.New("no denied IPs provided")
	}

	checker := &Checker{}

	for _, ipMask := range deniedIPs {
		ipMask = strings.Trim(ipMask, "[]")

		_, ipNet, err := net.ParseCIDR(ipMask)
		if err == nil {
			checker.denyIPsNet = append(checker.denyIPsNet, ipNet)
			continue
		}

		if ipAddr := net.ParseIP(ipMask); ipAddr != nil {
			checker.denyIPs = append(checker.denyIPs, &ipAddr)
		} else {
			return nil, fmt.Errorf("invalid IP/CIDR format: %s", ipMask)
		}
	}

	return checker, nil
}

func (ip *Checker) Contains(addr string) (bool, error) {
	if addr == "" {
		return false, errors.New("empty IP")
	}

	ipAddr := net.ParseIP(addr)
	if ipAddr == nil {
		return false, fmt.Errorf("invalid IP: %s", addr)
	}

	return ip.ContainsIP(ipAddr), nil
}

func (ip *Checker) ContainsIP(addr net.IP) bool {
	for _, deniedIP := range ip.denyIPs {
		if deniedIP.Equal(addr) {
			return true
		}
	}

	for _, denyNet := range ip.denyIPsNet {
		if denyNet.Contains(addr) {
			return true
		}
	}

	return false
}
