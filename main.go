package main

import (
	"net"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/the-control-group/FR9-dns/settings"
)

var (
	c settings.Settings
)

func main() {
	// Load settings
	var err error
	c, err = settings.Load()
	if err != nil {
		log.Fatal(err)
	}

	// Set up logging
	switch strings.ToLower(c.LogLevel) {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	}

	udpServer := &dns.Server{Addr: c.Listen, Net: "udp"}
	tcpServer := &dns.Server{Addr: c.Listen, Net: "tcp"}
	dns.HandleFunc(".", route)
	go func() {
		log.Fatal(udpServer.ListenAndServe())
	}()
	log.Fatal(tcpServer.ListenAndServe())
}

func route(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}
	req.RecursionAvailable = true
	for name, domain := range c.Forwarders {
		if strings.HasSuffix(req.Question[0].Name, domain.Pattern) {
			forward(name, domain, w, req)
		}
	}
	recurse(w, req)
}

func recurse(w dns.ResponseWriter, req *dns.Msg) {
	q := req.Question[0]
	network := "udp"

	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		network = "tcp"
	}

	d := &dns.Client{Net: network}
	var r *dns.Msg
	var err error
	for _, recursor := range c.Recursors {
		r, _, err = d.Exchange(req, recursor)
		if err == nil {
			if err := w.WriteMsg(r); err != nil {
				log.Warn("failed to respond: %v", err)
			}
			return
		}
		log.Info("recurse failed: %v", err)
	}

	// If all resolvers fail, return a SERVFAIL message
	log.Errorf("all resolvers failed for %v from client %s (%s)", q, w.RemoteAddr().String(), w.RemoteAddr().Network())
	m := &dns.Msg{}
	m.SetReply(req)
	m.RecursionAvailable = true
	m.SetRcode(req, dns.RcodeServerFailure)
	w.WriteMsg(m)
}

func isTransfer(req *dns.Msg) bool {
	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeIXFR, dns.TypeAXFR:
			return true
		}
	}
	return false
}

func forward(name string, f settings.Forwarder, w dns.ResponseWriter, req *dns.Msg) {
	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}
	if isTransfer(req) {
		if transport != "tcp" {
			dns.HandleFailed(w, req)
			return
		}
		t := new(dns.Transfer)
		c, err := t.In(req, f.Address)
		if err != nil {
			dns.HandleFailed(w, req)
			return
		}
		if err = t.Out(w, req, c); err != nil {
			dns.HandleFailed(w, req)
			return
		}
		return
	}
	c := &dns.Client{Net: transport}
	resp, _, err := c.Exchange(req, f.Address)
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}
	if f.Limit > 0 && len(resp.Answer) > f.Limit {
		resp.Answer = resp.Answer[:f.Limit]
	}
	w.WriteMsg(resp)
}
