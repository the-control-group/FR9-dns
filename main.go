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
		HandleFailed(w, req, "refused to answer an empty question")
		return
	}
	log.Debugf("recieved request: %s", req.Question[0].Name)
	for name, domain := range c.Forwarders {
		if strings.HasSuffix(req.Question[0].Name, domain.Pattern) {
			forward(name, domain, w, req)
			return
		}
	}
	log.Infof("Unable to find a forwader for %s, sending to recursors", req.Question[0].Name)
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
				log.Errorf("%s failed to respond: %v", recursor, err)
			}
			return
		}
		log.Infof("%s recurse to %s failed: %s", req.Question[0].Name, recursor, err.Error())
	}

	// If all resolvers fail, return a SERVFAIL message
	log.Errorf("all recursors failed request %s from client %s (%s)", q, w.RemoteAddr().String(), w.RemoteAddr().Network())
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

func HandleFailed(w dns.ResponseWriter, req *dns.Msg, msg string) {
	log.Errorf("failed to resolve %+v from server %s (%s): %s", req, w.RemoteAddr().String(), w.RemoteAddr().Network(), msg)
	dns.HandleFailed(w, req)
}

func forward(name string, f settings.Forwarder, w dns.ResponseWriter, req *dns.Msg) {
	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}
	if isTransfer(req) {
		if transport != "tcp" {
			HandleFailed(w, req, "transfer requested on non TCP request")
			return
		}
		t := new(dns.Transfer)
		c, err := t.In(req, f.Address)
		if err != nil {
			HandleFailed(w, req, err.Error())
			return
		}
		if err = t.Out(w, req, c); err != nil {
			HandleFailed(w, req, err.Error())
			return
		}
		return
	}
	c := &dns.Client{Net: transport}
	resp, _, err := c.Exchange(req, f.Address)
	if err != nil {
		HandleFailed(w, req, err.Error())
		return
	}
	if len(resp.Answer) < 1 {
		log.Errorf("recieved 0 results for %s", req.Question[0].Name)
	}
	if f.Limit > 0 && len(resp.Answer) > f.Limit {
		resp.Answer = resp.Answer[:f.Limit]
	}
	w.WriteMsg(resp)
}
