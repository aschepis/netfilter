package reverse_cache

import (
	"testing"
	"time"

	"github.com/aschepis/netfilter/ip"
)

func TestReverseCache(t *testing.T) {
	c := New(16)

	ip := ip.NewAddr4(1)
	expected := []string{"www.google.com", "gmail.com"}
	c.Add(ip, &DomainList{Domains: expected}, 100)

	dlist, ok := c.Get(ip)
	if !ok {
		t.Errorf("failed to lookup domains")
	}

	if dlist.Domains[0] != "www.google.com" || dlist.Domains[1] != "gmail.com" {
		t.Errorf("failed to lookup domains. expected: %v, got: %v", expected, dlist)
	}
}

func TestNoCache(t *testing.T) {
	c := New(16)

	ip := ip.NewAddr4(1)
	c.Add(ip, &DomainList{Domains: []string{"www.google.com"}}, 0)

	_, ok := c.Get(ip)
	if ok {
		t.Errorf("successfully looked up domain that should not have been cached")
	}
}

func TestExpire(t *testing.T) {
	c := New(16)

	ip := ip.NewAddr4(1)
	c.Add(ip, &DomainList{Domains: []string{"www.google.com"}}, 1)

	time.Sleep(2 * time.Second)
	_, ok := c.Get(ip)
	if ok {
		t.Errorf("successfully looked up domain that should have expired")
	}
}
