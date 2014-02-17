package reverse_cache

import (
	"time"

	"github.com/aschepis/netfilter/ip"
	"github.com/golang/groupcache/lru"
)

type DomainList struct {
	Domains []string
}

type ReverseCache struct {
	lru *lru.Cache
}

func New(maxEntries int) *ReverseCache {
	return &ReverseCache{
		lru: lru.New(maxEntries),
	}
}

func (c *ReverseCache) Add(ip ip.Addr, domains *DomainList, ttl int) {
	if ttl > 0 {
		c.lru.Add(ip, domains)
		go c.expire(ip, ttl)
	}
}

func (c *ReverseCache) Get(ip ip.Addr) (value *DomainList, ok bool) {
	iface, ok := c.lru.Get(ip)
	if ok {
		value = iface.(*DomainList)
	}

	return
}

func (c *ReverseCache) Remove(ip ip.Addr) {
	c.lru.Remove(ip)
}

func (c *ReverseCache) RemoveOldest() {
	c.lru.RemoveOldest()
}

func (c *ReverseCache) expire(ip ip.Addr, ttl int) {
	select {
	case <-time.After(time.Duration(ttl) * time.Second):
		c.lru.Remove(ip)
	}
}
