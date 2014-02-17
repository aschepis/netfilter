package ip

import "fmt"

type Addr4 uint32
type Addr6 uint64

type Addr struct {
	Addr4
	Addr6
}

func NewAddr4(addr Addr4) Addr {
	return Addr{Addr4: addr}
}

func NewAddr6(addr Addr6) Addr {
	return Addr{Addr6: addr}
}

func (ip Addr4) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24),
		byte(ip>>16), byte(ip>>8),
		byte(ip))
}

func (ip Addr6) String() string {
	return "not implemented"
}

func (ip Addr) String() string {
	if ip.Addr4 != 0 {
		return ip.Addr4.String()
	}
	return ip.Addr6.String()
}
