package ip

import "fmt"

type IPAddr4 uint32
type IPAddr IPAddr4

func (ip IPAddr4) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24),
		byte(ip>>16), byte(ip>>8),
		byte(ip))
}

func (ip IPAddr) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24),
		byte(ip>>16), byte(ip>>8),
		byte(ip))
}
