package netfilter
import (
	replay "github.com/aschepis/pcapreplay"
	"testing"
)

func TestHandler(t *testing.T) {
	reader, err := replay.NewPacketReader("test/test_traffic.pcapng")
	if err != nil {
		t.Errorf("Failed to create packet reader. err=%v", err)
	}

	handler := NewHandler()
	for {
		hdr, packet, err := reader.NextPacket()
		if err != nil {
			panic(err)
		} else if hdr == nil {
			break //eof
		}
		handler.Write(packet)
		handler.Process()
	}
}
