package main

import (
	"fmt"
	"io"

	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"github.com/aschepis/netfilter"
	replay "github.com/aschepis/pcapreplay"
)

type replayPacketSource struct {
	reader *replay.PacketReader
}

func newPacketSource(path string) (*replayPacketSource, error) {
	reader, err := replay.NewPacketReader(path)
	if err != nil {
		return nil, err
	}

	return &replayPacketSource{
		reader: reader,
	}, nil
}

func (s *replayPacketSource) Close() {
	s.reader.Close()
}

// ReadPacketData returns the next packet available from this data source.
// It returns:
//  data:  The bytes of an individual packet.
//  ci:  Metadata about the capture
//  err:  An error encountered while reading packet data.  If err != nil,
//    then data/ci will be ignored.
func (s *replayPacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	_, bytes, err := s.reader.NextPacket()
	if bytes == nil && err == nil {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	return bytes, gopacket.CaptureInfo{}, err
}

func main() {
	fmt.Println("pcap version: ", replay.PcapVersion())
	path := "./test_traffic.pcapng"

	// packetSorceror(path)
	filter(path)
}

func filter(path string) {
	stream, _ := replay.NewPacketReader(path)
	filter := netfilter.NewFilter2()
	defer filter.Stop()

	go filter.Run()
	for {
		_, bytes, err := stream.NextPacket()
		fmt.Println(len(bytes))
		if err != nil {
			fmt.Println(err)
			break
		} else if bytes == nil {
			fmt.Println("bytes is nil")
			break
		}

		filter.In <- bytes
	}
}

func packetSorceror(path string) {
	src, err := newPacketSource(path)
	if err != nil {
		panic(err)
	}
	defer src.Close()

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &payload)
	var source gopacket.PacketDataSource = src
	decodedLayers := make([]gopacket.LayerType, 0, 10)

	for {
		data, _, err := source.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("Error reading packet data: ", err)
			continue
		}

		fmt.Println("Decoding packet")
		err = parser.DecodeLayers(data, &decodedLayers)
		for _, typ := range decodedLayers {
			fmt.Println("  Successfully decoded layer type", typ)
			switch typ {
			case layers.LayerTypeEthernet:
				fmt.Println("    Eth ", eth.SrcMAC, eth.DstMAC)
			case layers.LayerTypeIPv4:
				fmt.Println("    IP4 ", ip4.SrcIP, ip4.DstIP)
			case layers.LayerTypeIPv6:
				fmt.Println("    IP6 ", ip6.SrcIP, ip6.DstIP)
			case layers.LayerTypeTCP:
				fmt.Println("    TCP ", tcp.SrcPort, tcp.DstPort)
				if (tcp.SrcPort == 80 || tcp.DstPort == 80) && len(tcp.LayerPayload()) > 0 {
					fmt.Println("=====")
					fmt.Println(string(tcp.LayerPayload()[:]))
				}
			case layers.LayerTypeUDP:
				fmt.Println("    UDP ", udp.SrcPort, udp.DstPort)
			}
		}

		if err != nil {
			fmt.Println("  Error encountered:", err)
		}
	}
}
