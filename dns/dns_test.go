package dns

import "testing"

var packetData []byte = []byte{
	0xcb, 0x0d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, //  ........    16
	0x00, 0x00, 0x00, 0x00, 0x07, 0x73, 0x75, 0x70, //  .....sup    24

	0x70, 0x6f, 0x72, 0x74, 0x11, 0x73, 0x70, 0x72, //  port.spr    32
	0x69, 0x6e, 0x67, 0x62, 0x6f, 0x61, 0x72, 0x64, //  ingboard    40
	0x72, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x03, 0x63, //  retail.c    48
	0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, //  om.....     56
}

var packetData3 []byte = []byte{
	0x1e, 0xc3, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, //  ........    16
	0x00, 0x00, 0x00, 0x00, 0x03, 0x75, 0x73, 0x65, //  .....use    24

	0x07, 0x74, 0x79, 0x70, 0x65, 0x6b, 0x69, 0x74, //  .typekit    32
	0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x01, 0x00, //  .net....    40
	0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, //  ........    48
	0x00, 0x00, 0x05, 0x00, 0x17, 0x03, 0x77, 0x61, //  ......wa    56

	0x63, 0x04, 0x30, 0x46, 0x38, 0x38, 0x0b, 0x65, //  c.0F88.e    64
	0x64, 0x67, 0x65, 0x63, 0x61, 0x73, 0x74, 0x63, //  dgecastc    72
	0x64, 0x6e, 0xc0, 0x18, 0xc0, 0x2d, 0x00, 0x05, //  dn...-..    80
	0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x10, //  ........    88

	0x03, 0x67, 0x70, 0x31, 0x03, 0x77, 0x61, 0x63, //  .gp1.wac    96
	0x05, 0x76, 0x32, 0x63, 0x64, 0x6e, 0xc0, 0x18, //  .v2cdn..   104
	0xc0, 0x50, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, //  .P......   112
	0x00, 0x05, 0x00, 0x04, 0x48, 0x15, 0x5b, 0x13, //  ....H.[.   120

}

func TestDNSRequest(t *testing.T) {
	packet, _ := NewPacket(packetData)
	if packet.Header.ID != 51981 {
		t.Errorf("Incorrect header id. Expected 51981, got: %v", packet.Header.ID)
	}
	if packet.Header.PacketType() != 0 {
		t.Errorf("Incorrect packet type. expected 0, got: %v", packet.Header.PacketType())
	}
	if packet.Header.QDCount != 1 {
		t.Errorf("Incorrect QDCount. expected 1, got: %v", packet.Header.QDCount)
	}
	if packet.Header.ANCount != 0 {
		t.Errorf("Incorrect ANCount. expected 0, got: %v", packet.Header.ANCount)
	}
	if packet.Header.NSCount != 0 {
		t.Errorf("Incorrect NSCount. expected 0, got: %v", packet.Header.NSCount)
	}
	if packet.Header.ARCount != 0 {
		t.Errorf("Incorrect ARCount. expected 0, got: %v", packet.Header.ARCount)
	}
	if len(packet.Questions) != 1 {
		t.Errorf("Incorrect length of questions array. expected 1, got: %v", len(packet.Questions))
	}
	expectedDescription := "support.springboardretail.com IN A"
	if expectedDescription != packet.Questions[0].String() {
		t.Errorf("Incorrect request description. expected \"%v\", got: %v", expectedDescription,
			packet.Questions[0].String())
	}
}

func TestDNSResponse(t *testing.T) {
	packet, _ := NewPacket(packetData3)
	if packet.Header.ID != 7875 {
		t.Errorf("Incorrect header id. Expected 7875, got: %v", packet.Header.ID)
	}
	if packet.Header.PacketType() != 1 {
		t.Errorf("Incorrect packet type. expected 1, got: %v", packet.Header.PacketType())
	}
	if packet.Header.QDCount != 1 {
		t.Errorf("Incorrect QDCount. expected 1, got: %v", packet.Header.QDCount)
	}
	if packet.Header.ANCount != 3 {
		t.Errorf("Incorrect ANCount. expected 3, got: %v", packet.Header.ANCount)
	}
	if packet.Header.NSCount != 0 {
		t.Errorf("Incorrect NSCount. expected 0, got: %v", packet.Header.NSCount)
	}
	if packet.Header.ARCount != 0 {
		t.Errorf("Incorrect ARCount. expected 0, got: %v", packet.Header.ARCount)
	}

	if len(packet.Answers) != 3 {
		t.Errorf("Incorrect length of answers array. expected 3, got: %v", len(packet.Questions))
	}

	expectedDescriptions := []string{
		"use.typekit.net IN CNAME: wac.0F88.edgecastcdn.net",
		"wac.0F88.edgecastcdn.net IN CNAME: gp1.wac.v2cdn.net",
		"gp1.wac.v2cdn.net IN A: 72.21.91.19",
	}

	for i, desc := range expectedDescriptions {
		if desc != packet.Answers[i].String() {
			t.Errorf("Incorrect answer description. expected \"%v\", got: %v", desc,
				packet.Answers[i].String())
		}
	}
}

func BenchmarkNewPacket(b *testing.B) {
	for i := 0; i < 1000; i++ {
		NewPacket(packetData3)
	}
}
