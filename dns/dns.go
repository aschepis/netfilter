package dns

var Types = map[uint16]string{
	1:   "A",
	2:   "NS",
	3:   "MD",
	4:   "MF",
	5:   "CNAME",
	6:   "SOA",
	7:   "MB",
	8:   "MG",
	9:   "MR",
	10:  "NULL",
	11:  "WKS",
	12:  "PTR",
	13:  "HINFO",
	14:  "MINFO",
	15:  "MX",
	16:  "TXT",
	252: "AXFR",
	253: "MAILB",
	254: "MAILA",
	255: "*",
}

var Classes = map[uint16]string{
	1:   "IN",
	2:   "CS",
	3:   "CH",
	4:   "HS",
	255: "*",
}

type CName Domain
