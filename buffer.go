package netfilter

import (
	"bytes"
	"container/list"
)

type Buffer struct {
	packets *list.List
}

type packet struct {
	Data []byte
}

func NewBuffer() (*Buffer, error) {
	ds := &Buffer{
		packets: list.New(),
	}
	return ds, nil
}

func (ds *Buffer) Write(buf []byte) error {
	dst := make([]byte, len(buf))
	copy(dst, buf)
	return ds.WriteNoCopy(buf)
}

func (ds *Buffer) WriteNoCopy(buf []byte) error {
	packet := &packet{Data: buf}
	ds.packets.PushBack(packet)
	return nil
}

func (ds *Buffer) Next(numBytes int) ([]byte, error) {
	return ds.getData(numBytes, true)
}

func (ds *Buffer) Peek(numBytes int) ([]byte, error) {
	return ds.getData(numBytes, false)
}

func (ds *Buffer) PutBack(buf []byte) error {
	ds.packets.PushFront(&packet{Data: buf})
	return nil
}

func (ds *Buffer) getData(numBytes int, destructive bool) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 512))

	for e := ds.packets.Front(); e != nil; e = e.Next() {
		packet := e.Value.(*packet)
		len := len(packet.Data)
		if len > numBytes {
			buf.Write(packet.Data[:numBytes])
			if destructive {
				packet.Data = packet.Data[numBytes:]
			}
			break
		} else {
			buf.Write(packet.Data)
			if destructive {
				ds.packets.Remove(e)
			}
			numBytes -= len
			if numBytes == 0 {
				break
			}
		}
	}

	return buf.Bytes(), nil
}
