package x365

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// PacketConn carries UDP payloads over the x365 stream. Every datagram is
// framed with a 2-byte big-endian length prefix; the first write also carries
// the x365 handshake header (command=UDP), header first, then length, then
// payload.
type PacketConn struct {
	net.Conn
	access         sync.Mutex
	key            [16]byte
	destination    M.Socksaddr
	requestWritten bool
	responseRead   bool
}

func (c *PacketConn) Read(p []byte) (int, error) {
	if !c.responseRead {
		if err := ReadResponse(c.Conn); err != nil {
			return 0, err
		}
		c.responseRead = true
	}
	var length uint16
	if err := binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	if int(length) > len(p) {
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(c.Conn, p[:length])
}

func (c *PacketConn) writeRequest(payload []byte) error {
	buffer := buf.NewSize(requestLen(c.destination) + 2 + len(payload))
	defer buffer.Release()
	if err := encodeRequest(buffer, c.key, CommandUDP, c.destination); err != nil {
		return err
	}
	if len(payload) > 0 {
		common.Must(
			binary.Write(buffer, binary.BigEndian, uint16(len(payload))),
			common.Error(buffer.Write(payload)),
		)
	}
	return common.Error(c.Conn.Write(buffer.Bytes()))
}

func (c *PacketConn) Write(p []byte) (int, error) {
	if !c.requestWritten {
		c.access.Lock()
		if !c.requestWritten {
			err := c.writeRequest(p)
			c.requestWritten = true
			c.access.Unlock()
			if err != nil {
				return 0, err
			}
			return len(p), nil
		}
		c.access.Unlock()
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(p)))
	if _, err := c.Conn.Write(length[:]); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	c.access.Lock()
	if !c.requestWritten {
		dataLen := buffer.Len()
		binary.BigEndian.PutUint16(buffer.ExtendHeader(2), uint16(dataLen))
		header := buf.With(buffer.ExtendHeader(requestLen(c.destination)))
		err := encodeRequest(header, c.key, CommandUDP, c.destination)
		c.requestWritten = true
		c.access.Unlock()
		if err != nil {
			return err
		}
		return common.Error(c.Conn.Write(buffer.Bytes()))
	}
	c.access.Unlock()
	return common.Error(c.Conn.Write(buffer.Bytes()))
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	if !c.responseRead {
		if err := ReadResponse(c.Conn); err != nil {
			return M.Socksaddr{}, err
		}
		c.responseRead = true
	}
	var length uint16
	if err := binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
		return M.Socksaddr{}, err
	}
	if _, err := buffer.ReadFullFrom(c.Conn, int(length)); err != nil {
		return M.Socksaddr{}, err
	}
	return c.destination, nil
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	if err != nil {
		return 0, nil, err
	}
	if c.destination.IsFqdn() {
		return n, c.destination, nil
	}
	return n, c.destination.UDPAddr(), nil
}

func (c *PacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

func (c *PacketConn) FrontHeadroom() int               { return requestLen(c.destination) + 2 }
func (c *PacketConn) NeedAdditionalReadDeadline() bool { return true }
func (c *PacketConn) Upstream() any                    { return c.Conn }
