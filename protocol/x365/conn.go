package x365

import (
	"io"
	"net"

	"github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

// x365 wire protocol (reverse-engineered from the 365VPN libgojni.so, package
// me7f1771e/outbound/x365, functions _ao/_ak):
//
// request header (client -> server):
//
//	[0:4]   magic "X365"        (0x58 0x33 0x36 0x35)
//	[4]     version 0x01
//	[5]     command             (1=TCP 2=UDP)
//	[6:22]  uuid 16 raw bytes
//	[22:24] port big-endian
//	[24]    atyp                (0x01 IPv4 / 0x02 domain[len] / 0x03 IPv6)
//	[25:]   address
//
// The port+atyp+addr trailer is exactly vmess.AddressSerializer
// (PortThenAddress), so the header is the VLESS request with the 4-byte magic
// replacing the version byte and the addons dropped.
//
// response header (server -> client): at least 5 bytes, first 4 must equal
// "X365". After the handshake both directions carry the raw relayed stream;
// UDP datagrams are framed with a 2-byte big-endian length prefix.

const (
	Version    byte = 0x01
	CommandTCP byte = 1
	CommandUDP byte = 2
)

var magic = [4]byte{'X', '3', '6', '5'}

// Client holds the parsed UUID key.
type Client struct {
	key [16]byte
}

func NewClient(userId string) (*Client, error) {
	user, err := uuid.FromString(userId)
	if err != nil {
		user = uuid.NewV5(uuid.Nil, userId)
	}
	return &Client{key: user}, nil
}

func (c *Client) DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	remote := NewConn(conn, c.key, CommandTCP, destination)
	return remote, common.Error(remote.Write(nil))
}

func (c *Client) DialEarlyConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	return NewConn(conn, c.key, CommandTCP, destination), nil
}

func (c *Client) DialPacketConn(conn net.Conn, destination M.Socksaddr) (*PacketConn, error) {
	packetConn := &PacketConn{Conn: conn, key: c.key, destination: destination}
	return packetConn, common.Error(packetConn.Write(nil))
}

func (c *Client) DialEarlyPacketConn(conn net.Conn, destination M.Socksaddr) (*PacketConn, error) {
	return &PacketConn{Conn: conn, key: c.key, destination: destination}, nil
}

func requestLen(destination M.Socksaddr) int {
	// magic(4) + version(1) + command(1) + uuid(16) + addr trailer
	return 4 + 1 + 1 + 16 + vmess.AddressSerializer.AddrPortLen(destination)
}

func encodeRequest(buffer *buf.Buffer, key [16]byte, command byte, destination M.Socksaddr) error {
	return common.Error(
		buffer.Write(magic[:]),
		buffer.WriteByte(Version),
		buffer.WriteByte(command),
		buffer.Write(key[:]),
		vmess.AddressSerializer.WriteAddrPort(buffer, destination),
	)
}

// WriteRequest writes the x365 request header followed by an optional payload.
func WriteRequest(writer io.Writer, key [16]byte, command byte, destination M.Socksaddr, payload []byte) error {
	buffer := buf.NewSize(requestLen(destination) + len(payload))
	defer buffer.Release()
	err := encodeRequest(buffer, key, command, destination)
	if err != nil {
		return err
	}
	if len(payload) > 0 {
		common.Must1(buffer.Write(payload))
	}
	return common.Error(writer.Write(buffer.Bytes()))
}

// ReadResponse reads and validates the 5-byte server response header.
func ReadResponse(reader io.Reader) error {
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	if header[0] != magic[0] || header[1] != magic[1] ||
		header[2] != magic[2] || header[3] != magic[3] {
		return E.New("x365: invalid response magic: ", header[:4])
	}
	return nil
}

var _ N.EarlyConn = (*Conn)(nil)

// Conn is the x365 stream connection (TCP).
type Conn struct {
	N.ExtendedConn
	key            [16]byte
	command        byte
	destination    M.Socksaddr
	requestWritten bool
	responseRead   bool
}

func NewConn(conn net.Conn, key [16]byte, command byte, destination M.Socksaddr) *Conn {
	return &Conn{
		ExtendedConn: bufio.NewExtendedConn(conn),
		key:          key,
		command:      command,
		destination:  destination,
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	if !c.responseRead {
		if err := ReadResponse(c.ExtendedConn); err != nil {
			return 0, err
		}
		c.responseRead = true
	}
	return c.ExtendedConn.Read(p)
}

func (c *Conn) ReadBuffer(buffer *buf.Buffer) error {
	if !c.responseRead {
		if err := ReadResponse(c.ExtendedConn); err != nil {
			return err
		}
		c.responseRead = true
	}
	return c.ExtendedConn.ReadBuffer(buffer)
}

func (c *Conn) Write(p []byte) (int, error) {
	if !c.requestWritten {
		if err := WriteRequest(c.ExtendedConn, c.key, c.command, c.destination, p); err != nil {
			return 0, err
		}
		c.requestWritten = true
		return len(p), nil
	}
	return c.ExtendedConn.Write(p)
}

func (c *Conn) WriteBuffer(buffer *buf.Buffer) error {
	if !c.requestWritten {
		header := buf.With(buffer.ExtendHeader(requestLen(c.destination)))
		if err := encodeRequest(header, c.key, c.command, c.destination); err != nil {
			return err
		}
		c.requestWritten = true
	}
	return c.ExtendedConn.WriteBuffer(buffer)
}

func (c *Conn) ReaderReplaceable() bool { return c.responseRead }
func (c *Conn) WriterReplaceable() bool { return c.requestWritten }
func (c *Conn) NeedHandshake() bool     { return !c.requestWritten }

func (c *Conn) FrontHeadroom() int {
	if c.requestWritten {
		return 0
	}
	return requestLen(c.destination)
}

func (c *Conn) NeedAdditionalReadDeadline() bool { return true }
func (c *Conn) Upstream() any                    { return c.ExtendedConn }
