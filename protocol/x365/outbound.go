package x365

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.X365OutboundOptions](registry, C.TypeX365, NewOutbound)
}

var (
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

// Outbound dials the 365VPN x365 protocol: a VLESS-shaped handshake with an
// "X365" magic prefix, layered over (REALITY/)uTLS and optionally an XHTTP
// stream-one transport.
type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	client     *Client
	serverAddr M.Socksaddr
	tlsConfig  tls.Config
	tlsDialer  tls.Dialer
	transport  adapter.V2RayClientTransport
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.X365OutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeX365, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		serverAddr: options.ServerOptions.Build(),
	}
	if options.TLS != nil {
		outbound.tlsConfig, err = tls.NewClientWithOptions(tls.ClientOptions{
			Context:        ctx,
			Logger:         logger,
			ServerAddress:  options.Server,
			Options:        common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "",
		})
		if err != nil {
			return nil, err
		}
		outbound.tlsDialer = tls.NewDialer(outboundDialer, outbound.tlsConfig)
	}
	if options.Transport != nil {
		outbound.transport, err = v2ray.NewClientTransport(ctx, outboundDialer, outbound.serverAddr, common.PtrValueOrDefault(options.Transport), outbound.tlsConfig)
		if err != nil {
			return nil, E.Cause(err, "create client transport: ", options.Transport.Type)
		}
	}
	outbound.client, err = NewClient(options.UUID)
	if err != nil {
		return nil, err
	}
	return outbound, nil
}

func (h *Outbound) dialServer(ctx context.Context) (net.Conn, error) {
	if h.transport != nil {
		return h.transport.DialContext(ctx)
	}
	if h.tlsDialer != nil {
		return h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	}
	return h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	conn, err := h.dialServer(ctx)
	if err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialEarlyConn(conn, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return h.client.DialEarlyPacketConn(conn, destination)
	default:
		common.Close(conn)
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	conn, err := h.dialServer(ctx)
	if err != nil {
		return nil, err
	}
	return h.client.DialEarlyPacketConn(conn, destination)
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.transport != nil {
		h.transport.Close()
	}
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	if transportKeeper, isTransportKeeper := h.transport.(adapter.IdleConnectionKeeper); isTransportKeeper {
		transportKeeper.SetKeepIdleConnections(keep)
	}
}

func (h *Outbound) CloseIdleConnections() {
	if transportKeeper, isTransportKeeper := h.transport.(adapter.IdleConnectionKeeper); isTransportKeeper {
		transportKeeper.CloseIdleConnections()
	}
}

func (h *Outbound) Close() error {
	return common.Close(h.transport)
}
