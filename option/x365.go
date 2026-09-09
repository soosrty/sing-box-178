package option

type X365OutboundOptions struct {
	DialerOptions
	ServerOptions
	UUID    string      `json:"uuid"`
	Network NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	Transport *V2RayTransportOptions `json:"transport,omitempty"`
}
