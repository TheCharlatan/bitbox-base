package proxy

import (
	"io"
	"net"
)

// Proxy - Manages a Proxy connection, piping data between local and remote.
type Proxy struct {
	sentBytes            uint64
	receivedBytes        uint64
	laddr, raddr         *net.TCPAddr
	baseConn, clientConn io.ReadWriteCloser
	erred                bool
	errsig               chan bool

	Matcher  func([]byte)
	Replacer func([]byte) []byte

	// Settings
	Nagles    bool
	Log       Logger
	OutputHex bool
}

// New - Create a new Proxy instance. Takes over local connection passed in,
// and closes it when finished.
func New(baseConn *net.TCPConn, laddr, raddr *net.TCPAddr) *Proxy {
	return &Proxy{
		baseConn: lconn,
		laddr:    laddr,
		raddr:    raddr,
		erred:    false,
		errsig:   make(chan bool),
		Log:      NullLogger{},
	}
}

type setNoDelayer interface {
	SetNoDelay(bool) error
}

// Start - open connection to remote and start proxying data.
func (p *Proxy) Start() {
	defer p.baseConn.Close()

	var err error
	//connect to remote
	p.clientConn, err = net.DialTCP("tcp", nil, p.raddr)
	if err != nil {
		p.Log.Warn("Remote connection failed: %s", err)
		return
	}
	defer p.clientConn.Close()

	//nagles?
	if p.Nagles {
		if conn, ok := p.baseConn.(setNoDelayer); ok {
			conn.SetNoDelay(true)
		}
		if conn, ok := p.clientConn.(setNoDelayer); ok {
			conn.SetNoDelay(true)
		}
	}

	//display both ends
	p.Log.Info("Opened %s >>> %s", p.laddr.String(), p.raddr.String())

	//bidirectional copy
	go p.pipe(p.baseConn, p.clientConn)
	go p.pipe(p.clientConn, p.baseConn)

	//wait for close...
	<-p.errsig
	p.Log.Info("Closed (%d bytes sent, %d bytes recieved)", p.sentBytes, p.receivedBytes)
}

func (p *Proxy) err(s string, err error) {
	if p.erred {
		return
	}
	if err != io.EOF {
		p.Log.Warn(s, err)
	}
	p.errsig <- true
	p.erred = true
}

func (p *Proxy) pipe(src, dst io.ReadWriter) {
	islocal := src == p.baseConn

	var dataDirection string
	if islocal {
		dataDirection = ">>> %d bytes sent%s"
	} else {
		dataDirection = "<<< %d bytes recieved%s"
	}

	var byteFormat string
	if p.OutputHex {
		byteFormat = "%x"
	} else {
		byteFormat = "%s"
	}

	//directional copy (64k buffer)
	buff := make([]byte, 0xffff)
	for {
		n, err := src.Read(buff)
		if err != nil {
			p.err("Read failed '%s'\n", err)
			return
		}
		b := buff[:n]

		//execute match
		if p.Matcher != nil {
			p.Matcher(b)
		}

		//execute replace
		if p.Replacer != nil {
			b = p.Replacer(b)
		}

		//show output
		p.Log.Debug(dataDirection, n, "")
		p.Log.Trace(byteFormat, b)

		//write out result
		n, err = dst.Write(b)
		if err != nil {
			p.err("Write failed '%s'\n", err)
			return
		}
		if islocal {
			p.sentBytes += uint64(n)
		} else {
			p.receivedBytes += uint64(n)
		}
	}
}
