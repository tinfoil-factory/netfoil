package dns

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/context"
)

// https://datatracker.ietf.org/doc/html/rfc8484

const (
	timeout                   = 20 * time.Second
	tcpServerReadWriteTimeout = 10 * time.Second
	keepAliveProbeTime        = 30 * time.Second
	idleSessionTimeout        = 90 * time.Second
	maxResponseHeaderBytes    = 2000
)

type DoHClient struct {
	httpClient *http.Client
	dohURL     *url.URL
}

func (c *DoHClient) DoH(request *Request) (*Response, error) {
	marshalledRequest, err := MarshalRequest(0, request.Flags, request.Question)
	if err != nil {
		return nil, err
	}

	r := base64.URLEncoding.EncodeToString(marshalledRequest)
	r = strings.TrimRight(r, "=")

	u := *c.dohURL
	queryParams := u.Query()
	queryParams.Set("dns", r)
	u.RawQuery = queryParams.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("DNS query failed: %s", resp.Status)
	} else if resp.Header.Get("Content-Type") != "application/dns-message" {
		err = fmt.Errorf("wrong content type in DNS response")
	}

	if err != nil {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("DNS query failed: %s, close failed %w", resp.Status, closeErr)
		}

		return nil, err
	}

	limitedBody := io.LimitReader(resp.Body, UINT16_MAX)
	body, err := io.ReadAll(limitedBody)
	closeErr := resp.Body.Close()
	if err != nil || closeErr != nil {
		if closeErr == nil {
			return nil, err
		} else if err == nil {
			return nil, closeErr
		}

		return nil, fmt.Errorf("failed to read and close %w %w", err, closeErr)
	}

	response, err := UnmarshalResponse(body)
	if err != nil {
		return nil, err
	}

	return response, nil

}

func NewDoHClient(dohURL *url.URL, DoHIP []netip.Addr, caCertPool *x509.CertPool) (*DoHClient, error) {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: keepAliveProbeTime,
	}

	tlsConfig := &tls.Config{}

	if caCertPool != nil {
		tlsConfig.RootCAs = caCertPool
	}

	httpTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == dohURL.Hostname()+":443" {
				randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(DoHIP))))
				if err != nil {
					return nil, err
				}

				ip := DoHIP[randomIndex.Int64()]
				addr = net.JoinHostPort(ip.String(), "443")
			} else {
				return nil, fmt.Errorf("unexpected address '%s'", addr)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:        tlsConfig,
		IdleConnTimeout:        idleSessionTimeout,
		ResponseHeaderTimeout:  timeout,
		TLSHandshakeTimeout:    timeout,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
	}

	client := http.Client{
		Transport: httpTransport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &DoHClient{
		dohURL:     dohURL,
		httpClient: &client,
	}, nil
}
