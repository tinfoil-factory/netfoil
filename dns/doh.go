package dns

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/context"
)

// https://datatracker.ietf.org/doc/html/rfc8484

type DoHClient struct {
	httpClient *http.Client
	dohURL     string
}

func (c *DoHClient) DoH(request *Request) (*Response, error) {
	marshalledRequest, err := MarshalRequest(request)
	if err != nil {
		return nil, err
	}

	r := base64.URLEncoding.EncodeToString(marshalledRequest)
	r = strings.TrimRight(r, "=")

	req, err := http.NewRequest("GET", c.dohURL+"?dns="+r, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DNS query failed: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	response, err := UnmarshalResponse(body)
	if err != nil {
		return nil, err
	}

	return response, nil

}

func NewDoHClient(dohURL string, DoHIP string, caCertPool *x509.CertPool) (*DoHClient, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("DoH URL must use HTTPS: %s", u)
	}

	if u.Hostname() == "" {
		return nil, fmt.Errorf("DoH URL must have a hostname: %s", u)
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	tlsConfig := &tls.Config{}

	if caCertPool != nil {
		tlsConfig.RootCAs = caCertPool
	}

	httpTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == u.Hostname()+":443" {
				addr = DoHIP + ":443"
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: tlsConfig,
	}

	client := http.Client{
		Transport: httpTransport,
	}

	return &DoHClient{
		dohURL:     dohURL,
		httpClient: &client,
	}, nil
}
