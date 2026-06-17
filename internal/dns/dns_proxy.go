package dns

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/tinfoil-factory/netfoil/internal/lru"
)

type workerTask struct {
	rawRequest     []byte
	responseLength int
	remote         *net.UDPAddr
	tcpConn        *net.TCPConn
}

type workerResult struct {
	remote             *net.UDPAddr
	tcpConn            *net.TCPConn
	question           *Question
	response           *Response
	marshalledResponse []byte
	allowed            bool
	cacheHit           bool
	externalRequest    bool
	pinned             bool
	logEvents          []LogEvent
	filterReasons      []FilterReason
	time               time.Duration
	err                error
}

type worker struct {
	cache          *lru.Cache[timedResponse]
	config         *Config
	dohClient      *DoHClient
	taskQueue      <-chan workerTask
	resultsChannel chan<- workerResult
	policy         *Policy
}

type timedResponse struct {
	response *Response
	time     time.Time
}

func (t *timedResponse) rewriteTTLs() (result *Response, stillValid bool) {
	now := time.Now()

	diff := now.Sub(t.time)
	diffSeconds := uint32(diff.Seconds())

	ok := true

	result = &Response{
		Flags:     t.response.Flags,
		Questions: slices.Clone(t.response.Questions),
		Answers:   slices.Clone(t.response.Answers),
	}

	for _, a := range result.Answers {
		if a.TTL >= diffSeconds {
			a.TTL = a.TTL - diffSeconds
		} else {
			ok = false
			a.TTL = 0
		}
	}

	return result, ok
}

func Server(conn *net.UDPConn, tcpListener *net.TCPListener, config *Config, policy *Policy, caCertPool *x509.CertPool) error {
	dohClient, err := NewDoHClient(config.DoHURL, config.DoHIPs, caCertPool)
	if err != nil {
		return err
	}

	cache := lru.NewCache[timedResponse](4096)

	numWorkers := 20
	channelSize := 50
	tasksChannel := make(chan workerTask, channelSize)
	resultsChannel := make(chan workerResult, channelSize)

	for i := 0; i < numWorkers; i++ {
		worker := &worker{
			cache:          cache,
			config:         config,
			dohClient:      dohClient,
			taskQueue:      tasksChannel,
			resultsChannel: resultsChannel,
			policy:         policy,
		}
		worker.start()
	}

	go func() {
		for result := range resultsChannel {
			if result.err != nil {
				fmt.Printf("error: worker failed to process: %s\n", result.err.Error())
			} else {
				logResult(config, result)
			}

			if result.marshalledResponse != nil {
				if result.tcpConn != nil {
					bf := bytes.Buffer{}
					err := binary.Write(&bf, binary.BigEndian, uint16(len(result.marshalledResponse)))
					if err != nil {
						fmt.Printf("error marshalling TCP length: %v\n", err)
					}

					_, err = result.tcpConn.Write(bf.Bytes())
					if err != nil {
						fmt.Printf("error: failed to write TCP length: %s\n", err.Error())
					}

					_, err = result.tcpConn.Write(result.marshalledResponse)
					if err != nil {
						fmt.Printf("error: failed to write TCP response: %s\n", err.Error())
					}
				} else {
					_, err = conn.WriteToUDP(result.marshalledResponse, result.remote)
					if err != nil {
						fmt.Printf("error: failed to write UDP response: %s\n", err.Error())
					}
				}
			}
		}
	}()

	maxTCPWorkers := 10
	tcpConnQueue := make(chan *net.TCPConn, 50)

	for i := 0; i < maxTCPWorkers; i++ {
		go func() {
			for conn := range tcpConnQueue {
				handleTCPConnection(conn, tasksChannel)
			}
		}()
	}

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				fmt.Printf("error: failed to accept connection: %s\n", err.Error())
			}
			tcpConn := conn.(*net.TCPConn)

			select {
			case tcpConnQueue <- tcpConn:
			default:
				err = conn.Close()
				if err != nil {
					fmt.Printf("error: failed to close connection: %s\n", err.Error())
				}
			}
		}
	}()

	for {
		buf := make([]byte, 1024)
		responseLength, remote, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			fmt.Printf("error: reading from udp: %s\n", err.Error())
			continue
		}

		if responseLength > 0 {
			workerTask := workerTask{
				rawRequest:     buf,
				responseLength: responseLength,
				remote:         remote,
			}

			tasksChannel <- workerTask
		}
	}
}

func handleTCPConnection(conn *net.TCPConn, taskChannel chan workerTask) {
	request := bytes.Buffer{}
	buf := make([]byte, 1024)

	var length *int = nil
	for {
		err := conn.SetReadDeadline(time.Now().Add(timeout))
		if err != nil {
			fmt.Printf("error: failed to set read deadline: %s\n", err.Error())
			err = conn.Close()
			if err != nil {
				fmt.Printf("error: failed to close connection: %s\n", err.Error())
			}
			return
		}

		readLength := len(buf)
		if length != nil && *length < readLength {
			readLength = *length
		}
		responseLength, err := conn.Read(buf[:readLength])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				// ignore
			} else if errors.Is(err, io.EOF) {
				// ignore
			} else if errors.Is(err, os.ErrDeadlineExceeded) {
				// ignore
			} else {
				fmt.Printf("error: reading from TCP: %s\n", err.Error())
			}
			err := conn.Close()
			if err != nil {
				fmt.Printf("error: failed to close TCP connection: %s\n", err.Error())
			}
			return
		}

		request.Write(buf[:responseLength])
		if length == nil && request.Len() < 2 {
			continue
		}

		if length == nil {
			l := int(binary.BigEndian.Uint16(request.Bytes()[0:2]))
			length = &l
		}

		if request.Len() < *length+2 {
			continue
		}

		workerTask := workerTask{
			rawRequest:     request.Bytes()[2:],
			responseLength: *length,
			remote:         nil,
			tcpConn:        conn,
		}

		taskChannel <- workerTask
		length = nil
	}
}

func logResult(config *Config, result workerResult) {
	nameWithoutTrailingDot := strings.TrimSuffix(result.question.Name, ".")
	if result.allowed && config.LogAllowed {
		fmt.Printf("allow|%s|%s\n", nameWithoutTrailingDot, result.question.Type.Name())
	}

	if !result.allowed && config.LogDenied {
		fmt.Printf("deny|%s|%s\n", nameWithoutTrailingDot, result.question.Type.Name())
	}

	if config.LogLevel == slog.LevelDebug {
		fmt.Printf("result\n")
		for _, logEvent := range result.logEvents {
			fmt.Printf("  %s\n", logEvent)
		}

		if len(result.filterReasons) > 0 {
			fmt.Printf("  filter\n")
		}
		for _, reason := range result.filterReasons {
			fmt.Printf("    %s\n", reason)
		}

		fmt.Printf("  cache hit: %t, external request: %t, pinned: %t\n", result.cacheHit, result.externalRequest, result.pinned)
		if result.response != nil {
			fmt.Printf("  response [%s]\n", result.response.Flags.RCODE.Name())
			for _, answer := range result.response.Answers {
				fmt.Printf("    name: %s\n", answer.Name)
				fmt.Printf("      type: %d\n", answer.Type)
				fmt.Printf("      TTL: %d\n", answer.TTL)

				switch answer.Type {
				case RecordTypeA:
					fmt.Printf("      IPv4: %s\n", answer.IPv4.String())
				case RecordTypeCNAME:
					fmt.Printf("      CNAME: %s\n", answer.CNAME)
				case RecordTypeAAAA:
					fmt.Printf("      IPv6: %s\n", answer.IPv6.String())
				case RecordTypeHTTPS:
					name := "."
					if answer.HTTPSRecord.TargetName != "" {
						name = answer.HTTPSRecord.TargetName
					}

					alpn := ""
					if len(answer.HTTPSRecord.ALPN) > 0 {
						alpn = fmt.Sprintf(" alpn=\"%s\"", strings.Join(answer.HTTPSRecord.ALPN, ","))
					}

					ipv4Hints := ""
					if len(answer.HTTPSRecord.IPv4Hint) > 0 {
						sb := strings.Builder{}
						for i, h := range answer.HTTPSRecord.IPv4Hint {
							sb.WriteString(h.String())
							if i < len(answer.HTTPSRecord.IPv4Hint)-1 {
								sb.WriteString(",")
							}
						}

						ipv4Hints = fmt.Sprintf(" ipv4hint=%s", sb.String())
					}

					ipv6Hints := ""
					if len(answer.HTTPSRecord.IPv6Hint) > 0 {
						sb := strings.Builder{}
						for i, h := range answer.HTTPSRecord.IPv6Hint {
							sb.WriteString(h.String())
							if i < len(answer.HTTPSRecord.IPv6Hint)-1 {
								sb.WriteString(",")
							}
						}

						ipv6Hints = fmt.Sprintf(" ipv6hint=%s", sb.String())
					}

					ech := ""
					if answer.HTTPSRecord.ECH != nil {
						sb := strings.Builder{}
						for i, e := range answer.HTTPSRecord.ECH {
							sb.WriteString(e.PublicName)
							if i < len(answer.HTTPSRecord.ECH)-1 {
								sb.WriteString(",")
							}
						}

						ech = fmt.Sprintf(" ech=%s", sb.String())
					}

					fmt.Printf("      HTTPS: %d %s%s%s%s%s\n", answer.HTTPSRecord.Priority, name, alpn, ipv4Hints, ipv6Hints, ech)
				}
			}
		}
		fmt.Printf("  time: %f\n", result.time.Seconds())
	}
}

func (w *worker) start() {
	go func() {
		for task := range w.taskQueue {
			start := time.Now()
			result, err := w.process(&task)
			elapsed := time.Since(start)

			w.resultsChannel <- workerResult{
				remote:             task.remote,
				tcpConn:            task.tcpConn,
				question:           result.question,
				response:           result.response,
				marshalledResponse: result.marshalledResponse,
				allowed:            result.allowed,
				cacheHit:           result.cacheHit,
				externalRequest:    result.externalRequest,
				pinned:             result.pinned,
				logEvents:          result.logEvents,
				filterReasons:      result.filterReasons,
				time:               elapsed,
				err:                err,
			}
		}
	}()
}

type processResponse struct {
	marshalledResponse []byte
	question           *Question
	allowed            bool
	response           *Response
	cacheHit           bool
	externalRequest    bool
	pinned             bool
	logEvents          []LogEvent
	filterReasons      []FilterReason
}

func (p *processResponse) appendLogEvent(logEvent LogEvent) {
	p.logEvents = append(p.logEvents, logEvent)
}

func (p *processResponse) appendFilterReason(filterReason ...FilterReason) {
	p.filterReasons = append(p.filterReasons, filterReason...)
}

func (w *worker) process(workerTask *workerTask) (processResponse, error) {
	result := processResponse{
		question:           nil,
		response:           nil,
		marshalledResponse: nil,
		allowed:            false,
		cacheHit:           false,
		externalRequest:    false,
		pinned:             false,
		logEvents:          make([]LogEvent, 0),
		filterReasons:      make([]FilterReason, 0),
	}

	// FIXME check for too large requests
	responseLength := workerTask.responseLength
	remote := workerTask.remote
	buf := workerTask.rawRequest
	policy := w.policy

	isTCP := false
	if workerTask.tcpConn != nil {
		isTCP = true
		result.appendLogEvent(LogEvent(fmt.Sprintf("query from: %s [TCP]", workerTask.tcpConn.RemoteAddr().String())))
	} else {
		result.appendLogEvent(LogEvent(fmt.Sprintf("query from: %s [UDP]", remote.String())))
	}

	request, err := UnmarshalRequest(buf[:responseLength])
	if err != nil {
		formatError, marshalErr := MarshalEmptyFormatError(buf[:responseLength])
		if marshalErr != nil {
			return result, fmt.Errorf("failed to marshal format error '%w' '%w'", err, marshalErr)
		}

		result.marshalledResponse = formatError
		return result, err
	}

	question := &request.Question
	result.question = question

	result.appendLogEvent(LogEvent(fmt.Sprintf("domain: %s", question.Name)))
	result.appendLogEvent(LogEvent(fmt.Sprintf("type: %d", question.Type)))

	if supportedRequest(request) {
		queryAllowed, filterReason := policy.queryIsAllowed(*question)
		result.appendFilterReason(filterReason...)
		if queryAllowed {
			key := fmt.Sprintf("%s:%d", question.Name, question.Type)

			found := false
			var candidateResponse *Response = nil
			if len(policy.pinA) > 0 && question.Type == RecordTypeA {
				var ip net.IP = nil
				questionName := strings.TrimSuffix(question.Name, ".")
				ip, found = policy.pinA[questionName]
				if found {
					candidateResponse = generateAResponse(question, ip)
					result.pinned = true
				}
			}

			if !found {
				var timedCandidateResponse *timedResponse = nil
				timedCandidateResponse, found = w.cache.Get(key)
				if found {
					result.cacheHit = true
					var stillValid bool
					candidateResponse, stillValid = timedCandidateResponse.rewriteTTLs()

					if !stillValid {
						found = false
					}
				}
			}

			if !found {
				result.externalRequest = true
				candidateResponse, err = w.dohClient.DoH(request)
				if err != nil {
					// FIXME retries / proper response to client
					serverFailure, marshalErr := MarshalServerFailure(request)
					if marshalErr != nil {
						return result, fmt.Errorf("failed to marshal server error '%w' '%w'", err, marshalErr)
					}

					result.marshalledResponse = serverFailure
					return result, fmt.Errorf("server failure %s %s: %w", request.Question.Type.Name(), request.Question.Name, err)
				}

				// TODO responses without at TTL will not be evicted from the cache, so not caching it for now
				// TODO decide what to do with large responses
				if len(candidateResponse.Answers) > 0 && len(candidateResponse.Answers) < 1000 {
					for _, answer := range candidateResponse.Answers {
						if answer.TTL > w.config.MaxTTL {
							answer.TTL = w.config.MaxTTL
						}
					}

					w.cache.Set(key, &timedResponse{
						time:     time.Now(),
						response: candidateResponse,
					})

					candidateResponse = &Response{
						Flags:     candidateResponse.Flags,
						Questions: slices.Clone(candidateResponse.Questions),
						Answers:   slices.Clone(candidateResponse.Answers),
					}
				}
			}

			responseAllowed, filterReason := policy.responseIsAllowed(question.Name, question.Type, candidateResponse)
			result.appendFilterReason(filterReason...)
			if responseAllowed {
				result.allowed = true
				result.response = candidateResponse
			} else {
				result.response = generateBlockResponse()
			}
		} else {
			result.response = generateBlockResponse()
		}
	} else {
		l := fmt.Sprintf("unsupported request type %d", question.Type)
		result.appendLogEvent(LogEvent(l))

		// FIXME what is the best response?
		result.response = generateNotImplementedResponse()
	}

	for i, answer := range result.response.Answers {
		if answer.TTL < w.config.MinTTL {
			answer.TTL = w.config.MinTTL
		}

		if answer.TTL > w.config.MaxTTL {
			answer.TTL = w.config.MaxTTL
		}

		if answer.Type == RecordTypeHTTPS {
			if w.config.RemoveECH {
				answer.HTTPSRecord.ECH = make([]ECHConfig, 0)
			}
		}

		result.response.Answers[i] = answer
	}

	marshalledResponse, err := MarshalResponse(request, result.response, isTCP)
	if err != nil {
		return result, fmt.Errorf("failed to marshal response '%w'", err)
	}

	result.marshalledResponse = marshalledResponse
	return result, nil
}
