package dns

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/tinfoil-factory/netfoil/lru"
)

type workerTask struct {
	rawRequest     []byte
	responseLength int
	remote         *net.UDPAddr
}

type workerResult struct {
	question        *Question
	allowed         bool
	remote          *net.UDPAddr
	rawResponse     []byte
	response        *Response
	logEvents       []LogEvent
	filterReasons   []FilterReason
	err             error
	time            time.Duration
	cacheHit        bool
	externalRequest bool
	pinned          bool
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

func Server(conn *net.UDPConn, config *Config, policy *Policy, caCertPool *x509.CertPool) error {
	dohClient, err := NewDoHClient(config.DoHURL, config.DoHIPs[0], caCertPool)
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
				continue
			}

			if result.allowed && config.LogAllowed {
				fmt.Printf("allow|%s|%s\n", result.question.Name, result.question.Type.Name())
			}

			if !result.allowed && config.LogDenied {
				fmt.Printf("deny|%s|%s\n", result.question.Name, result.question.Type.Name())
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
					fmt.Printf("  response [%d]\n", result.response.Flags.RCODE)
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

			_, err = conn.WriteToUDP(result.rawResponse, result.remote)
			if err != nil {
				fmt.Printf("error: failed to write response: %s\n", err.Error())
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

func (w *worker) start() {
	go func() {
		for task := range w.taskQueue {
			start := time.Now()
			rawResponse, question, allowed, response, logEvents, filterReasons, cacheHit, externalRequest, pinned, err := w.process(&task)
			elapsed := time.Since(start)

			w.resultsChannel <- workerResult{
				remote:          task.remote,
				question:        question,
				allowed:         allowed,
				rawResponse:     rawResponse,
				response:        response,
				logEvents:       logEvents,
				filterReasons:   filterReasons,
				err:             err,
				time:            elapsed,
				cacheHit:        cacheHit,
				externalRequest: externalRequest,
				pinned:          pinned,
			}
		}
	}()
}

func (w *worker) process(workerTask *workerTask) ([]byte, *Question, bool, *Response, []LogEvent, []FilterReason, bool, bool, bool, error) {
	var question *Question = nil
	allowed := false
	logEvents := make([]LogEvent, 0)
	filterReasons := make([]FilterReason, 0)
	var response *Response = nil
	cacheHit := false
	externalRequest := false
	pinned := false

	// FIXME check for too large requests
	responseLength := workerTask.responseLength
	remote := workerTask.remote
	buf := workerTask.rawRequest
	policy := w.policy

	logEvents = append(logEvents, LogEvent(fmt.Sprintf("query from: %s", remote.String())))

	request, err := UnmarshalRequest(buf[:responseLength])
	if err != nil {
		return nil, question, allowed, response, logEvents, filterReasons, cacheHit, externalRequest, pinned, err
	}

	question = &request.Question

	logEvents = append(logEvents, LogEvent(fmt.Sprintf("domain: %s", question.Name)))
	logEvents = append(logEvents, LogEvent(fmt.Sprintf("type: %d", question.Type)))

	if supportedRequest(request) {
		queryAllowed, filterReason := policy.queryIsAllowed(*question)
		filterReasons = append(filterReasons, filterReason...)
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
					pinned = true
				}
			}

			if !found {
				var timedCandidateResponse *timedResponse = nil
				timedCandidateResponse, found = w.cache.Get(key)
				if found {
					cacheHit = true
					var stillValid bool
					candidateResponse, stillValid = timedCandidateResponse.rewriteTTLs()

					if !stillValid {
						found = false
					}
				}
			}

			if !found {
				externalRequest = true
				candidateResponse, err = w.dohClient.DoH(request)
				if err != nil {
					// FIXME retries / proper response to client
					return nil, question, allowed, response, logEvents, filterReasons, cacheHit, externalRequest, pinned, err
				}

				// TODO responses without at TTL will not be evicted from the cache, so not caching it for now
				if len(candidateResponse.Answers) > 0 {
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
			filterReasons = append(filterReasons, filterReason...)
			if responseAllowed {
				allowed = true
				response = candidateResponse
			} else {
				response = generateBlockResponse(*question)
			}
		} else {
			response = generateBlockResponse(*question)
		}
	} else {
		l := fmt.Sprintf("unsupported request type %d", question.Type)
		logEvents = append(logEvents, LogEvent(l))

		// FIXME what is the best response?
		response = generateNotImplementedResponse()
	}

	for i, answer := range response.Answers {
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

		response.Answers[i] = answer
	}

	d, err := MarshalResponse(request, response)
	if err != nil {
		return nil, question, allowed, response, logEvents, filterReasons, cacheHit, externalRequest, pinned, err
	}

	return d, question, allowed, response, logEvents, filterReasons, cacheHit, externalRequest, pinned, nil
}
