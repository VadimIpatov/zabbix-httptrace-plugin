package httptrace

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/montanaflynn/stats"

	"github.com/vadimipatov/gcircularqueue"

	"zabbix.com/pkg/conf"
	"zabbix.com/pkg/plugin"
)

const pluginName = "HttpTrace"

type Options struct {
	Interval int `conf:"optional,range=1:3600,default=1"`
	Timeout  int `conf:"optional,range=1:30,default=1"`
}

type Plugin struct {
	plugin.Base
	urls map[string]*urlUnit
	sync.Mutex
	options Options
}

type timeSample struct {
	DnsLookup         float64 `json:"dnsLookup"`
	Connect           float64 `json:"connect"`
	TlsHandshake      float64 `json:"tlsHandshake"`
	FirstResponseByte float64 `json:"firstResponseByte"`
	Rtt               float64 `json:"rtt"`
}

type stat struct {
	Median timeSample `json:"median"`
	P75    timeSample `json:"p75"`
	P95    timeSample `json:"p95"`
	P99    timeSample `json:"p99"`
}

type urlUnit struct {
	url      string
	history  *gcircularqueue.CircularQueue
	accessed time.Time // last access time
	modified time.Time // data collect time
}

type metric = string

var impl Plugin

const (
	maxInactivityPeriod = 15 * time.Minute
	maxHistory          = 5*60 + 1
	minStatRange        = 3
)

const (
	metricDnsLookup         = "DnsLookup"
	metricConnect           = "Connect"
	metricTlsHandshake      = "TlsHandshake"
	metricFirstResponseByte = "FirstResponseByte"
	metricRtt               = "Rtt"
)

const (
	keyHttpTrace      = "httptrace"
	keyHttpTraceStats = "httptrace.stats"
	keyHttpDataRate   = "httptrace.rate"
)

const (
	p50 = 50
	p75 = 75
	p95 = 95
	p99 = 99
)

func (p *Plugin) measureTime(url string) (timeSample, error) {
	var (
		sample                            timeSample
		start, connect, dns, tlsHandshake time.Time
	)

	req, _ := http.NewRequest("GET", url, nil)

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dns = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			sample.DnsLookup = float64(time.Since(dns) / time.Millisecond)
		},

		ConnectStart: func(_, _ string) {
			connect = time.Now()
		},
		ConnectDone: func(net, addr string, err error) {
			if err != nil {
				p.Errf("unable to connect to host %s: %s", addr, err.Error())
			}
			sample.Connect = float64(time.Since(connect) / time.Millisecond)
		},

		GotFirstResponseByte: func() {
			sample.FirstResponseByte = float64(time.Since(start) / time.Millisecond)
		},

		TLSHandshakeStart: func() {
			tlsHandshake = time.Now()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			sample.TlsHandshake = float64(time.Since(tlsHandshake) / time.Millisecond)
		},
	}

	ctx, cancel := context.WithTimeout(req.Context(), time.Duration(p.options.Timeout)*time.Second)
	defer cancel()
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))

	start = time.Now()
	if _, err := http.DefaultTransport.RoundTrip(req); err != nil {
		return timeSample{}, err
	}
	sample.Rtt = float64(time.Since(start) / time.Millisecond)

	return sample, nil
}

func prepareData(history []interface{}) (res map[metric][]float64) {
	var sample timeSample
	var dnsLookup, connect, tlsHandshake, firstResponseByte, rtt [maxHistory]float64

	res = make(map[metric][]float64)

	var i int
	for i = 0; i < len(history)-1; i++ {
		if history[i] == nil {
			break
		}
		sample = history[i].(timeSample)
		dnsLookup[i] = sample.DnsLookup
		connect[i] = sample.Connect
		tlsHandshake[i] = sample.TlsHandshake
		firstResponseByte[i] = sample.FirstResponseByte
		rtt[i] = sample.Rtt
	}

	res = map[metric][]float64{
		metricDnsLookup:         dnsLookup[:i],
		metricConnect:           connect[:i],
		metricTlsHandshake:      tlsHandshake[:i],
		metricFirstResponseByte: firstResponseByte[:i],
		metricRtt:               rtt[:i],
	}

	return
}

func parseURL(uri string) (string, error) {
	if !strings.Contains(uri, "://") && !strings.HasPrefix(uri, "//") {
		uri = "//" + uri
	}

	url, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("could not parse url %q: %v", uri, err)
	}

	if url.Scheme == "" {
		url.Scheme = "http"
		if !strings.HasSuffix(url.Host, ":80") {
			url.Scheme += "s"
		}
	}
	return url.String(), nil
}

func percentile(input stats.Float64Data, percent float64) (res float64) {
	res, _ = stats.Percentile(input, percent)
	return
}

func (p *Plugin) Export(key string, params []string, ctx plugin.ContextProvider) (result interface{}, err error) {
	if len(params) != 1 {
		return nil, errors.New("Wrong parameters.")
	}

	url, err := parseURL(params[0])
	if err != nil {
		return nil, err
	}

	switch key {
	case keyHttpTrace:
		res, err := p.measureTime(url)
		if err != nil {
			p.Errf(err.Error())
			return nil, err
		}

		jsonRes, err := json.Marshal(res)
		if err != nil {
			p.Errf(err.Error())
			return nil, errors.New("Cannot marshal JSON.")
		}

		return string(jsonRes), nil

	case keyHttpTraceStats:
		if _, ok := p.urls[url]; !ok {
			p.urls[url] = &urlUnit{
				url:     url,
				history: gcircularqueue.NewCircularQueue(maxHistory),
			}
		}
		p.Lock()
		defer p.Unlock()
		p.urls[url].accessed = time.Now()
		if p.urls[url].history.Len() < minStatRange {
			// no data gathered yet
			return
		}

		data := prepareData(p.urls[url].history.Elements())

		jsonRes, err := json.Marshal(stat{
			Median: timeSample{
				DnsLookup:         percentile(data[metricDnsLookup], p50),
				Connect:           percentile(data[metricConnect], p50),
				TlsHandshake:      percentile(data[metricTlsHandshake], p50),
				FirstResponseByte: percentile(data[metricFirstResponseByte], p50),
				Rtt:               percentile(data[metricRtt], p50),
			},
			P75: timeSample{
				DnsLookup:         percentile(data[metricDnsLookup], p75),
				Connect:           percentile(data[metricConnect], p75),
				TlsHandshake:      percentile(data[metricTlsHandshake], p75),
				FirstResponseByte: percentile(data[metricFirstResponseByte], p75),
				Rtt:               percentile(data[metricRtt], p75),
			},
			P95: timeSample{
				DnsLookup:         percentile(data[metricDnsLookup], p95),
				Connect:           percentile(data[metricConnect], p95),
				TlsHandshake:      percentile(data[metricTlsHandshake], p95),
				FirstResponseByte: percentile(data[metricFirstResponseByte], p95),
				Rtt:               percentile(data[metricRtt], p95),
			},
			P99: timeSample{
				DnsLookup:         percentile(data[metricDnsLookup], p99),
				Connect:           percentile(data[metricConnect], p99),
				TlsHandshake:      percentile(data[metricTlsHandshake], p99),
				FirstResponseByte: percentile(data[metricFirstResponseByte], p99),
				Rtt:               percentile(data[metricRtt], p99),
			},
		})
		if err != nil {
			p.Errf(err.Error())
			return nil, errors.New("Cannot marshal JSON.")
		}

		value := string(jsonRes)
		return plugin.Result{
			Value: &value,
			Ts:    p.urls[url].modified,
		}, nil

	case keyHttpDataRate:
		// it's a challenge for you :)
		// try to implement a metric for measure data transfer rate.
		return nil, errors.New("Not implemented yet.")

	default:
		return nil, plugin.UnsupportedMetricError
	}
}

func (p *Plugin) Collect() (err error) {
	now := time.Now()
	p.Lock()
	for key, url := range p.urls {
		if now.Sub(url.accessed) > maxInactivityPeriod {
			p.Debugf("removed expired url %s", url.url)
			delete(p.urls, key)
			continue
		}
		res, err := p.measureTime(url.url)
		if err != nil {
			p.Errf(err.Error())
			continue
		}
		url.history.Push(res)
		if url.history.IsFull() {
			_ = url.history.Shift()
		}
		url.modified = now
	}
	p.Unlock()

	return
}

func (p *Plugin) Period() int {
	return p.options.Interval
}

func (p *Plugin) Start() {
	p.urls = make(map[string]*urlUnit)
}

func (p *Plugin) Stop() {
	p.urls = nil
}

func (p *Plugin) Configure(global *plugin.GlobalOptions, private interface{}) {
	if err := conf.Unmarshal(private, &p.options); err != nil {
		p.Warningf("cannot unmarshal configuration options: %s", err)
	}

	// set default timeout
	if p.options.Timeout == 0 {
		p.options.Timeout = global.Timeout
	}
}

func (p *Plugin) Validate(private interface{}) (err error) {
	return
}

func init() {
	impl.options.Interval = 1 // interval for the first poll. will be overwritten when configuration is done
	impl.urls = make(map[string]*urlUnit)
	plugin.RegisterMetrics(&impl, pluginName,
		keyHttpTrace, "Measure time of http request.",
		keyHttpTraceStats, "Calculate statistics for requested URLs.",
		keyHttpDataRate, "Measure data transfer rate.")
}
