package main

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type providerRoute struct {
	protocol             string
	responseDelaySeconds int
}

// The fixture records aggregate counters only; it never logs request rows,
// query values, SOAP bodies, or response content.
type counters struct {
	mu         sync.Mutex
	requests   int
	unique     int
	duplicates int
	rest       int
	soap       int
	status2    int
	status5    int
	invalid    int
	routes     map[string]providerRoute
	seen       map[string]struct{}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "pause" {
		select {}
	}
	if len(os.Args) != 7 || os.Args[1] != "--tls-cert" || os.Args[3] != "--tls-key" || os.Args[5] != "--routes" {
		os.Exit(125)
	}
	routesRaw, err := os.ReadFile(os.Args[6])
	routes, validRoutes := decodeRoutes(routesRaw)
	if err != nil || !validRoutes {
		os.Exit(125)
	}
	counts := &counters{routes: routes, seen: make(map[string]struct{}, len(routes))}
	http.HandleFunc("/__metrics", func(w http.ResponseWriter, _ *http.Request) {
		counts.mu.Lock()
		defer counts.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{
			"requests": counts.requests, "unique": counts.unique, "duplicates": counts.duplicates, "allowed_routes": len(counts.routes),
			"rest_get": counts.rest, "soap_post": counts.soap,
			"status_2xx": counts.status2, "status_503": counts.status5, "invalid": counts.invalid,
		})
	})
	http.HandleFunc("/rest/", func(w http.ResponseWriter, r *http.Request) {
		sourceID, operationID, pathOK := operationPath(r.URL.Path, "/rest/")
		valid := r.Method == http.MethodGet && pathOK && r.URL.RawQuery == "" && counts.allows(sourceID, operationID, "REST")
		if !valid {
			counts.reject()
			http.Error(w, "synthetic fixture rejected request", http.StatusBadRequest)
			return
		}
		status := statusForOperation(sourceID, operationID)
		counts.record(sourceID, operationID, false, status)
		waitSyntheticResponse(counts.responseDelay(sourceID, operationID))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			if operationID == "0014af9e0f58c9dd10c0167164e037ddf5f75658431d5ad3ffe531b6bf45d97a" {
				_, _ = io.WriteString(w, `{"synthetic":false}`)
			} else {
				_, _ = io.WriteString(w, `{"synthetic":true}`)
			}
		}
	})
	http.HandleFunc("/soap/", func(w http.ResponseWriter, r *http.Request) {
		body, bodyWithinLimit := readBoundedSOAPBody(r.Body)
		sourceID, operationID, pathOK := operationPath(r.URL.Path, "/soap/")
		valid := r.Method == http.MethodPost && pathOK &&
			r.URL.RawQuery == "" &&
			r.Header.Get("Content-Type") == "text/xml; charset=utf-8" &&
			r.Header.Get("SOAPAction") == "urn:synthetic:Read" && bodyWithinLimit && validSOAPRequest(body) && counts.allows(sourceID, operationID, "SOAP")
		if !valid {
			counts.reject()
			http.Error(w, "synthetic fixture rejected request", http.StatusBadRequest)
			return
		}
		status := statusForOperation(sourceID, operationID)
		counts.record(sourceID, operationID, true, status)
		waitSyntheticResponse(counts.responseDelay(sourceID, operationID))
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(status)
		if status == http.StatusOK {
			if operationID == "30a31059d5847698f696854e772aa1b22569c45c200d4e460c8e5f0c6358578c" {
				_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>synthetic</faultcode></s:Fault></s:Body></s:Envelope>`)
			} else {
				_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><op:ReadResponse xmlns:op="urn:synthetic:operation"/></s:Body></s:Envelope>`)
			}
		}
	})
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		counts.reject()
		http.Error(w, "synthetic fixture rejected request", http.StatusBadRequest)
	})
	server := &http.Server{Addr: ":8080", Handler: http.DefaultServeMux, ReadHeaderTimeout: 5 * time.Second}
	_ = server.ListenAndServeTLS(os.Args[2], os.Args[4])
}

func decodeRoutes(raw []byte) (map[string]providerRoute, bool) {
	if len(raw) == 0 || len(raw) > 4<<20 {
		return nil, false
	}
	var routes []struct {
		SourceID             string `json:"source_id"`
		OperationID          string `json:"operation_id"`
		Protocol             string `json:"protocol"`
		ResponseDelaySeconds int    `json:"response_delay_seconds,omitempty"`
	}
	if json.Unmarshal(raw, &routes) != nil || len(routes) != 12666 {
		return nil, false
	}
	allowed := make(map[string]providerRoute, len(routes))
	for _, route := range routes {
		if route.SourceID == "" || route.OperationID == "" || route.Protocol != "REST" && route.Protocol != "SOAP" || route.ResponseDelaySeconds < 0 || route.ResponseDelaySeconds > 60 {
			return nil, false
		}
		key := route.SourceID + "\x00" + route.OperationID
		if _, duplicate := allowed[key]; duplicate {
			return nil, false
		}
		allowed[key] = providerRoute{protocol: route.Protocol, responseDelaySeconds: route.ResponseDelaySeconds}
	}
	return allowed, true
}

func readBoundedSOAPBody(reader io.Reader) ([]byte, bool) {
	const maximumSOAPBodyBytes = 16 << 10
	body, err := io.ReadAll(io.LimitReader(reader, maximumSOAPBodyBytes+1))
	return body, err == nil && len(body) <= maximumSOAPBodyBytes
}

func (c *counters) allows(sourceID, operationID, protocol string) bool {
	return c != nil && c.routes[sourceID+"\x00"+operationID].protocol == protocol
}

func (c *counters) responseDelay(sourceID, operationID string) time.Duration {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Duration(c.routes[sourceID+"\x00"+operationID].responseDelaySeconds) * time.Second
}

func waitSyntheticResponse(delay time.Duration) {
	if delay > 0 {
		time.Sleep(delay)
	}
}

func (c *counters) reject() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalid++
}

func (c *counters) record(sourceID, operationID string, soap bool, status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests++
	key := sourceID + "\x00" + operationID
	if _, found := c.seen[key]; found {
		c.duplicates++
	} else {
		c.unique++
		c.seen[key] = struct{}{}
	}
	if soap {
		c.soap++
	} else {
		c.rest++
	}
	if status == http.StatusServiceUnavailable {
		c.status5++
	} else {
		c.status2++
	}
}

func operationPath(path, prefix string) (string, string, bool) {
	if !strings.HasPrefix(path, prefix) || strings.ContainsAny(path, "?#") {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	for _, r := range parts[0] {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' {
			return "", "", false
		}
	}
	for _, r := range parts[1] {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
			return "", "", false
		}
	}
	return parts[0], parts[1], true
}

func statusForOperation(_ string, operationID string) int {
	if operationID == "0004cea4696c10954bc7db92690058078e6dd3a7ffddd92c61e7f4061e83ef0a" || operationID == "28256cae93511a322963841fb8e03ac4c0273a45f85fd0371ac0f9f7b7bfb8b2" {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

func validSOAPRequest(body []byte) bool {
	if len(body) == 0 || len(body) > 16<<10 {
		return false
	}
	decoder := xml.NewDecoder(strings.NewReader(string(body)))
	decoder.Strict = true
	const envelopeNS = "http://schemas.xmlsoap.org/soap/envelope/"
	const operationNS = "urn:synthetic:operation"
	nextElement := func() (xml.StartElement, error) {
		for {
			token, err := decoder.Token()
			if err != nil {
				return xml.StartElement{}, err
			}
			switch value := token.(type) {
			case xml.CharData:
				if strings.TrimSpace(string(value)) != "" {
					return xml.StartElement{}, errors.New("unexpected text")
				}
			case xml.StartElement:
				return value, nil
			case xml.Comment, xml.ProcInst, xml.Directive:
				return xml.StartElement{}, errors.New("unexpected XML token")
			}
		}
	}
	consumeEnd := func(want xml.Name) bool {
		for {
			token, err := decoder.Token()
			if err != nil {
				return false
			}
			switch value := token.(type) {
			case xml.CharData:
				if strings.TrimSpace(string(value)) != "" {
					return false
				}
			case xml.EndElement:
				return value.Name == want
			case xml.StartElement, xml.Comment, xml.ProcInst, xml.Directive:
				return false
			}
		}
	}
	envelope, err := nextElement()
	if err != nil || envelope.Name != (xml.Name{Space: envelopeNS, Local: "Envelope"}) || !exactNamespaceAttribute(envelope.Attr, "s", envelopeNS) && !exactNamespaceAttribute(envelope.Attr, "soap", envelopeNS) {
		return false
	}
	header, err := nextElement()
	if err != nil || header.Name != (xml.Name{Space: envelopeNS, Local: "Header"}) || len(header.Attr) != 0 || !consumeEnd(header.Name) {
		return false
	}
	bodyElement, err := nextElement()
	if err != nil || bodyElement.Name != (xml.Name{Space: envelopeNS, Local: "Body"}) || len(bodyElement.Attr) != 0 {
		return false
	}
	operation, err := nextElement()
	if err != nil || operation.Name != (xml.Name{Space: operationNS, Local: "Read"}) || !exactNamespaceAttribute(operation.Attr, "op", operationNS) {
		return false
	}
	if !consumeEnd(operation.Name) || !consumeEnd(bodyElement.Name) || !consumeEnd(envelope.Name) {
		return false
	}
	_, err = decoder.Token()
	return errors.Is(err, io.EOF)
}

func exactNamespaceAttribute(attributes []xml.Attr, prefix, namespace string) bool {
	if len(attributes) != 1 {
		return false
	}
	attribute := attributes[0]
	return attribute.Name.Space == "xmlns" && attribute.Name.Local == prefix && attribute.Value == namespace
}
