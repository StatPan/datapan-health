package main

import (
	"strings"
	"testing"
)

func TestValidSOAPRequestRequiresExactBoundedDocumentLiteralBody(t *testing.T) {
	valid := []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header></soap:Header><soap:Body><op:Read xmlns:op="urn:synthetic:operation"></op:Read></soap:Body></soap:Envelope>`)
	if !validSOAPRequest(valid) {
		t.Fatal("exact synthetic document-literal request was rejected")
	}
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "wrong envelope namespace", body: `<soap:Envelope xmlns:soap="urn:wrong"><soap:Header></soap:Header><soap:Body><op:Read xmlns:op="urn:synthetic:operation"></op:Read></soap:Body></soap:Envelope>`},
		{name: "wrong operation QName", body: `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header></soap:Header><soap:Body><op:Write xmlns:op="urn:synthetic:operation"></op:Write></soap:Body></soap:Envelope>`},
		{name: "extra body element", body: `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header></soap:Header><soap:Body><op:Read xmlns:op="urn:synthetic:operation"></op:Read><op:Write xmlns:op="urn:synthetic:operation"></op:Write></soap:Body></soap:Envelope>`},
		{name: "operation selector attribute", body: `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header></soap:Header><soap:Body><op:Read xmlns:op="urn:synthetic:operation" command="write"></op:Read></soap:Body></soap:Envelope>`},
		{name: "nested operation input", body: `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header></soap:Header><soap:Body><op:Read xmlns:op="urn:synthetic:operation"><op:Input>value</op:Input></op:Read></soap:Body></soap:Envelope>`},
		{name: "trailing element", body: `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header></soap:Header><soap:Body><op:Read xmlns:op="urn:synthetic:operation"></op:Read></soap:Body></soap:Envelope><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"/>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if validSOAPRequest([]byte(test.body)) {
				t.Fatal("synthetic provider accepted an ambiguous or mutating SOAP shape")
			}
		})
	}
	if validSOAPRequest(make([]byte, 16<<10+1)) {
		t.Fatal("synthetic provider accepted a SOAP body above its strict byte ceiling")
	}
	oversizedValidPrefix := append(append([]byte(nil), valid...), []byte(strings.Repeat(" ", 16<<10-len(valid)+1))...)
	body, withinLimit := readBoundedSOAPBody(strings.NewReader(string(oversizedValidPrefix)))
	if withinLimit || validSOAPRequest(body) {
		t.Fatal("synthetic provider accepted valid XML followed by bytes beyond its request limit")
	}
}
