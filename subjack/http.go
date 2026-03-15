package subjack

import (
	"crypto/tls"
	"time"

	"github.com/valyala/fasthttp"
)

var httpClient = &fasthttp.Client{
	TLSConfig: &tls.Config{InsecureSkipVerify: true},
}

func httpGet(url string, ssl bool, timeout int) []byte {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	scheme := "http://"
	if ssl {
		scheme = "https://"
	}

	req.SetRequestURI(scheme + url)
	req.Header.Add("Connection", "close")

	httpClient.DoTimeout(req, resp, time.Duration(timeout)*time.Second)

	body := make([]byte, len(resp.Body()))
	copy(body, resp.Body())
	return body
}
