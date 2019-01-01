package subjack

import (
	"crypto/tls"
	"github.com/valyala/fasthttp"
	"time"
)

func get(url string, ssl bool, timeout int) (body []byte) {
	req := fasthttp.AcquireRequest()
	req.SetRequestURI(site(url, ssl))
	req.Header.Add("Connection", "close")
	resp := fasthttp.AcquireResponse()

	client := &fasthttp.Client{TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	client.DoTimeout(req, resp, time.Duration(timeout)*time.Second)

	return resp.Body()
}

func https(url string, ssl bool, timeout int) (body []byte) {
	newUrl := "https://" + url
	body = get(newUrl, ssl, timeout)

	return body
}

func site(url string, ssl bool) (site string) {
	site = "http://" + url
	if ssl {
		site = "https://" + url
	}

	return site
}
