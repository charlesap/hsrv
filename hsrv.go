package main

import (
    "crypto/tls"
    "net/http"
    "time"
    "strings"
    "fmt"
    "os"
    "log"
)

const (
	ApacheFormatPattern = "%s - - [%s] \"%s %d %d\" %f\n"
)

type ApacheLogRecord struct {
	http.ResponseWriter

	ip                    string
	time                  time.Time
	method, uri, protocol string
	status                int
	responseBytes         int64
	elapsedTime           time.Duration
}

func (r *ApacheLogRecord) Log(out *os.File) {
	timeFormatted := r.time.Format("02/Jan/2006 03:04:05")
	requestLine := fmt.Sprintf("%s %s %s", r.method, r.uri, r.protocol)
	fmt.Fprintf(out, ApacheFormatPattern, r.ip, timeFormatted, requestLine, r.status, r.responseBytes,
		r.elapsedTime.Seconds())
}

func (r *ApacheLogRecord) Write(p []byte) (int, error) {
	written, err := r.ResponseWriter.Write(p)
	r.responseBytes += int64(written)
	return written, err
}

func (r *ApacheLogRecord) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}



func myHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	if colon := strings.LastIndex(clientIP, ":"); colon != -1 {
		clientIP = clientIP[:colon]
	}

	record := &ApacheLogRecord{
		ResponseWriter: w,
		ip:             clientIP,
		time:           time.Time{},
		method:         r.Method,
		uri:            r.RequestURI,
		protocol:       r.Proto,
		status:         http.StatusOK,
		elapsedTime:    time.Duration(0),
	}

	startTime := time.Now()

	lp := len(r.URL.Path)
	if lp > 10 && r.URL.Path[1:11] == "wp-content" {
		http.ServeFile(w, r, "/var/www/"+r.TLS.ServerName+"/html/"+r.URL.Path[1:])
	} else if lp > 11 && r.URL.Path[1:] == "status.html" {
		http.ServeFile(w, r, "/var/www/"+r.TLS.ServerName+"/html/"+r.URL.Path[1:])
	} else if lp > 10 && r.URL.Path[1:11] == "robots.txt" {

	} else if lp > 6 && (r.URL.Path[lp-4:] == ".png" || r.URL.Path[lp-5:] == ".jpeg" || r.URL.Path[lp-5:] == ".json") {
		http.ServeFile(w, r, "/var/www/"+r.TLS.ServerName+"/html/"+r.URL.Path[1:])
	} else {
                http.ServeFile(w, r, "/var/www/"+r.TLS.ServerName+"/html/index.html")
	}

	finishTime := time.Now()
	record.time = finishTime.UTC()
	record.elapsedTime = finishTime.Sub(startTime)
        log, err := os.OpenFile("/var/log/hsrv.log", os.O_RDWR|os.O_APPEND, 0666)
	record.Log(log)
	if err != nil {
	   fmt.Println(err)
	}
	
	log.Close()
}

func redirect(w http.ResponseWriter, req *http.Request) {
    // remove/add not default ports from req.Host
    target := "https://" + req.Host + req.URL.Path 
    if len(req.URL.RawQuery) > 0 {
        target += "?" + req.URL.RawQuery
    }
//    log.Printf("redirect to: %s", target)
    http.Redirect(w, req, target,
            // see @andreiavrammsd comment: often 307 > 301
            http.StatusTemporaryRedirect)
}

func main() {
    t := log.Logger{}
    var err error
    tlsConfig := &tls.Config{}
    tlsConfig.Certificates = make([]tls.Certificate, 2)
    // go http server treats the 0'th key as a default fallback key
    tlsConfig.Certificates[0], err = tls.LoadX509KeyPair("/etc/pki/tls/certs/cluster.crt", "/etc/pki/tls/private/cluster.key")
    if err != nil {
        t.Fatal(err)
    }
    tlsConfig.Certificates[1], err = tls.LoadX509KeyPair("/etc/pki/tls/certs/localhost.crt", "/etc/pki/tls/private/localhost.key")
    if err != nil {
        t.Fatal(err)
    }
//    tlsConfig.Certificates[2], err = tls.LoadX509KeyPair("/srv/www/kuracali.com.pem", "/srv/www/kuracali.com.key.pem")
//    if err != nil {
//        t.Fatal(err)
//    }
    tlsConfig.BuildNameToCertificate()

    http.HandleFunc("/", myHandler)
    server := &http.Server{
        ReadTimeout:    10 * time.Second,
        WriteTimeout:   10 * time.Second,
        MaxHeaderBytes: 1 << 20,
        TLSConfig:      tlsConfig,
    }

    go http.ListenAndServe(":80", http.HandlerFunc(redirect))

    listener, err := tls.Listen("tcp", ":443", tlsConfig)
    if err != nil {
        fmt.Println(err)
        t.Fatal(err)
    }
    log.Fatal(server.Serve(listener))
}
