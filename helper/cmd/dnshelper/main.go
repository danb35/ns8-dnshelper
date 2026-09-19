// Command dnshelper performs DNS operations through libdns provider packages.
//
// It reads one JSON request on stdin and writes one JSON response on stdout;
// see internal/contract. Credentials are only accepted on stdin, never as
// arguments or environment variables. The exit status is 0 when the response
// has "ok": true and 1 otherwise.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/danb35/ns8-dnshelper/helper/internal/app"
	"github.com/danb35/ns8-dnshelper/helper/internal/contract"
)

const maxRequest = 1 << 20

func main() {
	lockDir := flag.String("lock-dir", "", "directory for per-zone lock files (locking is off when empty)")
	timeout := flag.Duration("timeout", 120*time.Second, "overall time limit (Hetzner alone takes 8-15 s per API action)")
	flag.Parse()

	var req contract.Request
	dec := json.NewDecoder(io.LimitReader(os.Stdin, maxRequest))
	if err := dec.Decode(&req); err != nil {
		// Decoder errors quote no input, so this cannot echo credentials.
		emit(contract.Response{Records: []contract.Record{}, Error: &contract.Error{
			Code: contract.CodeInvalidRequest, Message: "cannot parse the request: " + err.Error()}})
		os.Exit(1)
	}

	resp := app.Run(context.Background(), req, app.Options{LockDir: *lockDir, Timeout: *timeout})
	emit(resp)
	if !resp.OK {
		os.Exit(1)
	}
}

func emit(r contract.Response) {
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		fmt.Fprintln(os.Stderr, "dnshelper: cannot write response")
		os.Exit(1)
	}
}
