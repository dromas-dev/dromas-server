package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
)

// With one argument, N, it polls ../srv, the model of an earlier design, N
// times. With three, N URL AUTHORIZATION, it polls URL with that Authorization
// value: a real dromasd, a box's /messages, and the contents of the box's
// pass file.
func main() {
	n, _ := strconv.Atoi(os.Args[1])
	H := make([]byte, 32)
	H[0] = 9
	mac := hmac.New(sha256.New, make([]byte, 32))
	mac.Write([]byte("dromas-token-v1"))
	mac.Write(H)
	mac.Write([]byte{0, 0, 0, 0})
	tok := "Bearer drt1_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	url := "http://127.0.0.1:18777/v1/" + hex.EncodeToString(H) + "/messages"
	want := "[]"
	if len(os.Args) == 4 {
		url, tok = os.Args[2], os.Args[3]
		want = `{"count":0,"messages":[],"next_cursor":null}` + "\n"
	}
	tr := &http.Transport{MaxIdleConnsPerHost: 4}
	c := &http.Client{Transport: tr}
	var wg sync.WaitGroup
	bad := 0
	var mu sync.Mutex
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n/4; i++ {
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("Authorization", tok)
				resp, err := c.Do(req)
				if err != nil {
					mu.Lock()
					bad++
					mu.Unlock()
					continue
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 || string(b) != want {
					mu.Lock()
					bad++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	fmt.Println("requests", n, "bad", bad)
}
