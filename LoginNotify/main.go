package main

import (
	"fmt"
	"github.com/dlclark/regexp2"
	"github.com/pion/mdns"
	"github.com/zserge/lorca"
	"golang.org/x/net/ipv4"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

var emailMap = sync.Map{}

func main() {
	addr, err := net.ResolveUDPAddr("udp", mdns.DefaultAddress)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenUDP("udp4", addr)
	if err != nil {
		panic(err)
	}

	_, err = mdns.Server(ipv4.NewPacketConn(l), &mdns.Config{
		LocalNames: []string{"auth-server.local"},
	})
	if err != nil {
		panic(err)
	}
	http.HandleFunc("/failedLogin", failedLogin)
	log.Fatal(http.ListenAndServe(":37585", nil))
}

func failedLogin(w http.ResponseWriter, r *http.Request) {
	message, _ := io.ReadAll(r.Body)
	sp := strings.SplitN(string(message), "|", 2)
	if len(sp) != 2 {
		w.WriteHeader(200)
		return
	}
	if _, ok := emailMap.Load(sp[0]); ok {
		return
	}
	emailMap.Store(sp[0], 0)
	go func() {
		client := http.DefaultClient
		ppft := regexp.MustCompile("sFTTag:[ ]?'.*value=\"(.*)\"/>'")
		urlPost := regexp2.MustCompile("urlPost:[ ]?'(.+?(?='))", 0)
		loginEndpoint := fmt.Sprintf("https://login.live.com/oauth20_authorize.srf?redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=code&locale=en&client_id=%v", "000000004C12AE6F")

		req, _ := http.NewRequest("GET", loginEndpoint, nil)
		result, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return
		}
		if result.StatusCode != 200 {
			fmt.Println(err)
			return
		}
		cookie := result.Header.Values("set-cookie")
		var cookies []string
		for _, s := range cookie {
			cookies = append(cookies, strings.SplitN(s, ";", 2)[0])
		}
		cookieStr := strings.Join(cookies, "; ")
		body, _ := io.ReadAll(result.Body)
		mppft := ppft.FindStringSubmatch(string(body))
		mUrlPost, err := urlPost.FindStringMatch(string(body))
		if mppft == nil || err != nil || mUrlPost == nil {
			return
		}
		mapp := map[string]string{
			"login":            sp[0],
			"loginfmt":         sp[1],
			"passwd":           sp[1],
			"PPFT":             mppft[1],
			"PPSX":             "PassportR",
			"type":             "11",
			"NewUser":          "1",
			"LoginOptions":     "1",
			"i13":              "1",
			"CookieDisclosure": "0",
			"ps":               "2",
			"ctx":              "2",
			"i19":              "25774",
		}
		values := url.Values{}

		for s, s2 := range mapp {
			values.Add(s, s2)
		}
		req, _ = http.NewRequest("POST", mUrlPost.GroupByNumber(1).String(), strings.NewReader(values.Encode()))

		req.Header.Add("Cookie", cookieStr)
		req.Header.Add("Pragma", "no-cache")
		//req.Header.Add("Accept-Encoding", "gzip, deflate, compress")
		req.Header.Add("Accept-Language", "zh-TW, zh;q=0.9")
		req.Header.Add("User-Agent", "XboxReplay; XboxLiveAuth/4.0")
		req.Header.Add("Accept", "*/*")
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err := client.Do(req)
		resBody, err := io.ReadAll(res.Body)
		if len(resBody) == 0 {
			return
		}

		ui, err := lorca.New("", "", 640, 320, "--window-position=0,0")
		if err != nil {
			return
		}
		ui.Load("data:text/html," + url.PathEscape(string(resBody)))
		defer ui.Close()
		<-ui.Done()
		emailMap.Delete(sp[0])
	}()
}
