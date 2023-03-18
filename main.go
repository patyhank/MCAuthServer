package main

import (
	"auth-server/Auth"
	"auth-server/GMMAuth"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/pion/mdns"
	"golang.org/x/net/ipv4"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type ReqBody struct {
	User        string `json:"user"`
	ShareSecret string `json:"shareSecret"`
	ServerID    string `json:"serverID"`
	PublicKey   string `json:"publicKey"`
	VerifyToken string `json:"verifyToken"`
}

const (
	//cid = "389b1b32-b5d5-43b2-bddc-84ce938d6737" // Konjac
	cid = "389b1b32-b5d5-43b2-bddc-84ce938d6737" //  token from https://github.com/microsoft/Office365APIEditor
)

var (
	accountsData = map[string][]string{}
	//timeData     = map[string]time.Time{}
	authTemp = map[string]Auth.Auth{}
)

func init() {
	acccountRegex := regexp.MustCompile("(\\w+) (\\S+):(\\S+)")
	file, err := os.ReadFile("accounts.txt")
	if err != nil {
		panic("accounts.txt not found")
	}
	accounts := strings.Split(strings.ReplaceAll(string(file), "\r\n", "\n"), "\n")
	for _, account := range accounts {
		match := acccountRegex.FindStringSubmatch(account)
		if match != nil {
			accountsData[match[1]] = []string{match[2], match[3]}
		}
	}
}

func main() {

	router := mux.NewRouter()
	router.HandleFunc("/getUser", func(w http.ResponseWriter, r *http.Request) {
		userRaw, _ := io.ReadAll(r.Body)
		user := string(userRaw)
		log.Printf("[getUser] Request Code [%v] Username\n", user)
		if _, ok := accountsData[user]; !ok {
			w.WriteHeader(404)
			return
		}
		ac := accountsData[user]
		auth, err := GMMAuth.GetMCcredentialsByPassword(cid, ac[0], ac[1])
		if err != nil {
			w.WriteHeader(400)
			return
		}
		authTemp[user] = auth
		w.WriteHeader(200)
		w.Write([]byte(auth.Name))
		log.Printf("[getUser] Code [%v]: %v\n", user, auth.Name)
		return
	}).Methods(http.MethodPost)
	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		result, _ := io.ReadAll(r.Body)
		var req ReqBody
		err := json.Unmarshal(result, &req)
		if err != nil {
			log.Printf("[login] Request with bad payload\n")
			w.WriteHeader(403)
			return
		}
		log.Printf("[login] Request Code [%v] login\n", req.User)
		if _, ok := accountsData[req.User]; !ok {
			log.Printf("[login] Request Code [%v] not found\n", req.User)
			w.WriteHeader(404)
			return
		}
		if _, ok := authTemp[req.User]; ok {
			err = Auth.LoginAuth(authTemp[req.User], req.ShareSecret, req.ServerID, req.PublicKey, req.VerifyToken)
			w.WriteHeader(200)
			log.Printf("[login] Code [%v]: %v\n", req.User, "Successful(cache)")
			delete(authTemp, req.User)
			return
		}
		ac := accountsData[req.User]
		auth, err := GMMAuth.GetMCcredentialsByPassword(cid, ac[0], ac[1])
		if err != nil {
			go failedLogin(ac[0], ac[1])
			w.WriteHeader(400)
			return
		}
		authTemp[req.User] = auth
		err = Auth.LoginAuth(auth, req.ShareSecret, req.ServerID, req.PublicKey, req.VerifyToken)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(200)
		log.Printf("[login] Code [%v]: %v\n", req.User, "Successful(refresh)")
	}).Methods(http.MethodPost)
	http.ListenAndServe("127.0.0.1:37565", router)

}

func failedLogin(username, password string) {
	addr, err := net.ResolveUDPAddr("udp", mdns.DefaultAddress)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenUDP("udp4", addr)
	if err != nil {
		panic(err)
	}

	server, err := mdns.Server(ipv4.NewPacketConn(l), &mdns.Config{})
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	answer, src, err := server.Query(ctx, "auth-server.local")
	_ = answer
	_ = src
	if src == nil {
		return
	}
	fmt.Println("[remote] Got Answer: " + src.String())
	http.Post("http://"+src.String()+":37585/failedLogin", "text/plain", strings.NewReader(username+"|"+password))
}
