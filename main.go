package main

import (
	"auth-server/Auth"
	"auth-server/GMMAuth"
	"encoding/json"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
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
	timeData     = map[string]time.Time{}
	authTemp     = map[string]Auth.Auth{}
)

func init() {
	file, err := ioutil.ReadFile("accounts.txt")
	if err != nil {
		panic("accounts.txt not found")
	}
	accounts := strings.Split(strings.ReplaceAll(string(file), "\r\n", "\n"), "\n")
	for _, account := range accounts {
		codeAndAccount := strings.SplitN(account, " ", 2)
		accountsData[codeAndAccount[0]] = strings.SplitN(codeAndAccount[1], ":", 2)
	}
}

func main() {

	router := mux.NewRouter()
	router.HandleFunc("/getUser", func(w http.ResponseWriter, r *http.Request) {
		userRaw, _ := ioutil.ReadAll(r.Body)
		user := string(userRaw)
		log.Printf("[getUser] Request Code [%v] Username\n", user)
		if _, ok := accountsData[user]; !ok {
			w.WriteHeader(404)
			return
		}
		if _, ok := timeData[user]; ok {
			if timeData[user].After(time.Now()) {
				w.WriteHeader(200)
				w.Write([]byte(authTemp[user].Name))
				log.Printf("[getUser] Code [%v]: %v\n", user, authTemp[user].Name)
				return
			}
		}
		ac := accountsData[user]
		auth, err := GMMAuth.GetMCcredentialsByPassword(cid, ac[0], ac[1])
		if err != nil {
			w.WriteHeader(400)
			return
		}
		authTemp[user] = auth
		timeData[user] = time.Now().Add(10 * time.Minute)
		w.WriteHeader(200)
		w.Write([]byte(auth.Name))
		log.Printf("[getUser] Code [%v]: %v\n", user, auth.Name)
		return
	}).Methods(http.MethodPost)
	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		result, _ := ioutil.ReadAll(r.Body)
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
		if _, ok := timeData[req.User]; ok {
			if timeData[req.User].After(time.Now()) {
				err = Auth.LoginAuth(authTemp[req.User], req.ShareSecret, req.ServerID, req.PublicKey, req.VerifyToken)
				w.WriteHeader(200)
				log.Printf("[login] Code [%v]: %v\n", req.User, "Successful(cache)")
				return
			}
		}
		ac := accountsData[req.User]
		auth, err := GMMAuth.GetMCcredentialsByPassword(cid, ac[0], ac[1])
		if err != nil {
			w.WriteHeader(400)
			return
		}
		authTemp[req.User] = auth
		timeData[req.User] = time.Now().Add(10 * time.Minute)
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
