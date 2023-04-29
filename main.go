package main

import (
	"auth-server/Auth"
	"auth-server/GMMAuth"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
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

var (
	accountsData  = map[string][]string{}
	authTemp      = map[string]Auth.Auth{}
	acccountRegex = regexp.MustCompile("(\\w+) (\\S+):(\\S+)")
)

func reloadAccount() {
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

type ReqBody struct {
	User        string `json:"user"`
	ShareSecret string `json:"shareSecret"`
	ServerID    string `json:"serverID"`
	PublicKey   string `json:"publicKey"`
	VerifyToken string `json:"verifyToken"`
}

type Error struct {
	Err    string `json:"error"`
	ErrMsg string `json:"errorMessage"`
	Cause  string `json:"cause"`
}

func (e Error) Error() string {
	return e.Err + ": " + e.ErrMsg + ", " + e.Cause
}

// agent is a struct of auth
type agent struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

type proof struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

// Tokens store AccessToken and ClientToken
type Tokens struct {
	AccessToken string `json:"accessToken"`
	ClientToken string `json:"clientToken"`
}

var defaultAgent = agent{
	Name:    "Minecraft",
	Version: 1,
}

// authPayload is a yggdrasil request struct
type authPayload struct {
	Agent agent `json:"agent"`
	proof
	ClientToken string `json:"clientToken,omitempty"`
	RequestUser bool   `json:"requestUser"`
}

// authResp is the response from Mojang's auth server
type authResp struct {
	Tokens
	AvailableProfiles []Profile `json:"availableProfiles"` // only present if the agent field was received

	SelectedProfile Profile `json:"selectedProfile"` // only present if the agent field was received
	User            struct {
		// only present if requestUser was true in the request authPayload
		ID         string `json:"id"` // hexadecimal
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
	} `json:"user"`

	*Error
}

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Legacy bool   `json:"legacy"` // we don't care
}
type refreshPayload struct {
	Tokens
	SelectedProfile *Profile `json:"selectedProfile,omitempty"`

	RequestUser bool `json:"requestUser"`
}

type profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type request struct {
	AccessToken     string `json:"accessToken"`
	SelectedProfile string `json:"selectedProfile"`
	ServerID        string `json:"serverId"`
}

func main() {
	reloadAccount()
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	as := r.Group("/as")
	as.POST("/authenticate", func(c *gin.Context) {
		log.Printf("[session auth]\n")
		reloadAccount()
		var payload authPayload
		c.BindJSON(&payload)
		ac, ok := accountsData[payload.UserName]
		if !ok {
			c.AbortWithStatusJSON(403, gin.H{
				"error":        "ForbiddenOperationException",
				"errorMessage": "Invalid credentials. Invalid username or password.",
			})
			return
		}
		auth, err := GMMAuth.GetMCcredentialsByPassword(ac[0], ac[1])
		if err != nil {
			c.AbortWithStatusJSON(400, gin.H{
				"error":        "ForbiddenOperationException",
				"errorMessage": "Forbidden",
			})
			return
		}
		authTemp[payload.UserName] = auth
		profile := Profile{
			ID:   auth.UUID,
			Name: auth.Name,
		}
		c.JSON(200, authResp{
			Tokens: Tokens{
				AccessToken: payload.UserName,
				ClientToken: payload.UserName,
			},
			AvailableProfiles: []Profile{profile},
			SelectedProfile:   profile,
		})
	})

	as.POST("/refresh", func(c *gin.Context) {
		var re refreshPayload
		c.BindJSON(&re)

		c.JSON(200, authResp{
			Tokens: Tokens{
				AccessToken: re.AccessToken,
				ClientToken: re.AccessToken,
			},
			AvailableProfiles: []Profile{
				*re.SelectedProfile,
			},
			SelectedProfile: *re.SelectedProfile,
		})
	})
	as.POST("/validate", func(c *gin.Context) {
		c.Status(204)
	})
	as.POST("/signout", func(c *gin.Context) {
		c.Status(200)
	})
	as.POST("/invalidate", func(c *gin.Context) {
		c.Status(200)
	})
	ss := r.Group("/ss")
	ss.POST("/session/minecraft/join", func(c *gin.Context) {

		var req request
		err := c.BindJSON(&req)
		if err != nil {
			fmt.Println(err)
		}
		ac, ok := accountsData[req.AccessToken]
		if !ok {
			c.AbortWithStatusJSON(403, gin.H{
				"error":        "ForbiddenOperationException",
				"errorMessage": "Invalid credentials. Invalid username or password.",
			})
			return
		}

		log.Printf("[session join]: %v\n", req.AccessToken)
		if _, ok := authTemp[req.AccessToken]; ok {
			err := LoginRemote(request{
				AccessToken:     authTemp[req.AccessToken].AsTk,
				SelectedProfile: strings.ReplaceAll(authTemp[req.AccessToken].UUID, "-", ""),
				ServerID:        req.ServerID,
			})
			if err != nil {
				c.AbortWithStatus(403)
				return
			}
			c.Status(204)
			log.Printf("[login] Code [%v]: %v\n", req.AccessToken, "Successful(cache)")
			return
		}
		auth, err := GMMAuth.GetMCcredentialsByPassword(ac[0], ac[1])
		if err != nil {
			c.AbortWithStatusJSON(400, gin.H{
				"error":        "ForbiddenOperationException",
				"errorMessage": "Forbidden",
			})
			return
		}
		authTemp[req.AccessToken] = auth
		err = LoginRemote(request{
			AccessToken:     authTemp[req.AccessToken].AsTk,
			SelectedProfile: strings.ReplaceAll(authTemp[req.AccessToken].UUID, "-", ""),
			ServerID:        req.ServerID,
		})
		if err != nil {
			c.AbortWithStatus(403)
			return
		}
		c.Status(204)

	})

	r.GET("/getUser", func(c *gin.Context) {
		reloadAccount()
		buf := new(bytes.Buffer)
		buf.ReadFrom(c.Request.Body)
		user := buf.String()
		ac := accountsData[user]
		auth, err := GMMAuth.GetMCcredentialsByPassword(ac[0], ac[1])
		if err != nil {
			c.AbortWithStatus(400)
			return
		}
		authTemp[user] = auth
		c.String(200, "text/plain", auth.Name)
		log.Printf("[getUser] Code [%v]: %v\n", user, auth.Name)
	})
	r.GET("/login", func(c *gin.Context) {
		reloadAccount()
		result, _ := io.ReadAll(c.Request.Body)
		var req ReqBody
		err := json.Unmarshal(result, &req)
		if err != nil {
			log.Printf("[login] Request with bad payload\n")
			c.Status(403)
			return
		}
		log.Printf("[login] Request Code [%v] login\n", req.User)
		if _, ok := accountsData[req.User]; !ok {
			log.Printf("[login] Request Code [%v] not found\n", req.User)
			c.Status(403)
			return
		}
		if _, ok := authTemp[req.User]; ok {
			err = Auth.LoginAuth(authTemp[req.User], req.ShareSecret, req.ServerID, req.PublicKey, req.VerifyToken)
			c.Status(200)
			log.Printf("[login] Code [%v]: %v\n", req.User, "Successful(cache)")
			delete(authTemp, req.User)
			return
		}
		ac := accountsData[req.User]
		auth, err := GMMAuth.GetMCcredentialsByPassword(ac[0], ac[1])
		if err != nil {
			go failedLogin(ac[0], ac[1])
			c.Status(400)
			return
		}
		authTemp[req.User] = auth
		err = Auth.LoginAuth(auth, req.ShareSecret, req.ServerID, req.PublicKey, req.VerifyToken)
		if err != nil {
			c.Status(400)
			return
		}
		c.Status(200)
		log.Printf("[login] Code [%v]: %v\n", req.User, "Successful(refresh)")
	})
	r.Run("127.0.0.1:37565")
}
func LoginRemote(req request) error {
	client := http.Client{}
	requestPacket, err := json.Marshal(
		req,
	)
	if err != nil {
		return fmt.Errorf("create request packet to yggdrasil faile: %v", err)
	}

	PostRequest, err := http.NewRequest(http.MethodPost, "https://sessionserver.mojang.com/session/minecraft/join",
		bytes.NewReader(requestPacket))
	if err != nil {
		return fmt.Errorf("make request error: %v", err)
	}
	PostRequest.Header.Set("User-agent", "go-mc")
	PostRequest.Header.Set("Connection", "keep-alive")
	PostRequest.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(PostRequest)
	if err != nil {
		return fmt.Errorf("post fail: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("auth fail: %s", string(body))
	}
	return nil

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
