package Auth

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Auth includes a account
type Auth struct {
	Name string
	UUID string
	AsTk string
}

func LoginAuth(auth Auth, key, serverID, publicKey, verifyToken string) error {
	publicKeyByte, _ := base64.StdEncoding.DecodeString(publicKey)
	keyByte, _ := base64.StdEncoding.DecodeString(key)
	verifyTokenByte, _ := base64.StdEncoding.DecodeString(verifyToken)
	return loginAuth(auth, keyByte, encryptionRequest{
		ServerID:    serverID,
		PublicKey:   publicKeyByte,
		VerifyToken: verifyTokenByte,
	})
}

//
//func handleEncryptionRequest(c *Client, p pk.Packet) error {
//	// 创建AES对称加密密钥
//	key, encoStream, decoStream := newSymmetricEncryption()
//
//	// Read EncryptionRequest
//	var er encryptionRequest
//	if err := p.Scan(&er); err != nil {
//		return err
//	}
//
//	err := loginAuth(c.Auth, key, er) //向Mojang验证
//	if err != nil {
//		return fmt.Errorf("login fail: %v", err)
//	}
//
//	// 响应加密请求
//	// Write Encryption Key Response
//	p, err = genEncryptionKeyResponse(key, er.PublicKey, er.VerifyToken)
//	if err != nil {
//		return fmt.Errorf("gen encryption key response fail: %v", err)
//	}
//
//	err = c.Conn.WritePacket(p)
//	if err != nil {
//		return err
//	}
//
//	// 设置连接加密
//	c.Conn.SetCipher(encoStream, decoStream)
//	return nil
//}

type encryptionRequest struct {
	ServerID    string
	PublicKey   []byte
	VerifyToken []byte
}

// authDigest computes a special SHA-1 digest required for Minecraft web
// authentication on Premium servers (online-mode=true).
// Source: http://wiki.vg/Protocol_Encryption#Server
//
// Also many, many thanks to SirCmpwn and his wonderful gist (C#):
// https://gist.github.com/SirCmpwn/404223052379e82f91e6
func authDigest(serverID string, sharedSecret, publicKey []byte) string {
	h := sha1.New()
	h.Write([]byte(serverID))
	h.Write(sharedSecret)
	h.Write(publicKey)
	hash := h.Sum(nil)

	// Check for negative hashes
	negative := (hash[0] & 0x80) == 0x80
	if negative {
		hash = twosComplement(hash)
	}

	// Trim away zeroes
	res := strings.TrimLeft(fmt.Sprintf("%x", hash), "0")
	if negative {
		res = "-" + res
	}

	return res
}

// little endian
func twosComplement(p []byte) []byte {
	carry := true
	for i := len(p) - 1; i >= 0; i-- {
		p[i] = ^p[i]
		if carry {
			carry = p[i] == 0xff
			p[i]++
		}
	}
	return p
}

type profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type request struct {
	AccessToken     string  `json:"accessToken"`
	SelectedProfile profile `json:"selectedProfile"`
	ServerID        string  `json:"serverId"`
}

func loginAuth(auth Auth, shareSecret []byte, er encryptionRequest) error {
	digest := authDigest(er.ServerID, shareSecret, er.PublicKey)

	client := http.Client{}
	requestPacket, err := json.Marshal(
		request{
			AccessToken: auth.AsTk,
			SelectedProfile: profile{
				ID:   auth.UUID,
				Name: auth.Name,
			},
			ServerID: digest,
		},
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
