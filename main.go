package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pelletier/go-toml"
	"github.com/tidwall/pretty"
)

type serverConfig struct {
	Secret  string
	HookUrl string
	Port    int
}

type githubWebhookHeader struct {
	Signature256 string `header:"X-Hub-Signature-256"`
	UserAgent    string `header:"User-Agent"`
}

var config serverConfig

func logError(msg string, err error) {
	log.Printf("%s: %v\n", msg, err)
}

func githubWebhookTestHandler(c *gin.Context) {
	ok := true
	errMsg := ""
	defer func() {
		if !ok {
			c.String(http.StatusForbidden, errMsg)
		}
	}()
	handleError := func(msg string, err error) {
		ok = false
		errMsg = msg
		logError(msg, err)
	}
	header := githubWebhookHeader{}
	err := c.ShouldBindHeader(&header)
	if err != nil {
		handleError("could not bind header", err)
		return
	}
	if !strings.HasPrefix(header.UserAgent, "GitHub-Hookshot/") {
		handleError("invalid user agent", err)
		return
	}
	bodyReader := c.Request.Body
	body, err := ioutil.ReadAll(bodyReader)
	if err != nil {
		handleError("could not read request body", err)
		return
	}
	err = bodyReader.Close()
	if err != nil {
		handleError("could not close body reader", err)
		return
	}
	if config.Secret != "" {
		h := hmac.New(sha256.New, []byte(config.Secret))
		h.Write(body)
		expectedSig := h.Sum(nil)
		receivedSig, err := hex.DecodeString(header.Signature256[7:])
		if err != nil {
			handleError("could not decode hex string", err)
			return
		}
		valid := hmac.Equal(receivedSig, expectedSig)
		if !valid {
			handleError("invalid signature", err)
			return
		}
	}
	log.Printf("valid request: %s\n", string(pretty.Pretty(body)))
	c.String(http.StatusOK, "OK")
}

func main() {
	file, err := os.Open("config.toml")
	if errors.Is(err, os.ErrNotExist) {
		file, err = os.Open("config_default.toml")
		if errors.Is(err, os.ErrNotExist) {
			logError("could not open config file", err)
			return
		}
	}
	content, err := ioutil.ReadAll(file)
	if err != nil {
		logError("could not read config file", err)
	}
	err = toml.Unmarshal(content, &config)
	if err != nil {
		logError("could not unmarshal config content", err)
	}
	server := gin.Default()
	server.POST(config.HookUrl, githubWebhookTestHandler)
	server.Run(":" + strconv.Itoa(config.Port))
}
