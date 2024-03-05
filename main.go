package main

import (
  "crypto/rand"
  "crypto/x509"
  "encoding/pem"
  "fmt"
  "math"
  "math/big"
  "time"

  log "github.com/sirupsen/logrus"
  "gopkg.in/square/go-jose.v2"
  "gopkg.in/square/go-jose.v2/jwt"
)

const (
  keyName = os.Getenv("COINBASE_KEY_NAME")
  keySecret = os.Getenv("COINBASE_KEY_SECRET")
  requestMethod = "GET"
  requestHost = "api.coinbase.com"
  requestPath = "/api/v3/brokerage/accounts"
  serviceName = "retail_rest_api_proxy"
)

type APIKeyClaims struct {
  *jwt.Claims
  URI string `json:"uri"`
}

func buildJWT(service, uri string) (string, error) {
  block, _ := pem.Decode([]byte(keySecret))
  if block == nil {
    return "", fmt.Errorf("jwt: Could not decode private key.")
  }

  key, err := x509.ParseECPrivateKey(block.Bytes)
  if err != nil {
    return "", fmt.Errorf("jwt: %w", err)
  }

  sig, err := jose.NewSigner(
    jose.SigningKey{Algorithm: jose.ES256, Key: key},
    (&jose.SignerOptions{NonceSource: nonceSource{}}).WithType("JWT").WithHeader("kid", keyName),
  )
  if err != nil {
    return "", fmt.Errorf("jwt: %w", err)
  }

  cl := &APIKeyClaims{
    Claims: &jwt.Claims{
      Subject: keyName,
      Issuer: "coinbase-cloud",
      NotBefore: jwt.NewNumericDate(time.Now()),
      Expiry: jwt.NewNumericDate(time.Now().Add(2 * time.Minute)),
      Audience: jwt.Audience{service},
    },
    URI: uri,
  }
  jwtString, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
  if err != nil {
    return "", fmt.Errorf("jwt: %w", err)
  }
  return jwtString, nil
}

var max = big.NewInt(math.MaxInt64)

type nonceSource struct{}

func (n nonceSource) Nonce() (string, error) {
  r, err := rand.Int(rand.Reader, max)
  if err != nil {
    return "", err
  }
  return r.String(), nil
}

func main () {
  uri := fmt.Sprintf("%s %s%s", requestMethod, requestHost, requestPath)

  jwt, err := buildJWT(serviceName, uri)

  if err != nil {
    log.Errorf("error building jwt: %v", err)
  }
  fmt.Println("export JWT=" + jwt)
}
