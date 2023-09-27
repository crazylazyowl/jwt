package jwt

import (
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func ParsePrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := read(path)
	if err != nil {
		return nil, err
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(data)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func ParsePublicKey(path string) (*rsa.PublicKey, error) {
	data, err := read(path)
	if err != nil {
		return nil, err
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func Issue(username string, ttl time.Duration, private *rsa.PrivateKey) (string, error) {
	now := time.Now().UTC()

	claims := jwt.RegisteredClaims{
		Subject:   username,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
	}
	if ttl != -1 {
		claims.ExpiresAt = jwt.NewNumericDate(now.Add(ttl))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(private)
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func Verify(tokenStr string, public *rsa.PublicKey) (string, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", t.Header["alg"])
		}
		return public, nil
	})
	if err != nil {
		return "", err
	}
	if !token.Valid {
		return "", fmt.Errorf("invalid token; %v", token)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("problem with claims; %v", token)
	}
	subject, ok := claims["sub"].(string)
	if !ok {
		return "", fmt.Errorf("problem with subject; %v", token)
	}
	return subject, nil
}
