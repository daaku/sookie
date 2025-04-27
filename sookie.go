// Package sookie provides a simple way to set and get cookies with encryption and compression.
// It uses the XChaCha20-Poly1305 AEAD algorithm for encryption and Zstandard for compression.
// The cookie value is base64 encoded and can be safely sent over HTTP headers.
package sookie

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/shamaton/msgpack/v2"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	decoder, _ = zstd.NewReader(nil)
	encoder, _ = zstd.NewWriter(nil)

	// ErrExpired is returned when the cookie has expired.
	ErrExpired = errors.New("sookie: cookie expired")
)

type wrapper[V any] struct {
	V V
	E int64
}

// Set sets a cookie with the given value. The value is encrypted and compressed
// using the XChaCha20-Poly1305 AEAD algorithm and Zstandard compression.
// The cookie is set with the given name and options.
// MaxAge or Expires may optionally be set to control the expiration of the cookie.
// MaxAge takes precedence over Expires.
// The http.Cookie `Value` field must be empty and the passed in value will me marshaled and used instead.
// The cookie will be deleted if MaxAge is less than 0 (and an empty value will be sent).
func Set[V any](secret []byte, w http.ResponseWriter, value V, cookie http.Cookie) error {
	if cookie.Value != "" {
		return errors.New("sookie: cookie value must be empty")
	}

	// special case delete cookie
	if cookie.MaxAge < 0 {
		http.SetCookie(w, &cookie)
		return nil
	}

	var expires int64 = -1
	if cookie.MaxAge > 0 {
		expires = time.Now().Add(time.Duration(cookie.MaxAge) * time.Second).Unix()
	} else if !cookie.Expires.IsZero() {
		expires = cookie.Expires.Unix()
	}
	msgp, err := msgpack.Marshal(wrapper[V]{V: value, E: expires})
	if err != nil {
		return fmt.Errorf("sookie: failed to marshal value: %w", err)
	}

	compressed := encoder.EncodeAll(msgp, nil)

	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return fmt.Errorf("sookie: failed to create AEAD: %w", err)
	}

	// initial size is nonce for rand.Read, but capacity for the whole thing
	nonce := make([]byte, chacha20poly1305.NonceSizeX,
		chacha20poly1305.NonceSizeX+len(compressed)+chacha20poly1305.Overhead)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("sookie: failed to read nonce: %w", err)
	}
	ciphertext := aead.Seal(nonce, nonce, compressed, nil)
	cookie.Value = base64.RawURLEncoding.EncodeToString(ciphertext)

	if err := cookie.Valid(); err != nil {
		return fmt.Errorf("sookie: invalid cookie: %w", err)
	}

	http.SetCookie(w, &cookie)
	return nil
}

// Get retrieves a cookie with the given name from the request.
// The cookie value is decrypted and decompressed using the XChaCha20-Poly1305 AEAD algorithm.
// The cookie value is unmarshaled into the given type V.
// If the cookie is not found, the http.ErrNoCookie error is returned.
// If the cookie is expired, the ErrExpired error is returned.
func Get[V any](secret []byte, r *http.Request, name string) (V, error) {
	var w wrapper[V]
	cookie, err := r.Cookie(name)
	if err != nil {
		if err == http.ErrNoCookie {
			return w.V, err
		}
		return w.V, fmt.Errorf("sookie: failed to get cookie: %w", err)
	}
	message, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return w.V, fmt.Errorf("sookie: failed to decode cookie: %w", err)
	}
	if len(message) < chacha20poly1305.NonceSizeX {
		return w.V, errors.New("sookie: invalid cookie length")
	}
	nonce, ciphertext := message[:chacha20poly1305.NonceSizeX], message[chacha20poly1305.NonceSizeX:]
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		return w.V, fmt.Errorf("sookie: failed to create AEAD: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return w.V, fmt.Errorf("sookie: failed to decrypt cookie: %w", err)
	}
	uncompressed, err := decoder.DecodeAll(plaintext, nil)
	if err != nil {
		return w.V, fmt.Errorf("sookie: failed to decompress cookie: %w", err)
	}
	if err := msgpack.Unmarshal(uncompressed, &w); err != nil {
		return w.V, fmt.Errorf("sookie: failed to unmarshal cookie: %w", err)
	}
	if w.E != -1 && time.Now().Unix() > w.E {
		return w.V, ErrExpired
	}
	return w.V, nil
}
