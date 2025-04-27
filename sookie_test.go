package sookie_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daaku/ensure"
	"github.com/daaku/sookie"
)

const cookieName = "flash"

var (
	secret = []byte("274521B016094DBAB7093B257545A96E")
	given  = Flash{
		Kind:    "alert-success",
		Content: "ℹ️ The answer is <strong>42.</strong>.",
	}
)

type Flash struct {
	Kind    string
	Content string
}

func TestWithoutExpiry(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set(secret, w, given, http.Cookie{Name: cookieName})
	ensure.Nil(t, err)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	actual, err := sookie.Get[Flash](secret, r, cookieName)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, actual.Kind, given.Kind)
	ensure.DeepEqual(t, actual.Content, given.Content)
}

func TestSuccessUsingPointers(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set(secret, w, &given, http.Cookie{Name: cookieName})
	ensure.Nil(t, err)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	actual, err := sookie.Get[*Flash](secret, r, cookieName)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, actual.Kind, given.Kind)
	ensure.DeepEqual(t, actual.Content, given.Content)
}

func TestNoCookieUsingPointers(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	actual, err := sookie.Get[*Flash](secret, r, cookieName)
	ensure.NotNil(t, err)
	ensure.DeepEqual(t, err, http.ErrNoCookie)
	ensure.True(t, actual == nil)
}

func TestDelete(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set(secret, w, Flash{}, http.Cookie{
		Name:   cookieName,
		MaxAge: -1,
	})
	ensure.Nil(t, err)
	ensure.StringContains(t, w.Header().Get("Set-Cookie"), cookieName+"=;")
}

func TestSetErrorWithValue(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set(secret, w, Flash{}, http.Cookie{
		Name:  cookieName,
		Value: "not empty",
	})
	ensure.NotNil(t, err)
	ensure.StringContains(t, err.Error(), "sookie: cookie value must be empty")
}

func TestSetErrorWithUnsupportedMarshal(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set(secret, w, struct{ P uintptr }{}, http.Cookie{Name: cookieName})
	ensure.NotNil(t, err)
	ensure.StringContains(t, err.Error(), "sookie: failed to marshal value")
}

func TestSetErrorWithInvalidSecret(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set([]byte("hello world"), w, Flash{}, http.Cookie{Name: cookieName})
	ensure.NotNil(t, err)
	ensure.StringContains(t, err.Error(), "sookie: failed to create AEAD")
}

func TestSetErrorWithEmptySecret(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set([]byte(""), w, Flash{}, http.Cookie{Name: cookieName})
	ensure.NotNil(t, err)
	ensure.StringContains(t, err.Error(), "sookie: failed to create AEAD")
}

func TestSetErrorWithInvalidCookie(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set(secret, w, Flash{}, http.Cookie{
		Name:        cookieName,
		Partitioned: true,
	})
	ensure.NotNil(t, err)
	ensure.StringContains(t, err.Error(), "sookie: invalid cookie")
}

func TestErrorWithExpired(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set(secret, w, Flash{}, http.Cookie{
		Name:    cookieName,
		Expires: time.Now().Add(-1 * time.Hour),
	})
	ensure.Nil(t, err)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	_, err = sookie.Get[Flash](secret, r, cookieName)
	ensure.DeepEqual(t, err, sookie.ErrExpired)
}

func TestSetGetValidExpiredMaxAge(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set(secret, w, given, http.Cookie{
		Name:   cookieName,
		MaxAge: 100,
	})
	ensure.Nil(t, err)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	actual, err := sookie.Get[Flash](secret, r, cookieName)
	ensure.Nil(t, err)
	ensure.DeepEqual(t, actual.Kind, given.Kind)
	ensure.DeepEqual(t, actual.Content, given.Content)
}

func TestGetNoCookie(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	_, err := sookie.Get[Flash](secret, r, cookieName)
	ensure.DeepEqual(t, err, http.ErrNoCookie)
}

func TestGetErrorInvalidCookie(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", cookieName+"=invalid")
	_, err := sookie.Get[Flash](secret, r, cookieName)
	ensure.NotNil(t, err)
	ensure.StringContains(t, err.Error(), "sookie: invalid cookie length")
}

func TestGetErrorDecode(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", cookieName+"=@")
	_, err := sookie.Get[Flash](secret, r, cookieName)
	ensure.NotNil(t, err)
	ensure.StringContains(t, err.Error(), "sookie: failed to decode cookie")
}

func TestGetErrorWithEmptySecret(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set(secret, w, given, http.Cookie{Name: cookieName})
	ensure.Nil(t, err)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	_, err = sookie.Get[Flash]([]byte(""), r, cookieName)
	ensure.NotNil(t, err)
	ensure.StringContains(t, err.Error(), "sookie: failed to create AEAD")
}

func TestSetGetSecretMismatch(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set(secret, w, given, http.Cookie{Name: cookieName})
	ensure.Nil(t, err)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	invalidSecret := bytes.Repeat([]byte("a"), len(secret))
	_, err = sookie.Get[Flash](invalidSecret, r, cookieName)
	ensure.NotNil(t, err)
	ensure.StringContains(t, err.Error(), "sookie: failed to decrypt cookie")
}

func TestSetGetUnmarshalMismatch(t *testing.T) {
	w := httptest.NewRecorder()
	err := sookie.Set(secret, w, given, http.Cookie{Name: cookieName})
	ensure.Nil(t, err)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", w.Header().Get("Set-Cookie"))
	_, err = sookie.Get[int](secret, r, cookieName)
	ensure.NotNil(t, err)
	ensure.StringContains(t, err.Error(), "sookie: failed to unmarshal cookie")
}

func TestDelExists(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", cookieName+"=value")
	sookie.Del(w, r, http.Cookie{Name: cookieName})
	ensure.DeepEqual(t, w.Header().Get("Set-Cookie"), cookieName+"=; Max-Age=0")
}

func TestDelMissing(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	sookie.Del(w, r, http.Cookie{Name: cookieName})
	ensure.DeepEqual(t, len(w.Header().Values("Set-Cookie")), 0)
}
