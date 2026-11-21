package langstrothauth

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
)

func httptestNewRequest(method, target, form string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func itoa(i int) string { return strconv.Itoa(i) }
