package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandlerPOST(t *testing.T) {
	h := GraphQL(&executableSchemaStub{})

	t.Run("success", func(t *testing.T) {
		resp := doRequest(t, h, "POST", "/graphql", `{"query":"{ me { name } }"}`)
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, `{"data":{"name":"test"}}`, resp.Body.String())
	})

	t.Run("query caching", func(t *testing.T) {
		// Run enough unique queries to evict a bunch of them
		for i := 0; i < 2000; i++ {
			query := `{"query":"` + strings.Repeat(" ", i) + "{ me { name } }" + `"}`
			resp := doRequest(h, "POST", "/graphql", query)
			assert.Equal(t, http.StatusOK, resp.Code)
			assert.Equal(t, `{"data":{"name":"test"}}`, resp.Body.String())
		}

		t.Run("evicted queries run", func(t *testing.T) {
			query := `{"query":"` + strings.Repeat(" ", 0) + "{ me { name } }" + `"}`
			resp := doRequest(h, "POST", "/graphql", query)
			assert.Equal(t, http.StatusOK, resp.Code)
			assert.Equal(t, `{"data":{"name":"test"}}`, resp.Body.String())
		})

		t.Run("non-evicted queries run", func(t *testing.T) {
			query := `{"query":"` + strings.Repeat(" ", 1999) + "{ me { name } }" + `"}`
			resp := doRequest(h, "POST", "/graphql", query)
			assert.Equal(t, http.StatusOK, resp.Code)
			assert.Equal(t, `{"data":{"name":"test"}}`, resp.Body.String())
		})
	})

	t.Run("decode failure", func(t *testing.T) {
		resp := doRequest(t, h, "POST", "/graphql", "notjson")
		assert.Equal(t, http.StatusBadRequest, resp.Code)
		assert.Equal(t, `{"data":null,"errors":[{"message":"json body could not be decoded: invalid character 'o' in literal null (expecting 'u')"}]}`, resp.Body.String())
	})

	t.Run("parse failure", func(t *testing.T) {
		resp := doRequest(t, h, "POST", "/graphql", `{"query": "!"}`)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"data":null,"errors":[{"message":"Unexpected !","locations":[{"line":1,"column":1}]}]}`, resp.Body.String())
	})

	t.Run("validation failure", func(t *testing.T) {
		resp := doRequest(t, h, "POST", "/graphql", `{"query": "{ me { title }}"}`)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"data":null,"errors":[{"message":"Cannot query field \"title\" on type \"User\".","locations":[{"line":1,"column":8}]}]}`, resp.Body.String())
	})

	t.Run("invalid variable", func(t *testing.T) {
		resp := doRequest(t, h, "POST", "/graphql", `{"query": "query($id:Int!){user(id:$id){name}}","variables":{"id":false}}`)
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"data":null,"errors":[{"message":"cannot use bool as Int","path":["variable","id"]}]}`, resp.Body.String())
	})

	t.Run("execution failure", func(t *testing.T) {
		resp := doRequest(t, h, "POST", "/graphql", `{"query": "mutation { me { name } }"}`)
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, `{"data":null,"errors":[{"message":"mutations are not supported"}]}`, resp.Body.String())
	})
}

func TestHandlerGET(t *testing.T) {
	h := GraphQL(&executableSchemaStub{})

	t.Run("success", func(t *testing.T) {
		resp := doRequest(t, h, "GET", "/graphql?query={me{name}}", ``)
		assert.Equal(t, http.StatusOK, resp.Code)
		assert.Equal(t, `{"data":{"name":"test"}}`, resp.Body.String())
	})

	t.Run("decode failure", func(t *testing.T) {
		resp := doRequest(t, h, "GET", "/graphql?query=me{id}&variables=notjson", "")
		assert.Equal(t, http.StatusBadRequest, resp.Code)
		assert.Equal(t, `{"data":null,"errors":[{"message":"variables could not be decoded"}]}`, resp.Body.String())
	})

	t.Run("invalid variable", func(t *testing.T) {
		resp := doRequest(t, h, "GET", `/graphql?query=query($id:Int!){user(id:$id){name}}&variables={"id":false}`, "")
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"data":null,"errors":[{"message":"cannot use bool as Int","path":["variable","id"]}]}`, resp.Body.String())
	})

	t.Run("parse failure", func(t *testing.T) {
		resp := doRequest(t, h, "GET", "/graphql?query=!", "")
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"data":null,"errors":[{"message":"Unexpected !","locations":[{"line":1,"column":1}]}]}`, resp.Body.String())
	})

	t.Run("no mutations", func(t *testing.T) {
		resp := doRequest(t, h, "GET", "/graphql?query=mutation{me{name}}", "")
		assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)
		assert.Equal(t, `{"data":null,"errors":[{"message":"GET requests only allow query operations"}]}`, resp.Body.String())
	})
}

func TestHandlerOptions(t *testing.T) {
	h := GraphQL(&executableSchemaStub{})

	resp := doRequest(t, h, "OPTIONS", "/graphql?query={me{name}}", ``)
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "OPTIONS, GET, POST", resp.HeaderMap.Get("Allow"))
}

func TestHandlerHead(t *testing.T) {
	h := GraphQL(&executableSchemaStub{})

	resp := doRequest(t, h, "HEAD", "/graphql?query={me{name}}", ``)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.Code)
}

func doRequest(t *testing.T, handler http.Handler, method string, target string, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)
	return w
}
