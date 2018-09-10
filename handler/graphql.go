package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/y0ssar1an/q"
	"io"
	"net/http"
	"strings"

	"github.com/99designs/gqlgen/complexity"
	"github.com/99designs/gqlgen/graphql"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/golang-lru"
	"github.com/vektah/gqlparser"
	"github.com/vektah/gqlparser/ast"
	"github.com/vektah/gqlparser/gqlerror"
	"github.com/vektah/gqlparser/validator"
)

var (
	ErrOperationNotFound    = errors.New("operation not found")
	ErrUnsupportedOperation = errors.New("unsupported operation type")
	ErrQueryLimitExceed     = errors.New("unsupported operation type")
	ErrCacheCreation = errors.New("cache creation failed")
)

type params struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName"`
	Variables     map[string]interface{} `json:"variables"`
}

type Config struct {
	cacheSize       int
	upgrader        websocket.Upgrader
	recover         graphql.RecoverFunc
	errorPresenter  graphql.ErrorPresenterFunc
	resolverHook    graphql.FieldMiddleware
	requestHook     graphql.RequestMiddleware
	complexityLimit int
}

func (c *Config) newRequestContext(doc *ast.QueryDocument, query string,
	variables map[string]interface{}) *graphql.RequestContext {

	reqCtx := graphql.NewRequestContext(doc, query, variables)
	if hook := c.recover; hook != nil {
		reqCtx.Recover = hook
	}

	if hook := c.errorPresenter; hook != nil {
		reqCtx.ErrorPresenter = hook
	}

	if hook := c.resolverHook; hook != nil {
		reqCtx.ResolverMiddleware = hook
	}

	if hook := c.requestHook; hook != nil {
		reqCtx.RequestMiddleware = hook
	}

	return reqCtx
}

type Option func(cfg *Config)

func WithConfig(newCfg *Config) Option {
	return func(cfg *Config) {
		cfg = newCfg
	}
}

func WebsocketUpgrader(upgrader websocket.Upgrader) Option {
	return func(cfg *Config) {
		cfg.upgrader = upgrader
	}
}

func RecoverFunc(recover graphql.RecoverFunc) Option {
	return func(cfg *Config) {
		cfg.recover = recover
	}
}

// ErrorPresenter transforms errors found while resolving into errors that will be returned to the user. It provides
// a good place to add any extra fields, like error.type, that might be desired by your frontend. Check the default
// implementation in graphql.DefaultErrorPresenter for an example.
func ErrorPresenter(f graphql.ErrorPresenterFunc) Option {
	return func(cfg *Config) {
		cfg.errorPresenter = f
	}
}

// ComplexityLimit sets a maximum query complexity that is allowed to be executed.
// If a query is submitted that exceeds the limit, a 422 status code will be returned.
func ComplexityLimit(limit int) Option {
	return func(cfg *Config) {
		cfg.complexityLimit = limit
	}
}

// ResolverMiddleware allows you to define a function that will be called around every resolver,
// useful for tracing and logging.
func ResolverMiddleware(middleware graphql.FieldMiddleware) Option {
	return func(cfg *Config) {
		if cfg.resolverHook == nil {
			cfg.resolverHook = middleware
			return
		}

		lastResolve := cfg.resolverHook
		cfg.resolverHook = func(ctx context.Context, next graphql.Resolver) (res interface{}, err error) {
			return lastResolve(ctx, func(ctx context.Context) (res interface{}, err error) {
				return middleware(ctx, next)
			})
		}
	}
}

// RequestMiddleware allows you to define a function that will be called around the root request,
// after the query has been parsed. This is useful for logging and tracing
func RequestMiddleware(middleware graphql.RequestMiddleware) Option {
	return func(cfg *Config) {
		if cfg.requestHook == nil {
			cfg.requestHook = middleware
			return
		}

		lastResolve := cfg.requestHook
		cfg.requestHook = func(ctx context.Context, next func(ctx context.Context) []byte) []byte {
			return lastResolve(ctx, func(ctx context.Context) []byte {
				return middleware(ctx, next)
			})
		}
	}
}

// CacheSize sets the maximum size of the query cache.
// If size is less than or equal to 0, the cache is disabled.
func CacheSize(size int) Option {
	return func(cfg *Config) {
		cfg.cacheSize = size
	}
}

const DefaultCacheSize = 1000

func Exec(ctx context.Context, exec graphql.ExecutableSchema, query, operation string,
	variables map[string]interface{}, options ...Option) (response *graphql.Response, err error) {

	cfg := new(Config)
	for _, option := range options {
		option(cfg)
	}

	var cache *lru.Cache
	if cfg.cacheSize > 0 {
		var err error
		cache, err = lru.New(DefaultCacheSize)
		if err != nil {
			return nil, ErrCacheCreation
		}
	}

	var doc *ast.QueryDocument
	if cache != nil {
		val, ok := cache.Get(query)
		if ok {
			doc = val.(*ast.QueryDocument)
		}
	}

	if doc == nil {
		var qErr gqlerror.List
		doc, qErr = gqlparser.LoadQuery(exec.Schema(), query)
		if len(qErr) > 0 {
			return nil, qErr
		}
		if cache != nil {
			cache.Add(query, doc)
		}
	}

	op := doc.Operations.ForName(operation)
	if op == nil {
		return nil, ErrOperationNotFound
	}

	vars, err := validator.VariableValues(exec.Schema(), op, variables)
	if err != nil {
		return nil, err
	}

	reqCtx := graphql.NewRequestContext(doc, query, vars)
	ctx = graphql.WithRequestContext(ctx, reqCtx)

	defer func() {
		if panicErr := recover(); panicErr != nil {
			err = reqCtx.Recover(ctx, panicErr)
		}
	}()

	if cfg.complexityLimit > 0 {
		queryComplexity := complexity.Calculate(exec, op, vars)
		if queryComplexity > cfg.complexityLimit {
			return nil, ErrQueryLimitExceed
		}
	}

	switch op.Operation {
	case ast.Query:
		return exec.Query(ctx, op), nil
	case ast.Mutation:
		return exec.Mutation(ctx, op), nil
	default:
		return nil, ErrUnsupportedOperation
	}
}

func GraphQL(exec graphql.ExecutableSchema, options ...Option) http.HandlerFunc {
	cfg := Config{
		cacheSize: DefaultCacheSize,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "OPTIONS, GET, POST")
			w.WriteHeader(http.StatusOK)
			return
		}

		if strings.Contains(r.Header.Get("Upgrade"), "websocket") {
			connectWs(exec, w, r, &cfg)
			return
		}

		var reqParams params
		switch r.Method {
		case http.MethodGet:
			reqParams.Query = r.URL.Query().Get("query")
			reqParams.OperationName = r.URL.Query().Get("operationName")

			if variables := r.URL.Query().Get("variables"); variables != "" {
				if err := jsonDecode(strings.NewReader(variables), &reqParams.Variables); err != nil {
					sendErrorf(w, http.StatusBadRequest, "variables could not be decoded")
					return
				}
			}
		case http.MethodPost:
			if err := jsonDecode(r.Body, &reqParams); err != nil {
				sendErrorf(w, http.StatusBadRequest, "json body could not be decoded: "+err.Error())
				return
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		options = append(options, WithConfig(&cfg))

		response, err := Exec(r.Context(), exec, reqParams.Query, reqParams.OperationName, reqParams.Variables, options...)
		if err != nil {
			if err, ok := err.(gqlerror.List); ok && len(err) > 0 {
				sendError(w, http.StatusUnprocessableEntity, err...)
				return
			}

			switch err {
			case ErrUnsupportedOperation:
				sendErrorf(w, http.StatusBadRequest, "unsupported operation type")
			case ErrOperationNotFound:
				sendErrorf(w, http.StatusUnprocessableEntity, "operation not found")
			default :
				sendError(w, http.StatusUnprocessableEntity)
			}
			return
		}

		q.Q(response)

		b, err := json.Marshal(response)
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})
}

func jsonDecode(r io.Reader, val interface{}) error {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	return dec.Decode(val)
}

func sendError(w http.ResponseWriter, code int, errors ...*gqlerror.Error) {
	w.WriteHeader(code)
	b, err := json.Marshal(&graphql.Response{Errors: errors})
	if err != nil {
		panic(err)
	}
	w.Write(b)
}

func sendErrorf(w http.ResponseWriter, code int, format string, args ...interface{}) {
	sendError(w, code, &gqlerror.Error{Message: fmt.Sprintf(format, args...)})
}
