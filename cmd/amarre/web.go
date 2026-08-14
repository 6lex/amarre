package main

import (
	"log/slog"
	"net/http"

	"github.com/6lex/amarre/internal/collector"
	"github.com/6lex/amarre/internal/config"
	"github.com/6lex/amarre/internal/store"
	"github.com/6lex/amarre/internal/web"
)

func newWebHandler(cfg *config.Config, st *store.Store, col *collector.Collector, log *slog.Logger) (http.Handler, error) {
	s, err := web.NewServer(cfg, st, col, log)
	if err != nil {
		return nil, err
	}
	return s.Handler(), nil
}
