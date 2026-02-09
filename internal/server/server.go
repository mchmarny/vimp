package server

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	// sqlite3 driver
	_ "modernc.org/sqlite"
)

//go:embed assets/static/* assets/templates/*
var assets embed.FS

// Config contains server configuration.
type Config struct {
	Port    int
	Target  string
	Version string
}

// Server represents the HTTP server for the dashboard.
type Server struct {
	config  *Config
	db      *sql.DB
	queries *Queries
	tmpl    *template.Template
	mux     *http.ServeMux
	server  *http.Server
}

// New creates a new Server instance.
func New(cfg *Config) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 8080
	}
	if cfg.Target == "" {
		return nil, errors.New("target database is required")
	}

	// Remove driver prefix if present
	dbPath := strings.TrimPrefix(cfg.Target, "sqlite://")

	db, err := sql.Open("sqlite", fmt.Sprintf("%s?parseTime=true", dbPath))
	if err != nil {
		return nil, errors.Wrap(err, "failed to open database")
	}

	// Test connection - use Ping without context since New() doesn't have ctx
	//nolint:noctx // New() doesn't receive context, ping is quick validation
	if pingErr := db.Ping(); pingErr != nil {
		return nil, errors.Wrap(pingErr, "failed to connect to database")
	}

	// Parse templates with custom functions
	funcMap := template.FuncMap{
		"shortDigest": func(d string) string {
			if len(d) > 19 {
				return d[:19] + "..."
			}
			return d
		},
		"shortImage": func(img string) string {
			if len(img) > 50 {
				return "..." + img[len(img)-47:]
			}
			return img
		},
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "N/A"
			}
			return t.Format("2006-01-02 15:04")
		},
		"formatScore": func(s float32) string {
			return fmt.Sprintf("%.1f", s)
		},
		"severityClass": func(s string) string {
			switch strings.ToLower(s) {
			case "critical":
				return "severity-critical"
			case "high":
				return "severity-high"
			case "medium":
				return "severity-medium"
			case "low":
				return "severity-low"
			default:
				return "severity-unknown"
			}
		},
		"add": func(a, b int) int {
			return a + b
		},
	}

	tmpl, err := template.New("").Funcs(funcMap).ParseFS(assets,
		"assets/templates/*.html",
		"assets/templates/components/*.html")
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse templates")
	}

	s := &Server{
		config:  cfg,
		db:      db,
		queries: NewQueries(db),
		tmpl:    tmpl,
		mux:     http.NewServeMux(),
	}

	s.setupRoutes()

	return s, nil
}

// setupRoutes configures the HTTP routes.
func (s *Server) setupRoutes() {
	// Static files - panic on error since this is critical setup
	staticFS, err := fs.Sub(assets, "assets/static")
	if err != nil {
		panic("failed to load embedded static assets: " + err.Error())
	}
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Pages
	s.mux.HandleFunc("GET /", s.handleDashboard)
	s.mux.HandleFunc("GET /images", s.handleImages)
	s.mux.HandleFunc("GET /images/{image...}", s.handleImageDetail)

	// API endpoints (JSON)
	s.mux.HandleFunc("GET /api/stats", s.handleAPIStats)
	s.mux.HandleFunc("GET /api/images", s.handleAPIImages)
	s.mux.HandleFunc("GET /api/images/{image...}", s.handleAPIImageDetail)
	s.mux.HandleFunc("GET /api/timeseries/{image...}", s.handleAPITimeSeries)

	// HTMX partials
	s.mux.HandleFunc("GET /partials/images", s.handlePartialImages)
	s.mux.HandleFunc("GET /partials/recent", s.handlePartialRecent)
}

// Start starts the HTTP server.
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.config.Port)

	s.server = &http.Server{
		Addr:              addr,
		Handler:           s.logMiddleware(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
	}

	slog.Info("starting server", "addr", fmt.Sprintf("http://localhost%s", addr))

	errCh := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down server")
		// Use Background() intentionally - the parent ctx is already canceled
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second) //nolint:contextcheck // shutdown needs fresh context
		defer cancel()
		return s.server.Shutdown(shutdownCtx) //nolint:contextcheck // shutdownCtx is derived from Background
	case err := <-errCh:
		return err
	}
}

// Close closes the server and database connection.
func (s *Server) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// logMiddleware logs HTTP requests.
func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start))
	})
}

// Addr returns the server address (for testing).
func (s *Server) Addr() string {
	if s.server != nil {
		return s.server.Addr
	}
	return fmt.Sprintf(":%d", s.config.Port)
}

// DB returns the database connection (for testing).
func (s *Server) DB() *sql.DB {
	return s.db
}
