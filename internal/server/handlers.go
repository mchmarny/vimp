package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// PageData contains common data for all pages.
type PageData struct {
	Title   string
	Version string
	Target  string
}

// DashboardData contains data for the dashboard page.
type DashboardData struct {
	PageData
	Stats      *DashboardStats
	Registries []*RegistryStat
	Recent     []*RecentImage
}

// ImagesData contains data for the images page.
type ImagesData struct {
	PageData
	Images []*RecentImage
	Search string
	Total  int
}

// ImageDetailData contains data for the image detail page.
type ImageDetailData struct {
	PageData
	Detail     *ImageDetail
	TimeSeries []*TimeSeriesPoint
}

// ExposuresData contains data for the exposures page.
type ExposuresData struct {
	PageData
	Image     string
	Digest    string
	Exposures []*ExposureInfo
	Total     int
}

// handleDashboard renders the main dashboard.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := s.queries.GetDashboardStats(ctx)
	if err != nil {
		slog.Error("failed to get dashboard stats", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	registries, err := s.queries.GetRegistryStats(ctx, 5)
	if err != nil {
		slog.Error("failed to get registry stats", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	recent, err := s.queries.GetRecentImages(ctx, 10)
	if err != nil {
		slog.Error("failed to get recent images", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := &DashboardData{
		PageData: PageData{
			Title:   "Dashboard",
			Version: s.config.Version,
			Target:  s.config.Target,
		},
		Stats:      stats,
		Registries: registries,
		Recent:     recent,
	}

	if err := s.tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		slog.Error("failed to render dashboard", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleImages renders the images list page.
func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	search := r.URL.Query().Get("search")
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	var images []*RecentImage
	var err error

	if search != "" {
		images, err = s.queries.SearchImages(ctx, search, limit)
	} else {
		images, err = s.queries.GetRecentImages(ctx, limit)
	}

	if err != nil {
		slog.Error("failed to get images", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := &ImagesData{
		PageData: PageData{
			Title:   "Images",
			Version: s.config.Version,
			Target:  s.config.Target,
		},
		Images: images,
		Search: search,
		Total:  len(images),
	}

	// Check if this is an HTMX request
	if r.Header.Get("HX-Request") == "true" {
		if err := s.tmpl.ExecuteTemplate(w, "image-table", data); err != nil {
			slog.Error("failed to render image table", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	if err := s.tmpl.ExecuteTemplate(w, "images.html", data); err != nil {
		slog.Error("failed to render images", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleImageDetail renders the image detail page.
func (s *Server) handleImageDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get image from path - handle URL encoding and @ separator
	imagePath := unescapePath(r.PathValue("image"))

	// Check if digest is included (image@digest or image/digest format in query)
	digest := r.URL.Query().Get("digest")
	if digest == "" && strings.Contains(imagePath, "@") {
		parts := strings.SplitN(imagePath, "@", 2)
		imagePath = parts[0]
		digest = parts[1]
	}

	// If we have a digest, show exposures
	if digest != "" {
		exposures, err := s.queries.GetExposures(ctx, imagePath, digest)
		if err != nil {
			slog.Error("failed to get exposures", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		data := &ExposuresData{
			PageData: PageData{
				Title:   "Exposures - " + imagePath,
				Version: s.config.Version,
				Target:  s.config.Target,
			},
			Image:     imagePath,
			Digest:    digest,
			Exposures: exposures,
			Total:     len(exposures),
		}

		if err := s.tmpl.ExecuteTemplate(w, "exposures.html", data); err != nil {
			slog.Error("failed to render exposures", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Show image detail with all digests
	detail, err := s.queries.GetImageDetail(ctx, imagePath)
	if err != nil {
		slog.Error("failed to get image detail", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	timeSeries, err := s.queries.GetTimeSeries(ctx, imagePath)
	if err != nil {
		slog.Error("failed to get time series", "error", err)
		// Don't fail the whole page for time series
		timeSeries = []*TimeSeriesPoint{}
	}

	data := &ImageDetailData{
		PageData: PageData{
			Title:   "Image - " + imagePath,
			Version: s.config.Version,
			Target:  s.config.Target,
		},
		Detail:     detail,
		TimeSeries: timeSeries,
	}

	if err := s.tmpl.ExecuteTemplate(w, "image.html", data); err != nil {
		slog.Error("failed to render image detail", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handlePartialImages handles HTMX partial request for images table.
func (s *Server) handlePartialImages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	search := r.URL.Query().Get("search")
	limit := 50

	var images []*RecentImage
	var err error

	if search != "" {
		images, err = s.queries.SearchImages(ctx, search, limit)
	} else {
		images, err = s.queries.GetRecentImages(ctx, limit)
	}

	if err != nil {
		slog.Error("failed to get images", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := &ImagesData{
		Images: images,
		Search: search,
		Total:  len(images),
	}

	if err := s.tmpl.ExecuteTemplate(w, "image-table", data); err != nil {
		slog.Error("failed to render image table", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handlePartialRecent handles HTMX partial request for recent images.
func (s *Server) handlePartialRecent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	recent, err := s.queries.GetRecentImages(ctx, 10)
	if err != nil {
		slog.Error("failed to get recent images", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := &DashboardData{
		Recent: recent,
	}

	if err := s.tmpl.ExecuteTemplate(w, "recent-table", data); err != nil {
		slog.Error("failed to render recent table", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleAPIStats returns dashboard stats as JSON.
func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := s.queries.GetDashboardStats(ctx)
	if err != nil {
		slog.Error("failed to get stats", "error", err)
		writeJSONError(w, "Failed to get stats", http.StatusInternalServerError)
		return
	}

	writeJSON(w, stats)
}

// handleAPIImages returns images as JSON.
func (s *Server) handleAPIImages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	search := r.URL.Query().Get("search")
	limit := 50

	var images []*RecentImage
	var err error

	if search != "" {
		images, err = s.queries.SearchImages(ctx, search, limit)
	} else {
		images, err = s.queries.GetRecentImages(ctx, limit)
	}

	if err != nil {
		slog.Error("failed to get images", "error", err)
		writeJSONError(w, "Failed to get images", http.StatusInternalServerError)
		return
	}

	writeJSON(w, images)
}

// handleAPIImageDetail returns image detail as JSON.
func (s *Server) handleAPIImageDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	imagePath := unescapePath(r.PathValue("image"))

	digest := r.URL.Query().Get("digest")
	if strings.Contains(imagePath, "@") {
		parts := strings.SplitN(imagePath, "@", 2)
		imagePath = parts[0]
		digest = parts[1]
	}

	if digest != "" {
		exposures, err := s.queries.GetExposures(ctx, imagePath, digest)
		if err != nil {
			slog.Error("failed to get exposures", "error", err)
			writeJSONError(w, "Failed to get exposures", http.StatusInternalServerError)
			return
		}
		writeJSON(w, exposures)
		return
	}

	detail, err := s.queries.GetImageDetail(ctx, imagePath)
	if err != nil {
		slog.Error("failed to get image detail", "error", err)
		writeJSONError(w, "Failed to get image detail", http.StatusInternalServerError)
		return
	}

	writeJSON(w, detail)
}

// handleAPITimeSeries returns time series data as JSON.
func (s *Server) handleAPITimeSeries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	imagePath := unescapePath(r.PathValue("image"))

	timeSeries, err := s.queries.GetTimeSeries(ctx, imagePath)
	if err != nil {
		slog.Error("failed to get time series", "error", err)
		writeJSONError(w, "Failed to get time series", http.StatusInternalServerError)
		return
	}

	writeJSON(w, timeSeries)
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode JSON", "error", err)
	}
}

// writeJSONError writes a JSON error response.
//
//nolint:unparam // code kept for future use with different status codes
func writeJSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		slog.Error("failed to encode error response", "error", err)
	}
}

// unescapePath safely unescapes a URL path, logging any errors.
func unescapePath(path string) string {
	unescaped, err := url.PathUnescape(path)
	if err != nil {
		slog.Warn("failed to unescape path", "path", path, "error", err)
		return path // Return original on error
	}
	return unescaped
}
