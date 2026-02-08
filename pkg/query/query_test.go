package query

import (
	"testing"
)

func TestOutputFormatString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		format OutputFormat
		want   string
	}{
		{FormatJSON, "json"},
		{FormatSARIF, "sarif"},
		{OutputFormat(99), "json"}, // unknown defaults to json
	}

	for _, tc := range tests {
		got := tc.format.String()
		if got != tc.want {
			t.Errorf("OutputFormat(%d).String() = %s, want %s", tc.format, got, tc.want)
		}
	}
}

func TestParseOutputFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  OutputFormat
	}{
		{"json", FormatJSON},
		{"JSON", FormatJSON},
		{"sarif", FormatSARIF},
		{"SARIF", FormatSARIF},
		{"Sarif", FormatSARIF},
		{"unknown", FormatJSON},
		{"", FormatJSON},
	}

	for _, tc := range tests {
		got := ParseOutputFormat(tc.input)
		if got != tc.want {
			t.Errorf("ParseOutputFormat(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestQueryString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		query Query
		want  string
	}{
		{Undefined, "undefined"},
		{Images, "images"},
		{Digests, "digests"},
		{Exposure, "exposure"},
		{Packages, "packages"},
		{TimeSeries, "timeseries"},
		{CommonVulns, "common"},
	}

	for _, tc := range tests {
		got := tc.query.String()
		if got != tc.want {
			t.Errorf("Query(%d).String() = %s, want %s", tc.query, got, tc.want)
		}
	}
}

func TestOptionsGetQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts Options
		want Query
	}{
		{
			name: "explicit query type",
			opts: Options{QueryType: TimeSeries},
			want: TimeSeries,
		},
		{
			name: "cross-image query",
			opts: Options{Images: []string{"image1", "image2"}},
			want: CommonVulns,
		},
		{
			name: "time-series with date range",
			opts: Options{StartDate: "2024-01-01"},
			want: TimeSeries,
		},
		{
			name: "no filters returns images",
			opts: Options{},
			want: Images,
		},
		{
			name: "image only returns digests",
			opts: Options{Image: "docker.io/redis"},
			want: Digests,
		},
		{
			name: "image and digest returns exposure",
			opts: Options{Image: "docker.io/redis", Digest: "sha256:abc"},
			want: Exposure,
		},
		{
			name: "all filters returns packages",
			opts: Options{Image: "docker.io/redis", Digest: "sha256:abc", Exposure: "CVE-2021-44228"},
			want: Packages,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := tc.opts.GetQuery()
			if err != nil {
				t.Fatalf("GetQuery() error: %v", err)
			}
			if got != tc.want {
				t.Errorf("GetQuery() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOptionsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{
			name:    "empty options valid",
			opts:    Options{},
			wantErr: false,
		},
		{
			name:    "with image",
			opts:    Options{Image: "docker.io/redis"},
			wantErr: false,
		},
		{
			name:    "with target",
			opts:    Options{Target: "sqlite://test.db"},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.opts.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestOptionsValidateExtractsDigest(t *testing.T) {
	t.Parallel()

	opts := Options{
		Image: "docker.io/redis@sha256:abc123",
	}

	err := opts.Validate()
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	if opts.Image != "docker.io/redis" {
		t.Errorf("Image = %s, want docker.io/redis", opts.Image)
	}
	if opts.Digest != "sha256:abc123" {
		t.Errorf("Digest = %s, want sha256:abc123", opts.Digest)
	}
}

func TestOptionsValidateSetsDefaultTarget(t *testing.T) {
	t.Parallel()

	opts := Options{}
	err := opts.Validate()
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	if opts.Target == "" {
		t.Error("Validate() should set default target")
	}
}

func TestOptionsString(t *testing.T) {
	t.Parallel()

	opts := Options{
		Image:     "docker.io/redis",
		Digest:    "sha256:abc",
		Exposure:  "CVE-2021-44228",
		Target:    "sqlite://test.db",
		DiffsOnly: true,
	}

	got := opts.String()
	if got == "" {
		t.Error("String() returned empty string")
	}

	// Should contain key values
	if !containsStr(got, "docker.io/redis") {
		t.Errorf("String() should contain image, got %s", got)
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
