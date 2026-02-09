package registry

import (
	"context"
	"testing"
	"time"
)

func TestDiscoverTags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tests := []struct {
		name      string
		imageRef  string
		count     int
		wantErr   bool
		wantCount int
	}{
		{
			name:      "alpine with tag",
			imageRef:  "alpine:latest",
			count:     3,
			wantErr:   false,
			wantCount: 3,
		},
		{
			name:      "alpine without tag",
			imageRef:  "alpine",
			count:     5,
			wantErr:   false,
			wantCount: 5,
		},
		{
			name:      "count of 1",
			imageRef:  "alpine",
			count:     1,
			wantErr:   false,
			wantCount: 1,
		},
		{
			name:     "invalid count",
			imageRef: "alpine",
			count:    0,
			wantErr:  true,
		},
		{
			name:     "invalid image reference",
			imageRef: "not a valid ref!!!",
			count:    5,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags, err := DiscoverTags(ctx, tt.imageRef, tt.count)
			if (err != nil) != tt.wantErr {
				t.Errorf("DiscoverTags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(tags) != tt.wantCount {
				t.Errorf("DiscoverTags() returned %d tags, want %d", len(tags), tt.wantCount)
			}
		})
	}
}

func TestSortTagsBySemver(t *testing.T) {
	tests := []struct {
		name string
		tags []string
		want []string
	}{
		{
			name: "semver tags",
			tags: []string{"v1.0.0", "v1.2.0", "v1.1.0", "v2.0.0"},
			want: []string{"v2.0.0", "v1.2.0", "v1.1.0", "v1.0.0"},
		},
		{
			name: "semver without v prefix",
			tags: []string{"1.0.0", "1.2.0", "1.1.0", "2.0.0"},
			want: []string{"2.0.0", "1.2.0", "1.1.0", "1.0.0"},
		},
		{
			name: "mixed semver and non-semver",
			tags: []string{"latest", "v1.0.0", "v2.0.0", "edge"},
			want: []string{"v2.0.0", "v1.0.0", "latest", "edge"},
		},
		{
			name: "non-semver only",
			tags: []string{"latest", "edge", "stable", "alpine"},
			want: []string{"stable", "latest", "edge", "alpine"},
		},
		{
			name: "prerelease versions",
			tags: []string{"v1.0.0", "v1.0.0-rc1", "v1.0.0-beta", "v1.0.0-alpha"},
			want: []string{"v1.0.0", "v1.0.0-rc1", "v1.0.0-beta", "v1.0.0-alpha"},
		},
		{
			name: "empty slice",
			tags: []string{},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortTagsBySemver(tt.tags)
			if len(got) != len(tt.want) {
				t.Errorf("sortTagsBySemver() returned %d items, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("sortTagsBySemver()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestBuildImageURIs(t *testing.T) {
	tests := []struct {
		name    string
		baseRef string
		tags    []string
		want    []string
		wantErr bool
	}{
		{
			name:    "simple image with tags",
			baseRef: "alpine:latest",
			tags:    []string{"3.18", "3.19", "3.20"},
			want:    []string{"index.docker.io/library/alpine:3.18", "index.docker.io/library/alpine:3.19", "index.docker.io/library/alpine:3.20"},
			wantErr: false,
		},
		{
			name:    "ghcr image",
			baseRef: "ghcr.io/repo/image:v1",
			tags:    []string{"v1.0.0", "v1.1.0"},
			want:    []string{"ghcr.io/repo/image:v1.0.0", "ghcr.io/repo/image:v1.1.0"},
			wantErr: false,
		},
		{
			name:    "empty tags",
			baseRef: "alpine",
			tags:    []string{},
			want:    []string{},
			wantErr: false,
		},
		{
			name:    "invalid base reference",
			baseRef: "not valid!!!",
			tags:    []string{"v1"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildImageURIs(tt.baseRef, tt.tags)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildImageURIs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("BuildImageURIs() returned %d items, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("BuildImageURIs()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		tag  string
		want string
	}{
		{"v1.0.0", "v1.0.0"},
		{"1.0.0", "v1.0.0"},
		{"latest", "vlatest"},
		{"", "v"},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			if got := normalizeVersion(tt.tag); got != tt.want {
				t.Errorf("normalizeVersion(%q) = %q, want %q", tt.tag, got, tt.want)
			}
		})
	}
}
