package sarif

// Report represents a SARIF 2.1.0 report.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
type Report struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single run of an analysis tool.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the analysis tool that was run.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes the primary tool component.
type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version,omitempty"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules,omitempty"`
}

// Rule describes a rule used by the tool.
type Rule struct {
	ID               string        `json:"id"`
	Name             string        `json:"name,omitempty"`
	ShortDescription Message       `json:"shortDescription,omitempty"`
	FullDescription  Message       `json:"fullDescription,omitempty"`
	HelpURI          string        `json:"helpUri,omitempty"`
	DefaultConfig    DefaultConfig `json:"defaultConfiguration,omitempty"`
}

// DefaultConfig contains default rule configuration.
type DefaultConfig struct {
	Level string `json:"level,omitempty"`
}

// Message represents a localizable string.
type Message struct {
	Text string `json:"text"`
}

// Result represents a single finding.
type Result struct {
	RuleID    string     `json:"ruleId"`
	RuleIndex int        `json:"ruleIndex,omitempty"`
	Level     string     `json:"level"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations,omitempty"`
}

// Location represents where a result was found.
type Location struct {
	PhysicalLocation PhysicalLocation  `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

// PhysicalLocation represents a file location.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation,omitempty"`
}

// ArtifactLocation represents the location of an artifact.
type ArtifactLocation struct {
	URI string `json:"uri,omitempty"`
}

// LogicalLocation represents a logical location such as a package.
type LogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}
