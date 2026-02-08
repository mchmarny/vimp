// Package parser provides JSON parsing utilities for scanner output.
//
// Built on gabs for flexible JSON traversal, the package provides
// type-safe extraction functions:
//   - ToString: safely extract string values
//   - ToFloat32: safely extract float32 values
//   - ToBool: safely extract boolean values
//   - Children: safely iterate over array elements
//
// These functions handle missing or malformed data gracefully,
// returning zero values rather than panicking.
//
// Example usage:
//
//	container, _ := gabs.ParseJSON(data)
//	name := parser.ToString(container.Search("package", "name").Data())
//	score := parser.ToFloat32(container.Search("cvss", "score").Data())
package parser
