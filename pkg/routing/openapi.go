package routing

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var openAPIMethods = map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true, "options": true, "trace": true}

// ImportOpenAPI converts OpenAPI 3 path operations into a Condition route
// catalog. operationId is preferred as the stable route ID.
func ImportOpenAPI(data []byte) ([]Route, []Diagnostic, error) {
	var document map[string]any
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, nil, err
	}
	paths, ok := document["paths"].(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("OpenAPI document has no paths object")
	}
	var routes []Route
	seenIDs := map[string]int{}
	for path, rawPath := range paths {
		pathItem, _ := rawPath.(map[string]any)
		for method, rawOperation := range pathItem {
			method = strings.ToLower(method)
			if !openAPIMethods[method] {
				continue
			}
			operation, _ := rawOperation.(map[string]any)
			id := strings.TrimSpace(fmt.Sprint(operation["operationId"]))
			if id == "" || id == "<nil>" {
				id = routeIDFromOperation(method, path)
			}
			seenIDs[id]++
			if seenIDs[id] > 1 {
				id = fmt.Sprintf("%s_%d", id, seenIDs[id])
			}
			metadata := map[string]any{"openapi_operation_id": operation["operationId"]}
			if tags, ok := operation["tags"].([]any); ok {
				metadata["tags"] = tags
			}
			if extension, ok := operation["x-condition"].(map[string]any); ok {
				for key, value := range extension {
					metadata[key] = value
				}
			}
			routes = append(routes, Route{ID: id, Method: strings.ToUpper(method), Pattern: path, Metadata: metadata})
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Pattern == routes[j].Pattern {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Pattern < routes[j].Pattern
	})
	return routes, Analyze(routes), nil
}

func ExportOpenAPI(title, version string, routes []Route) ([]byte, error) {
	if title == "" {
		title = "Condition routes"
	}
	if version == "" {
		version = "1.0.0"
	}
	paths := map[string]any{}
	for _, route := range routes {
		pathItem, _ := paths[route.Pattern].(map[string]any)
		if pathItem == nil {
			pathItem = map[string]any{}
			paths[route.Pattern] = pathItem
		}
		pathItem[strings.ToLower(route.Method)] = map[string]any{"operationId": route.ID, "x-condition": route.Metadata, "responses": map[string]any{"200": map[string]any{"description": "Policy-controlled response"}}}
	}
	document := map[string]any{"openapi": "3.1.0", "info": map[string]any{"title": title, "version": version}, "paths": paths}
	return json.MarshalIndent(document, "", "  ")
}

func FormatBCLRouteCatalog(catalogID string, routes []Route) string {
	if catalogID == "" {
		catalogID = "http"
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "routes %s {\n", strconv.Quote(catalogID))
	for _, route := range routes {
		fmt.Fprintf(&builder, "  route %s {\n    method %s\n    pattern %s\n", strconv.Quote(route.ID), strconv.Quote(strings.ToUpper(route.Method)), strconv.Quote(route.Pattern))
		if len(route.Metadata) > 0 {
			builder.WriteString("    metadata {\n")
			keys := make([]string, 0, len(route.Metadata))
			for key := range route.Metadata {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				switch value := route.Metadata[key].(type) {
				case string:
					if value != "" {
						fmt.Fprintf(&builder, "      %s %s\n", key, strconv.Quote(value))
					}
				case bool, int, int64, float64:
					fmt.Fprintf(&builder, "      %s %v\n", key, value)
				}
			}
			builder.WriteString("    }\n")
		}
		builder.WriteString("  }\n")
	}
	builder.WriteString("}\n")
	return builder.String()
}

func routeIDFromOperation(method, path string) string {
	value := strings.ToLower(method + "_" + path)
	value = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, value)
	return strings.Trim(value, "_")
}
