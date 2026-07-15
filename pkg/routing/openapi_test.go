package routing

import "testing"

func TestImportExportOpenAPI(t *testing.T) {
	source := []byte(`openapi: 3.1.0
info: {title: Demo, version: 1.0.0}
paths:
  /users/{id}:
    get:
      operationId: get_user
      tags: [users]
`)
	routes, diagnostics, err := ImportOpenAPI(source)
	if err != nil || len(diagnostics) != 0 {
		t.Fatalf("import: routes=%#v diagnostics=%#v err=%v", routes, diagnostics, err)
	}
	if len(routes) != 1 || routes[0].ID != "get_user" || routes[0].Method != "GET" {
		t.Fatalf("routes = %#v", routes)
	}
	if output, err := ExportOpenAPI("Demo", "1.0.0", routes); err != nil || len(output) == 0 {
		t.Fatalf("export: %s %v", output, err)
	}
	if catalog := FormatBCLRouteCatalog("http", routes); len(catalog) == 0 {
		t.Fatal("empty BCL route catalog")
	}
}
