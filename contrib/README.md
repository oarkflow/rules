# Rules contrib storage

This nested Go module provides SQL implementations of `github.com/oarkflow/rules/pkg/storage.Store` using `github.com/oarkflow/squealx` and its SQLite and PostgreSQL drivers.

```go
import contribstorage "github.com/oarkflow/rules/contrib/storage"

sqliteStore, err := contribstorage.NewSQLiteStore("rules.db")
postgresStore, err := contribstorage.NewPostgresStore(os.Getenv("DATABASE_URL"))
```

Both stores should be closed when no longer needed. Tenant contexts and record types are aliases or forwards to the core storage package, so either package can be used with the returned stores.

## Storage conformance checks

Run the SQLite adapter suite with:

```sh
go test ./...
```

The PostgreSQL conformance test is opt-in and uses an isolated tenant namespace. Point it at a disposable test database with:

```sh
RULES_POSTGRES_TEST_DSN="$DATABASE_URL" go test ./storage -run TestPostgresStoreStateRetentionConformance -count=1
```

The test creates tables through the normal migrations and leaves its uniquely scoped test records in the database. Use a disposable database for this check.
