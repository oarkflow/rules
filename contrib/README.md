# Rules contrib storage

This nested Go module provides SQL implementations of `github.com/oarkflow/rules/pkg/storage.Store` using `github.com/oarkflow/squealx` and its SQLite and PostgreSQL drivers.

```go
import contribstorage "github.com/oarkflow/rules/contrib/storage"

sqliteStore, err := contribstorage.NewSQLiteStore("rules.db")
postgresStore, err := contribstorage.NewPostgresStore(os.Getenv("DATABASE_URL"))
```

Both stores should be closed when no longer needed. Tenant contexts and record types are aliases or forwards to the core storage package, so either package can be used with the returned stores.
