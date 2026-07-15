package reload

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oarkflow/rules"
)

type Watcher struct {
	Service  *rules.Service
	Interval time.Duration
}

func (w Watcher) Watch(ctx context.Context, req rules.ReloadRequest, onReload func(*rules.ReloadResponse)) error {
	if w.Service == nil {
		return nil
	}
	root, err := w.rootPath(ctx, req)
	if err != nil {
		return err
	}
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("reload path %q is a directory", root)
	}

	debounce := time.Duration(req.DebounceMillis) * time.Millisecond
	if debounce <= 0 {
		debounce = w.Interval
	}
	if debounce <= 0 {
		debounce = 250 * time.Millisecond
	}
	watchReq := req
	watchReq.Path = root
	includeImports := watchReq.IncludeImports == nil || *watchReq.IncludeImports
	pollInterval := w.Interval
	if pollInterval <= 0 {
		pollInterval = 50 * time.Millisecond
	}
	snapshotFiles := func() map[string]time.Time {
		if includeImports {
			return snapshotBCLFiles(filepath.Dir(root))
		}
		return snapshotBCLFile(root)
	}
	snapshot := snapshotFiles()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	var timer *time.Timer
	var timerC <-chan time.Time
	pending := root
	fire := func(changed string) {
		reloadReq := watchReq
		resp, _ := w.Service.Reload(ctx, reloadReq)
		if resp != nil {
			resp.ChangedPath = firstNonEmpty(changed, root)
			resp.DependencyPath = firstNonEmpty(changed, root)
		}
		if onReload != nil {
			onReload(resp)
		}
	}
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ctx.Err()
		case <-ticker.C:
			current := snapshotFiles()
			changed, nextSnapshot := changedBCLPath(current, snapshot)
			snapshot = nextSnapshot
			if changed == "" {
				continue
			}
			pending = changed
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(debounce)
			} else {
				timer = time.NewTimer(debounce)
			}
			timerC = timer.C
		case <-timerC:
			timerC = nil
			fire(pending)
		}
	}
}

func (w Watcher) rootPath(ctx context.Context, req rules.ReloadRequest) (string, error) {
	if req.Path != "" {
		return req.Path, nil
	}
	if req.Name == "" {
		return "", fmt.Errorf("reload watch requires definition name or path")
	}
	record, err := w.Service.GetDefinition(ctx, req.Name)
	if err != nil {
		return "", err
	}
	if record.SourcePath == "" {
		return "", fmt.Errorf("definition %q was published from source and cannot be file-watched", req.Name)
	}
	return record.SourcePath, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func snapshotBCLFiles(root string) map[string]time.Time {
	out := map[string]time.Time{}
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(path) != ".bcl" {
			return nil
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return nil
		}
		out[path] = info.ModTime()
		return nil
	})
	return out
}

func snapshotBCLFile(path string) map[string]time.Time {
	out := map[string]time.Time{}
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		out[path] = info.ModTime()
	}
	return out
}

func changedBCLPath(current, previous map[string]time.Time) (string, map[string]time.Time) {
	var changed string
	for path, mod := range current {
		if previous[path].IsZero() || mod.After(previous[path]) {
			if changed == "" || path < changed {
				changed = path
			}
		}
	}
	if changed == "" {
		for path := range previous {
			if _, ok := current[path]; !ok {
				if changed == "" || path < changed {
					changed = path
				}
			}
		}
	}
	return changed, current
}
