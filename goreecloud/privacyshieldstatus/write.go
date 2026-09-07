package privacyshieldstatus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile atomically replaces path with a Privacy Shield status snapshot.
// It uses a separate file boundary from Infrastructure Status and requests
// mode 0600 for temporary and final files.  On platforms where POSIX mode bits
// are not the access-control boundary, the containing directory must use an
// approved native ACL.
func WriteFile(path string, snapshot Snapshot) (err error) {
	if path == "" {
		return fmt.Errorf("Privacy Shield status path is empty")
	}

	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal Privacy Shield status: %w", err)
	}
	payload = append(payload, '\n')

	dir := filepath.Dir(path)
	if err = os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("prepare Privacy Shield status directory: %w", err)
	}

	file, err := os.CreateTemp(dir, ".goreecloud-dns-privacy-status-*")
	if err != nil {
		return fmt.Errorf("create temporary Privacy Shield status file: %w", err)
	}
	tmp := file.Name()
	defer func() { _ = os.Remove(tmp) }()

	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure temporary Privacy Shield status file: %w", err)
	}
	if _, err = file.Write(payload); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temporary Privacy Shield status file: %w", err)
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temporary Privacy Shield status file: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("close temporary Privacy Shield status file: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace Privacy Shield status file: %w", err)
	}

	return nil
}
