package archive

import (
	"os"
	"path/filepath"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/zstd"
)

func writeParquet[T any](path string, rows []T) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".partial-*.parquet")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := parquet.Write(temp, rows, parquet.Compression(&zstd.Codec{Concurrency: 1})); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func readObservations(path string) ([]Observation, error) { return parquet.ReadFile[Observation](path) }
