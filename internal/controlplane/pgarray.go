package controlplane

import (
	"database/sql/driver"

	"github.com/lib/pq"
)

// stringArray scans and writes Postgres text[].
type stringArray []string

func (a *stringArray) Scan(src any) error {
	var s pq.StringArray
	if err := s.Scan(src); err != nil {
		return err
	}
	*a = stringArray(s)
	return nil
}

// Value writes an empty array (not NULL) for a nil slice.
func (a stringArray) Value() (driver.Value, error) {
	if a == nil {
		return "{}", nil
	}
	return pq.StringArray(a).Value()
}
