package db

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
)

// JSON stores any value as jsonb and scans jsonb back into a value.
type JSON[T any] struct{ V T }

// Value implements driver.Valuer.
func (j JSON[T]) Value() (driver.Value, error) {
	b, err := json.Marshal(j.V)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// Scan implements sql.Scanner.
func (j *JSON[T]) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		var zero T
		j.V = zero
		return nil
	case []byte:
		return json.Unmarshal(v, &j.V)
	case string:
		return json.Unmarshal([]byte(v), &j.V)
	default:
		return errors.New("db.JSON: unsupported scan type")
	}
}

func jsonb(v any) (string, error) {
	if v == nil {
		return "{}", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
