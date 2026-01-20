package util

import (
	"encoding/json"
	"net/http"
)

func Encode[T any](w http.ResponseWriter, status int, data T) error {
	// Encode the data to JSON
	jsonResponse, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Write headers and response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	// Write the JSON response
	_, err = w.Write(jsonResponse)
	if err != nil {
		return err
	}

	return nil
}

func Decode[T any](r *http.Request) (T, error) {
	var data T

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return data, err
	}
	return data, nil
}
