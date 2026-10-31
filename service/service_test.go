package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"kaspersky-test/model"
)

func stringPtr(s string) *string {
	return &s
}
func statusPtr(s model.ThreatStatus) *model.ThreatStatus {
	return &s
}

func TestValidateMD5(t *testing.T) {
	tests := []struct {
		name    string
		md5     string
		wantErr bool
	}{
		{"lowercase", "d41d8cd98f00b204e9800998ecf8427e", false},
		{"uppercase", "D41D8CD98F00B204E9800998ECF8427E", false},
		{"mixed case", "D41d8cD98f00b204e9800998ecf8427e", false},
		{"empty", "", true},
		{"too short", strings.Repeat("a", 31), true},
		{"too long", strings.Repeat("a", 33), true},
		{"non hex character", strings.Repeat("a", 31) + "z", true},
		{"spaces", " " + strings.Repeat("a", 31), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMD5(tt.md5)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("expected ErrInvalidInput, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestValidateThreat(t *testing.T) {
	tests := []struct {
		name        string
		threatName  string
		threatType  model.ThreatType
		level       model.ThreatLevel
		status      *model.ThreatStatus
		description *string
		source      *string
		wantErr     bool
	}{
		{name: "valid required fields", threatName: "Trojan.Win32.Generic", threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh},
		{name: "valid optional fields", threatName: "Trojan.Win32.Generic", threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh, status: statusPtr(model.ThreatStatusConfirmed), description: stringPtr("Description"), source: stringPtr("scanner")},
		{name: "name exactly 3", threatName: "abc", threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh},
		{name: "name exactly 255", threatName: strings.Repeat("a", 255), threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh},
		{name: "unicode name length", threatName: strings.Repeat("я", 255), threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh},
		{name: "empty name", threatName: "", threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh, wantErr: true},
		{name: "name too short", threatName: "ab", threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh, wantErr: true},
		{name: "name too long", threatName: strings.Repeat("a", 256), threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh, wantErr: true},
		{name: "whitespace name", threatName: "  \t ", threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh, wantErr: true},
		{name: "invalid type", threatName: "Valid", threatType: "malware", level: model.ThreatLevelHigh, wantErr: true},
		{name: "missing type", threatName: "Valid", level: model.ThreatLevelHigh, wantErr: true},
		{name: "invalid level", threatName: "Valid", threatType: model.ThreatTypeTrojan, level: "extreme", wantErr: true},
		{name: "missing level", threatName: "Valid", threatType: model.ThreatTypeTrojan, wantErr: true},
		{name: "invalid status", threatName: "Valid", threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh, status: statusPtr("invalid"), wantErr: true},
		{name: "description exactly 2000", threatName: "Valid", threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh, description: stringPtr(strings.Repeat("a", 2000))},
		{name: "description too long", threatName: "Valid", threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh, description: stringPtr(strings.Repeat("a", 2001)), wantErr: true},
		{name: "source exactly 255", threatName: "Valid", threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh, source: stringPtr(strings.Repeat("a", 255))},
		{name: "source too long", threatName: "Valid", threatType: model.ThreatTypeTrojan, level: model.ThreatLevelHigh, source: stringPtr(strings.Repeat("a", 256)), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateThreat(tt.threatName, tt.threatType, tt.level, tt.status, tt.description, tt.source)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("expected ErrInvalidInput, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestValidateThreatEnums(t *testing.T) {
	for _, threatType := range []model.ThreatType{
		model.ThreatTypeTrojan, model.ThreatTypeVirus, model.ThreatTypeWorm,
		model.ThreatTypeRansomware, model.ThreatTypeSpyware,
		model.ThreatTypeOther, model.ThreatTypeUnknown,
	} {
		t.Run("type/"+string(threatType), func(t *testing.T) {
			if err := validateThreat("Valid", threatType, model.ThreatLevelHigh, nil, nil, nil); err != nil {
				t.Fatalf("valid type rejected: %v", err)
			}
		})
	}

	for _, level := range []model.ThreatLevel{
		model.ThreatLevelLow, model.ThreatLevelMedium, model.ThreatLevelHigh,
		model.ThreatLevelCritical, model.ThreatLevelUnknown,
	} {
		t.Run("level/"+string(level), func(t *testing.T) {
			if err := validateThreat("Valid", model.ThreatTypeTrojan, level, nil, nil, nil); err != nil {
				t.Fatalf("valid level rejected: %v", err)
			}
		})
	}

	for _, status := range []model.ThreatStatus{
		model.ThreatStatusSuspected, model.ThreatStatusConfirmed, model.ThreatStatusFalsePositive,
	} {
		t.Run("status/"+string(status), func(t *testing.T) {
			if err := validateThreat("Valid", model.ThreatTypeTrojan, model.ThreatLevelHigh, statusPtr(status), nil, nil); err != nil {
				t.Fatalf("valid status rejected: %v", err)
			}
		})
	}
}

func TestMapRepoError(t *testing.T) {
	unexpected := errors.New("connection failed")
	tests := []struct {
		name  string
		input error
		want  error
	}{
		{"not found", pgx.ErrNoRows, ErrNotFound},
		{"wrapped not found", fmt.Errorf("query: %w", pgx.ErrNoRows), ErrNotFound},
		{"duplicate md5", &pgconn.PgError{Code: "23505"}, ErrAlreadyExists},
		{"not null violation", &pgconn.PgError{Code: "23502"}, ErrInvalidInput},
		{"check violation", &pgconn.PgError{Code: "23514"}, ErrInvalidInput},
		{"value too long", &pgconn.PgError{Code: "22001"}, ErrInvalidInput},
		{"invalid date", &pgconn.PgError{Code: "22007"}, ErrInvalidInput},
		{"date out of range", &pgconn.PgError{Code: "22008"}, ErrInvalidInput},
		{"unexpected pg error", &pgconn.PgError{Code: "08006"}, nil},
		{"unexpected error", unexpected, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapRepoError(tt.input)
			if tt.want != nil {
				if !errors.Is(got, tt.want) {
					t.Fatalf("expected %v, got %v", tt.want, got)
				}
			} else if got != tt.input {
				t.Fatalf("expected original error to be returned, got %v", got)
			}
		})
	}
}
