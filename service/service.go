package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"kaspersky-test/model"
	"kaspersky-test/repo"
)

var (
	ErrInvalidInput  = errors.New("invalid input")
	ErrNotFound      = errors.New("threat not found")
	ErrAlreadyExists = errors.New("threat already exists")
)

var md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

type Service struct {
	db *pgxpool.Pool
}

func New(db *pgxpool.Pool) *Service {
	return &Service{db: db}
}

func (s *Service) GetInfo(ctx context.Context, md5 string) (*model.ThreatResponse, error) {
	if err := validateMD5(md5); err != nil {
		return nil, err
	}

	threat, err := repo.GetInfo(ctx, s.db, strings.ToLower(md5))
	if err != nil {
		return nil, mapRepoError(err)
	}
	return threat, nil
}

func (s *Service) CreateThreat(ctx context.Context, req model.ThreatCreateRequest) (*model.ThreatResponse, error) {
	if err := validateMD5(req.MD5); err != nil {
		return nil, err
	}
	if err := validateThreat(req.Name, req.Type, req.Level, req.Status, req.Description, req.Source); err != nil {
		return nil, err
	}

	req.MD5 = strings.ToLower(req.MD5)
	threat, err := repo.CreateThreat(ctx, req, s.db)
	if err != nil {
		return nil, mapRepoError(err)
	}
	return threat, nil
}

func (s *Service) UpdateThreat(ctx context.Context, md5 string, req model.ThreatUpdateRequest) (*model.ThreatResponse, error) {
	if err := validateMD5(md5); err != nil {
		return nil, err
	}
	if err := validateThreat(req.Name, req.Type, req.Level, req.Status, req.Description, req.Source); err != nil {
		return nil, err
	}

	threat, err := repo.UpdateThreat(ctx, s.db, strings.ToLower(md5), req)
	if err != nil {
		return nil, mapRepoError(err)
	}
	return threat, nil
}

func validateMD5(md5 string) error {
	if !md5Pattern.MatchString(md5) {
		return fmt.Errorf("%w: md5 must contain exactly 32 hexadecimal characters", ErrInvalidInput)
	}
	return nil
}

func validateThreat(name string, threatType model.ThreatType, level model.ThreatLevel, status *model.ThreatStatus, description, source *string) error {
	length := utf8.RuneCountInString(name)
	if length < 3 || length > 255 || strings.TrimSpace(name) == "" {
		return fmt.Errorf("%w: name must contain 3 to 255 characters", ErrInvalidInput)
	}

	switch threatType {
	case model.ThreatTypeTrojan, model.ThreatTypeVirus, model.ThreatTypeWorm,
		model.ThreatTypeRansomware, model.ThreatTypeSpyware, model.ThreatTypeOther, model.ThreatTypeUnknown:
	default:
		return fmt.Errorf("%w: invalid threat type", ErrInvalidInput)
	}

	switch level {
	case model.ThreatLevelLow, model.ThreatLevelMedium, model.ThreatLevelHigh,
		model.ThreatLevelCritical, model.ThreatLevelUnknown:
	default:
		return fmt.Errorf("%w: invalid threat level", ErrInvalidInput)
	}

	if status != nil {
		switch *status {
		case model.ThreatStatusSuspected, model.ThreatStatusConfirmed, model.ThreatStatusFalsePositive:
		default:
			return fmt.Errorf("%w: invalid threat status", ErrInvalidInput)
		}
	}

	if description != nil && utf8.RuneCountInString(*description) > 2000 {
		return fmt.Errorf("%w: description is longer than 2000 characters", ErrInvalidInput)
	}
	if source != nil && utf8.RuneCountInString(*source) > 255 {
		return fmt.Errorf("%w: source is longer than 255 characters", ErrInvalidInput)
	}
	return nil
}

func mapRepoError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return fmt.Errorf("%w: md5 already exists", ErrAlreadyExists)
		case "23502", "23514", "22001", "22007", "22008":
			return fmt.Errorf("%w: database constraint violation", ErrInvalidInput)
		}
	}
	return err
}
