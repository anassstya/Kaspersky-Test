package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"kaspersky-test/model"
)

func GetInfo(ctx context.Context, db *pgxpool.Pool, md5 string) (*model.ThreatResponse, error) {
	sql := `
		SELECT md5, name, type, level, status,
		       description, source, first_seen_at,
		       created_at, updated_at
		FROM threats
		WHERE md5 = $1
	`

	var threat model.ThreatResponse

	err := db.QueryRow(ctx, sql, md5).Scan(
		&threat.MD5,
		&threat.Name,
		&threat.Type,
		&threat.Level,
		&threat.Status,
		&threat.Description,
		&threat.Source,
		&threat.FirstSeenAt,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &threat, nil
}

func CreateThreat(ctx context.Context, req model.ThreatCreateRequest, db *pgxpool.Pool) (*model.ThreatResponse, error) {
	sql := `
		INSERT INTO threats ( md5, name, type, level, status,
			description, source, first_seen_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING md5, name, type, level, status,
		description, source, first_seen_at,
		created_at, updated_at
	`

	status := model.ThreatStatusSuspected
	if req.Status != nil {
		status = *req.Status
	}

	var threat model.ThreatResponse

	err := db.QueryRow(ctx, sql, req.MD5, req.Name, req.Type, req.Level, status, req.Description, req.Source, req.FirstSeenAt).Scan(
		&threat.MD5,
		&threat.Name,
		&threat.Type,
		&threat.Level,
		&threat.Status,
		&threat.Description,
		&threat.Source,
		&threat.FirstSeenAt,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &threat, nil
}

func UpdateThreat(ctx context.Context, db *pgxpool.Pool, md5 string, req model.ThreatUpdateRequest) (*model.ThreatResponse, error) {
	sql := `
		UPDATE threats
		SET
			name = $2,
			type = $3,
			level = $4,
			status = $5,
			description = $6,
			source = $7,
			first_seen_at = $8,
			updated_at = NOW()
		WHERE md5 = $1
		RETURNING md5, name, type, level, status,
		          description, source, first_seen_at,
		          created_at, updated_at
	`

	status := model.ThreatStatusSuspected
	if req.Status != nil {
		status = *req.Status
	}

	var threat model.ThreatResponse

	err := db.QueryRow(
		ctx,
		sql,
		md5,
		req.Name,
		req.Type,
		req.Level,
		status,
		req.Description,
		req.Source,
		req.FirstSeenAt,
	).Scan(
		&threat.MD5,
		&threat.Name,
		&threat.Type,
		&threat.Level,
		&threat.Status,
		&threat.Description,
		&threat.Source,
		&threat.FirstSeenAt,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &threat, nil
}
