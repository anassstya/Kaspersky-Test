package model

import "time"

type (
	ThreatType   string
	ThreatLevel  string
	ThreatStatus string
)

const (
	ThreatTypeTrojan     ThreatType = "trojan"
	ThreatTypeVirus      ThreatType = "virus"
	ThreatTypeWorm       ThreatType = "worm"
	ThreatTypeRansomware ThreatType = "ransomware"
	ThreatTypeSpyware    ThreatType = "spyware"
	ThreatTypeOther      ThreatType = "other"
	ThreatTypeUnknown    ThreatType = "unknown"
)

const (
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
	ThreatLevelUnknown  ThreatLevel = "unknown"
)

const (
	ThreatStatusSuspected     ThreatStatus = "suspected"
	ThreatStatusConfirmed     ThreatStatus = "confirmed"
	ThreatStatusFalsePositive ThreatStatus = "false_positive"
)

type ThreatCreateRequest struct {
	MD5         string        `json:"md5"`
	Name        string        `json:"name"`
	Type        ThreatType    `json:"type"`
	Level       ThreatLevel   `json:"level"`
	Status      *ThreatStatus `json:"status,omitempty"`
	Description *string       `json:"description,omitempty"`
	Source      *string       `json:"source,omitempty"`
	FirstSeenAt *time.Time    `json:"first_seen_at,omitempty"`
}

type ThreatUpdateRequest struct {
	Name        string        `json:"name"`
	Type        ThreatType    `json:"type"`
	Level       ThreatLevel   `json:"level"`
	Status      *ThreatStatus `json:"status,omitempty"`
	Description *string       `json:"description,omitempty"`
	Source      *string       `json:"source,omitempty"`
	FirstSeenAt *time.Time    `json:"first_seen_at,omitempty"`
}

type ThreatResponse struct {
	MD5         string       `json:"md5"`
	Name        string       `json:"name"`
	Type        ThreatType   `json:"type"`
	Level       ThreatLevel  `json:"level"`
	Status      ThreatStatus `json:"status"`
	Description *string      `json:"description,omitempty"`
	Source      *string      `json:"source,omitempty"`
	FirstSeenAt *time.Time   `json:"first_seen_at,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type ErrorResponse struct {
	Code    string  `json:"code"`
	Message string  `json:"message"`
	Details *string `json:"details,omitempty"`
}
