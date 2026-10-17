package store

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID            uuid.UUID `json:"id"`
	Email         *string   `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	DisplayName   *string   `json:"display_name"`
	Locale        *string   `json:"locale"`
	Kind          string    `json:"kind"`
	Status        string    `json:"status"`
	Version       int64     `json:"version"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Tenant struct {
	ID              uuid.UUID `json:"id"`
	Slug            string    `json:"slug"`
	Name            string    `json:"name"`
	Kind            string    `json:"kind"`
	Status          string    `json:"status"`
	Plan            *string   `json:"plan"`
	DataModeDefault string    `json:"data_mode_default"`
	Version         int64     `json:"version"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type Workspace struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	IsDefault bool      `json:"is_default"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Membership struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	UserID      uuid.UUID `json:"user_id"`
	TenantRole  string    `json:"tenant_role"`
	Status      string    `json:"status"`
	JoinedAt    time.Time `json:"joined_at"`
	Version     int64     `json:"version"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       *string   `json:"email,omitempty"`
	DisplayName *string   `json:"display_name,omitempty"`
}

type App struct {
	ID       uuid.UUID `json:"id"`
	Slug     string    `json:"slug"`
	Name     string    `json:"name"`
	ClientID string    `json:"client_id"`
	Manifest Manifest  `json:"manifest"`
	Status   string    `json:"status"`
	Version  int64     `json:"version"`
}

type TenantApp struct {
	TenantID  uuid.UUID  `json:"tenant_id"`
	AppID     uuid.UUID  `json:"app_id"`
	AppSlug   string     `json:"app"`
	Status    string     `json:"status"`
	Version   int64      `json:"version"`
	Placement *Placement `json:"placement,omitempty"`
}

type Placement struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      uuid.UUID  `json:"tenant_id"`
	AppID         uuid.UUID  `json:"app_id"`
	Mode          string     `json:"mode"`
	Manager       string     `json:"manager"`
	DBServerID    *uuid.UUID `json:"db_server_id"`
	DatabaseName  *string    `json:"database_name"`
	SchemaName    *string    `json:"schema_name"`
	LocationLabel *string    `json:"location_label"`
	State         string     `json:"state"`
	Error         *string    `json:"error,omitempty"`
	Version       int64      `json:"version"`
}

type Grant struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	AppID       uuid.UUID  `json:"app_id"`
	AppSlug     string     `json:"app"`
	WorkspaceID *uuid.UUID `json:"workspace_id"`
	SubjectType string     `json:"subject_type"`
	SubjectID   uuid.UUID  `json:"subject_id"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	Version     int64      `json:"version"`
}
