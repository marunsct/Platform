// Package access connects maturad to OpenFGA (TS11, ADR 0005, technical specification §18): it keeps the
// installation's store and models, mirrors Matura's own facts into it (Syncer), and serves apps' checks.
package access

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/google/uuid"

	"github.com/marunsct/Platform/internal/fga"
	"github.com/marunsct/Platform/internal/store"
)

// ErrNoModel is an app whose manifest declares no authorization model.
var ErrNoModel = errors.New("the app's manifest declares no authorization model")

// Service holds the installation's OpenFGA store and the model ids of Matura and each app. maturad has one; the API
// and the Syncer share it.
type Service struct {
	Client    *fga.Client
	Store     *store.Store
	StoreName string // OpenFGA store name; default "matura"
	Log       *slog.Logger

	mu        sync.Mutex
	storeID   string
	baseModel string
	models    map[uuid.UUID]appModel
}

type appModel struct {
	hash, id string
	types    []string
}

// Ready returns the store and Matura's base model, creating them on first use. A store id recorded earlier is
// checked once per process; when OpenFGA no longer has it, the store is found by name or created again, and a new
// store makes the Syncer write every fact again.
func (s *Service) Ready(ctx context.Context) (storeID, baseModel string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready(ctx)
}

func (s *Service) ready(ctx context.Context) (string, string, error) {
	if s.storeID != "" && s.baseModel != "" {
		return s.storeID, s.baseModel, nil
	}
	st, err := s.Store.FGAState(ctx)
	if err != nil {
		return "", "", err
	}
	id := st.StoreID
	if id != "" {
		ok, err := s.Client.StoreExists(ctx, id)
		if err != nil {
			return "", "", err
		}
		if !ok {
			id = ""
		}
	}
	if id == "" {
		name := s.StoreName
		if name == "" {
			name = "matura"
		}
		if id, err = s.Client.FindStore(ctx, name); err != nil {
			return "", "", err
		}
		if id == "" {
			if id, err = s.Client.CreateStore(ctx, name); err != nil {
				return "", "", err
			}
		}
		if err := s.Store.SetFGAStore(ctx, id); err != nil {
			return "", "", err
		}
		if id != st.StoreID {
			st = store.FGAState{StoreID: id}
		}
	}
	base := fga.Base()
	if st.BaseModelID == "" || st.BaseHash != base.Hash() {
		mid, err := s.Client.WriteModel(ctx, id, base)
		if err != nil {
			return "", "", err
		}
		if err := s.Store.SetFGABaseModel(ctx, mid, base.Hash()); err != nil {
			return "", "", err
		}
		st.BaseModelID = mid
	}
	s.storeID, s.baseModel = id, st.BaseModelID
	return s.storeID, s.baseModel, nil
}

// AppModel returns the store and the model to use for the app, writing the app's model when it changed.
func (s *Service) AppModel(ctx context.Context, app store.App) (storeID, modelID string, types []string, err error) {
	own, ok := app.Manifest.FGAModel()
	if !ok {
		return "", "", nil, ErrNoModel
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if storeID, _, err = s.ready(ctx); err != nil {
		return "", "", nil, err
	}
	m := fga.ForApp(app.Slug, own)
	h := m.Hash()
	if c, ok := s.models[app.ID]; ok && c.hash == h {
		return storeID, c.id, c.types, nil
	}
	id, err := s.Store.FGAAppModel(ctx, app.ID, h)
	if err != nil {
		return "", "", nil, err
	}
	if id == "" {
		if id, err = s.Client.WriteModel(ctx, storeID, m); err != nil {
			return "", "", nil, err
		}
		if err := s.Store.SetFGAAppModel(ctx, app.ID, h, id); err != nil {
			return "", "", nil, err
		}
		s.log().Info("authorization model written", "app", app.Slug, "model", id)
	}
	if s.models == nil {
		s.models = map[uuid.UUID]appModel{}
	}
	s.models[app.ID] = appModel{hash: h, id: id, types: own.TypeNames()}
	return storeID, id, own.TypeNames(), nil
}

// Checked passes err on, first forgetting the store and models when OpenFGA no longer knows them, so the next call
// sets them up again.
func (s *Service) Checked(ctx context.Context, err error) error {
	var e *fga.Error
	if errors.As(err, &e) && e.Stale() {
		s.mu.Lock()
		s.storeID, s.baseModel, s.models = "", "", nil
		s.mu.Unlock()
		if ferr := s.Store.ForgetFGAModels(ctx); ferr != nil {
			s.log().Warn("forgetting OpenFGA models failed", "err", ferr)
		}
	}
	return err
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}
