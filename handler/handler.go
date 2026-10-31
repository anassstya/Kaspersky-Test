package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"kaspersky-test/model"
	"kaspersky-test/service"
)

type Handler struct {
	service *service.Service
}

func New(s *service.Service) *Handler {
	return &Handler{service: s}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /info/{md5}", h.GetInfo)
	mux.HandleFunc("POST /info", h.CreateThreat)
	mux.HandleFunc("PUT /info/{md5}", h.UpdateThreat)
}

func (h *Handler) GetInfo(w http.ResponseWriter, r *http.Request) {
	threat, err := h.service.GetInfo(r.Context(), r.PathValue("md5"))
	if err != nil {
		writeServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, threat)
}

func (h *Handler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	var req model.ThreatCreateRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest,
			"VALIDATION_ERROR", "Invalid request body", err.Error())
		return
	}

	threat, err := h.service.CreateThreat(r.Context(), req)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	w.Header().Set("Location", "/info/"+threat.MD5)
	writeJSON(w, http.StatusCreated, threat)
}

func (h *Handler) UpdateThreat(w http.ResponseWriter, r *http.Request) {
	var req model.ThreatUpdateRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest,
			"VALIDATION_ERROR", "Invalid request body", err.Error())
		return
	}

	threat, err := h.service.UpdateThreat(
		r.Context(),
		r.PathValue("md5"),
		req,
	)
	if err != nil {
		writeServiceError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, threat)
}

func writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidInput):
		writeError(w, http.StatusBadRequest,
			"VALIDATION_ERROR", "Invalid request", err.Error())

	case errors.Is(err, service.ErrNotFound):
		writeError(w, http.StatusNotFound,
			"THREAT_NOT_FOUND", "Threat not found", "")

	case errors.Is(err, service.ErrAlreadyExists):
		writeError(w, http.StatusConflict,
			"THREAT_ALREADY_EXISTS", "Threat already exists", "")

	default:
		writeError(w, http.StatusInternalServerError,
			"INTERNAL_ERROR", "Internal server error", "")
	}
}

func writeError(w http.ResponseWriter, status int, code, message, details string) {
	resp := model.ErrorResponse{
		Code:    code,
		Message: message,
	}

	if details != "" {
		resp.Details = &details
	}

	writeJSON(w, status, resp)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
