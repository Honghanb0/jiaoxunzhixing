package scheduler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"security-agent/internal/config"
	"security-agent/internal/models"
	"security-agent/internal/storage"
)

type AlertService struct {
	cfg       *config.AlertsConfig
	vulnRepo  *storage.VulnerabilityRepository
	sensRepo  *storage.SensitiveInfoRepository
	alertRepo *storage.AlertRepository
}

func NewAlertService(cfg *config.AlertsConfig, vulnRepo *storage.VulnerabilityRepository, sensRepo *storage.SensitiveInfoRepository, alertRepo *storage.AlertRepository) *AlertService {
	return &AlertService{
		cfg:       cfg,
		vulnRepo:  vulnRepo,
		sensRepo:  sensRepo,
		alertRepo: alertRepo,
	}
}

func (s *AlertService) SendAlert(alert *models.Alert) error {
	if !s.cfg.Enabled {
		return nil
	}

	if s.alertRepo != nil {
		if err := s.alertRepo.Create(alert); err != nil {
			log.Printf("Failed to save alert: %v", err)
		}
	}

	for _, channel := range s.cfg.Channels {
		if err := s.sendToChannel(alert, channel); err != nil {
			log.Printf("Failed to send alert to %s: %v", channel.Type, err)
		}
	}

	return nil
}

func (s *AlertService) sendToChannel(alert *models.Alert, channel config.AlertChannel) error {
	switch channel.Type {
	case "webhook":
		return s.sendWebhook(alert, channel.URL)
	case "email":
		return s.sendEmail(alert, channel)
	default:
		return fmt.Errorf("unsupported channel type: %s", channel.Type)
	}
}

func (s *AlertService) sendWebhook(alert *models.Alert, webhookURL string) error {
	payload := map[string]interface{}{
		"alert_id":   alert.ID,
		"title":      alert.Title,
		"content":    alert.Content,
		"severity":   alert.Severity,
		"domain_id":  alert.DomainID,
		"type":       alert.Type,
		"status":     alert.Status,
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (s *AlertService) sendEmail(alert *models.Alert, channel config.AlertChannel) error {
	log.Printf("Email alert: To=%s, Subject=%s, Title=%s", channel.To, alert.Title, alert.Title)
	return nil
}

func (s *AlertService) CreateAlertFromVulnerability(vuln *models.Vulnerability) error {
	alert := &models.Alert{
		DomainID:    vuln.ScanJobID,
		ScanJobID:   vuln.ScanJobID,
		Type:        "vulnerability",
		ReferenceID: vuln.ID,
		Title:       fmt.Sprintf("[%s] %s", vuln.Severity, vuln.Name),
		Content:     fmt.Sprintf("Vulnerability found at %s\nSeverity: %s\nDescription: %s", vuln.URL, vuln.Severity, vuln.Description),
		Severity:    vuln.Severity,
		Status:      "new",
		CreatedAt:   time.Now(),
	}

	return s.SendAlert(alert)
}

func (s *AlertService) CreateAlertFromSensitiveInfo(info *models.SensitiveInfo) error {
	alert := &models.Alert{
		DomainID:    info.ScanJobID,
		ScanJobID:   info.ScanJobID,
		Type:        "sensitive_info",
		ReferenceID: info.ID,
		Title:       fmt.Sprintf("[%s] Sensitive Info: %s", info.Severity, info.Type),
		Content:     fmt.Sprintf("Sensitive information detected at %s\nType: %s\nLocation: %s", info.URL, info.Type, info.Location),
		Severity:    info.Severity,
		Status:      "new",
		CreatedAt:   time.Now(),
	}

	return s.SendAlert(alert)
}
