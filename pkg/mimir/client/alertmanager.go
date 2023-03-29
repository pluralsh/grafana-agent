package client

import (
	"context"
	"io"

	"github.com/pkg/errors"
	alertmanagerConfig "github.com/prometheus/alertmanager/config"
	"gopkg.in/yaml.v3"
)

const alertmanagerAPIPath = "/api/v1/alerts"

type configCompat struct {
	TemplateFiles      map[string]string `yaml:"template_files"`
	AlertmanagerConfig string            `yaml:"alertmanager_config"`
}

// CreateAlertmanagerConfig creates a new alertmanager config
func (r *MimirClient) CreateAlertmanagerConfig(ctx context.Context, cfg string, templates map[string]string) error {
	payload, err := yaml.Marshal(&configCompat{
		TemplateFiles:      templates,
		AlertmanagerConfig: cfg,
	})
	if err != nil {
		return err
	}

	res, err := r.doRequest(alertmanagerAPIPath, alertmanagerAPIPath, "POST", payload)
	if err != nil {
		return err
	}

	res.Body.Close()

	return nil
}

// DeleteAlermanagerConfig deletes the users alertmanagerconfig
func (r *MimirClient) DeleteAlermanagerConfig(ctx context.Context) error {
	res, err := r.doRequest(alertmanagerAPIPath, alertmanagerAPIPath, "DELETE", nil)
	if err != nil {
		return err
	}

	res.Body.Close()

	return nil
}

// GetAlertmanagerConfig retrieves a Mimir cluster's Alertmanager config.
func (r *MimirClient) GetAlertmanagerConfig(ctx context.Context) (*alertmanagerConfig.Config, map[string]string, error) {
	res, err := r.doRequest(alertmanagerAPIPath, alertmanagerAPIPath, "GET", nil)
	if err != nil {
		return nil, nil, err
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, nil, err
	}

	compat := configCompat{}
	err = yaml.Unmarshal(body, &compat)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to unmarshal response")
	}

	conf, err := alertmanagerConfig.Load(compat.AlertmanagerConfig)
	if err != nil {
		return nil, nil, errors.Wrap(err, "unable to load alertmanager config") //TODO: ensure this works since it will break if no route exists
	}

	return conf, compat.TemplateFiles, nil
}
