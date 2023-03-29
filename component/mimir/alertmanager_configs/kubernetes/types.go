package alertmanager_configs

import (
	"fmt"
	"time"

	"github.com/grafana/agent/component/common/config"
	amConfig "github.com/prometheus/alertmanager/config"
)

// redefine the alertmanager config type so that we can add methods to it
type alertConfig amConfig.Config
type alertGlobalConfig amConfig.GlobalConfig

type Arguments struct {
	Address              string                  `river:"address,attr"`
	TenantID             string                  `river:"tenant_id,attr,optional"`
	UseLegacyRoutes      bool                    `river:"use_legacy_routes,attr,optional"`
	HTTPClientConfig     config.HTTPClientConfig `river:"http_client_config,block,optional"`
	SyncInterval         time.Duration           `river:"sync_interval,attr,optional"`
	MimirNameSpacePrefix string                  `river:"mimir_namespace_prefix,attr,optional"`

	AlertmanagerConfigSelector          LabelSelector `river:"alertmanager_config_selector,block,optional"`
	AlertmanagerConfigNamespaceSelector LabelSelector `river:"alertmanager_config_namespace_selector,block,optional"`
}

var DefaultArguments = Arguments{
	SyncInterval:         30 * time.Second,
	MimirNameSpacePrefix: "agent",
}

func (args *Arguments) UnmarshalRiver(f func(interface{}) error) error {
	*args = DefaultArguments

	type arguments Arguments
	if err := f((*arguments)(args)); err != nil {
		return err
	}

	if args.SyncInterval <= 0 {
		return fmt.Errorf("sync_interval must be greater than 0")
	}
	if args.MimirNameSpacePrefix == "" {
		return fmt.Errorf("mimir_namespace_prefix must not be empty")
	}

	return nil
}

type LabelSelector struct {
	MatchLabels      map[string]string `river:"match_labels,attr,optional"`
	MatchExpressions []MatchExpression `river:"match_expression,block,optional"`
}

type MatchExpression struct {
	Key      string   `river:"key,attr"`
	Operator string   `river:"operator,attr"`
	Values   []string `river:"values,attr,optional"`
}
