package alertmanagers

import "fmt"

type DebugInfo struct {
	Error               string                       `river:"error,attr,optional"`
	AlertmanagerConfigs []DebugK8sAlertmanagerConfig `river:"alertmanager_configs,block,optional"`
	// MimirRuleNamespaces []DebugMimirNamespace        `river:"mimir_rule_namespace,block,optional"`
}

type DebugK8sAlertmanagerConfig struct {
	Namespace    string `river:"namespace,attr"`
	Name         string `river:"name,attr"`
	UID          string `river:"uid,attr"`
	NumReceivers int    `river:"num_receivers,attr"`
	NumRoutes    int    `river:"num_routes,attr"`
}

type DebugMimirNamespace struct {
	Name          string `river:"name,attr"`
	NumRuleGroups int    `river:"num_rule_groups,attr"`
}

func (c *Component) DebugInfo() interface{} {
	var output DebugInfo
	// for ns := range c.currentState {
	// 	if !isManagedMimirNamespace(c.args.MimirNameSpacePrefix, ns) {
	// 		continue
	// 	}

	// 	output.MimirRuleNamespaces = append(output.MimirRuleNamespaces, DebugMimirNamespace{
	// 		Name:          ns,
	// 		NumRuleGroups: len(c.currentState[ns]),
	// 	})
	// }

	// This should load from the informer cache, so it shouldn't fail under normal circumstances.
	managedK8sNamespaces, err := c.namespaceLister.List(c.namespaceSelector)
	if err != nil {
		return DebugInfo{
			Error: fmt.Sprintf("failed to list namespaces: %v", err),
		}
	}

	for _, n := range managedK8sNamespaces {
		// This should load from the informer cache, so it shouldn't fail under normal circumstances.
		rules, err := c.amConfigLister.AlertmanagerConfigs(n.Name).List(c.amConfigSelector)
		if err != nil {
			return DebugInfo{
				Error: fmt.Sprintf("failed to list rules: %v", err),
			}
		}

		for _, r := range rules {
			output.AlertmanagerConfigs = append(output.AlertmanagerConfigs, DebugK8sAlertmanagerConfig{
				Namespace:    n.Name,
				Name:         r.Name,
				UID:          string(r.UID),
				NumReceivers: len(r.Spec.Receivers),
				NumRoutes:    len(r.Spec.Route.Routes),
			})
		}
	}

	return output
}
