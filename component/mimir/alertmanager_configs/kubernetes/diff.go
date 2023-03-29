package alertmanager_configs

import (
	"reflect"
	"strings"

	promv1alpha1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1alpha1"
	amConfig "github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/pkg/labels"
	// Used for prometheus rulefmt compatibility instead of gopkg.in/yaml.v2
)

const inhibitRuleNamespaceKey = "namespace"

type amConfigDiffKind string

const (
	amConfigDiffKindAdd    amConfigDiffKind = "add"
	amConfigDiffKindRemove amConfigDiffKind = "remove"
	amConfigDiffKindUpdate amConfigDiffKind = "update"
)

type amConfigDiff struct {
	Kind    amConfigDiffKind
	Actual  promv1alpha1.AlertmanagerConfig
	Desired promv1alpha1.AlertmanagerConfig
}

type amConfigsByNamespace map[string]*promv1alpha1.AlertmanagerConfig

// type amConfigsByNamespace map[string][]amConfig.Config
type amConfigDiffsByNamespace map[string][]amConfigDiff

type amConfigRouteDiff struct {
	Kind    amConfigDiffKind
	Actual  amConfig.Route
	Desired amConfig.Route
}

// function that will compare []*amConfig.Route and build the config that will be used to update the alertmanager
func (c *Component) buildRoutes(desired, actual []*amConfig.Route) []*amConfig.Route {

	var outputRoutes []*amConfig.Route

	seenRoutes := map[string]bool{}
	for _, desiredRoute := range desired {
		seenRoutes[desiredRoute.Receiver] = true

		// TODO: cleanup but test if the error is happening due to routes having empty default values
		// desiredRoute.GroupInterval = c.currentState.Route.GroupInterval

		for _, actualRoute := range actual {
			if desiredRoute.Receiver == actualRoute.Receiver {
				if equalRoutes(desiredRoute, actualRoute) {
					continue
				}
				// route needs to be updated
				outputRoutes = append(outputRoutes, desiredRoute)
			}
		}
		// route needs to be added
		outputRoutes = append(outputRoutes, desiredRoute)
	}

	// append routes that are unmanaged by the operator
	outputRoutes = append(outputRoutes, c.unmanagedState.Route.Routes...)

	// c.wantedState.Route.Routes = outputRoutes

	for _, actualRoute := range actual {
		if seenRoutes[actualRoute.Receiver] {
			continue
		}
		// route needs to be removed
		// TODO: we'd only need this for logging and metric purposes
	}
	return outputRoutes
}

// function that will compare []*amConfig.Receiver and build the config that will be used to update the alertmanager
func (c *Component) buildReceivers(desired, actual []*amConfig.Receiver) []*amConfig.Receiver {

	var outputReceivers []*amConfig.Receiver

	seenReceivers := map[string]bool{}
	for _, desiredReceiver := range desired {
		seenReceivers[desiredReceiver.Name] = true

		for _, actualReceiver := range actual {
			if desiredReceiver.Name == actualReceiver.Name {
				if equalReceivers(desiredReceiver, actualReceiver) {
					continue
				}
				// receiver needs to be updated
				outputReceivers = append(outputReceivers, desiredReceiver)
			}
		}
		// receiver needs to be added
		outputReceivers = append(outputReceivers, desiredReceiver)
	}

	// append receivers that are unmanaged by the operator
	outputReceivers = append(outputReceivers, c.unmanagedState.Receivers...)

	// c.wantedState.Receivers = outputReceivers

	for _, actualReceiver := range actual {
		if seenReceivers[actualReceiver.Name] {
			continue
		}
		// receiver needs to be removed
		// TODO: we'd only need this for logging and metric purposes
	}
	return outputReceivers
}

// function that checks if two []amConfig.TimeInterval are equal or not and build the config that will be used to update the alertmanager
func (c *Component) buildTimeIntervals(desired, actual []amConfig.TimeInterval) []amConfig.TimeInterval {

	var outputTimeIntervals []amConfig.TimeInterval

	seenTimeIntervals := map[string]bool{}
	for _, desiredTimeInterval := range desired {
		seenTimeIntervals[desiredTimeInterval.Name] = true

		for _, actualTimeInterval := range actual {
			if desiredTimeInterval.Name == actualTimeInterval.Name {
				if equalTimeIntervals(desiredTimeInterval, actualTimeInterval) {
					continue
				}
				// time interval needs to be updated
				outputTimeIntervals = append(outputTimeIntervals, desiredTimeInterval)
			}
		}
		// time interval needs to be added
		outputTimeIntervals = append(outputTimeIntervals, desiredTimeInterval)
	}

	// append time intervals that are unmanaged by the operator
	outputTimeIntervals = append(outputTimeIntervals, c.unmanagedState.TimeIntervals...)

	// c.wantedState.TimeIntervals = outputTimeIntervals

	for _, actualTimeInterval := range actual {
		if seenTimeIntervals[actualTimeInterval.Name] {
			continue
		}
		// time interval needs to be removed
		// TODO: we'd only need this for logging and metric purposes
	}
	return outputTimeIntervals
}

// function that checks if two amConfig.TimeInterval are equal or not
func equalTimeIntervals(desired, actual amConfig.TimeInterval) bool {
	if reflect.DeepEqual(desired, actual) {
		return true
	}
	return false
}

// function that checks if two receivers are equal
func equalReceivers(desired, actual *amConfig.Receiver) bool {
	if reflect.DeepEqual(desired, actual) {
		return true
	}
	return false
}

// function that checks if two routes are equal
func equalRoutes(desired, actual *amConfig.Route) bool {
	if reflect.DeepEqual(desired, actual) {
		return true
	}
	return false
}

// func diffAmConfigState(desired, actual amConfigsByNamespace) amConfigDiffsByNamespace {
// 	seenNamespaces := map[string]bool{}

// 	diff := make(amConfigDiffsByNamespace)

// 	for namespace, desiredAmConfigs := range desired {
// 		seenNamespaces[namespace] = true

// 		actualAmConfigs := actual[namespace]
// 		subDiff := diffAmConfigNamespaceState(desiredAmConfigs, actualAmConfigs)

// 		if len(subDiff) == 0 {
// 			continue
// 		}

// 		diff[namespace] = subDiff
// 	}

// 	for namespace, actualAmConfigs := range actual {
// 		if seenNamespaces[namespace] {
// 			continue
// 		}

// 		subDiff := diffAmConfigNamespaceState(nil, actualAmConfigs)

// 		diff[namespace] = subDiff
// 	}

// 	return diff
// }

// func diffAmConfigNamespaceState(desired []promv1alpha1.AlertmanagerConfig, actual []promv1alpha1.AlertmanagerConfig) []amConfigDiff {
// 	var diff []amConfigDiff

// 	seenAmConfigs := map[string]bool{}

// desiredAmConfigs:
// 	for _, desiredAmConfig := range desired {
// 		seenAmConfigs[desiredAmConfig.Name] = true

// 		for _, actualAmConfig := range actual {
// 			if desiredAmConfig.Name == actualAmConfig.Name {
// 				if equalAmConfigs(desiredAmConfig, actualAmConfig) {
// 					continue desiredAmConfigs
// 				}

// 				diff = append(diff, amConfigDiff{
// 					Kind:    amConfigDiffKindUpdate,
// 					Actual:  actualAmConfig,
// 					Desired: desiredAmConfig,
// 				})
// 				continue desiredAmConfigs
// 			}
// 		}

// 		diff = append(diff, amConfigDiff{
// 			Kind:    amConfigDiffKindAdd,
// 			Desired: desiredAmConfig,
// 		})
// 	}

// 	for _, actualAmConfig := range actual {
// 		if seenAmConfigs[actualAmConfig.Name] {
// 			continue
// 		}

// 		diff = append(diff, amConfigDiff{
// 			Kind:   amConfigDiffKindRemove,
// 			Actual: actualAmConfig,
// 		})
// 	}

// 	return diff
// }

// func equalAmConfigs(a, b promv1alpha1.AlertmanagerConfig) bool {
// 	aBuf, err := yaml.Marshal(a)
// 	if err != nil {
// 		return false
// 	}
// 	bBuf, err := yaml.Marshal(b)
// 	if err != nil {
// 		return false
// 	}

// 	return bytes.Equal(aBuf, bBuf)
// }

// contains will return true if any slice value with all whitespace removed
// is equal to the provided value with all whitespace removed
func contains(value *labels.Matcher, in amConfig.Matchers) bool {
	for _, matcher := range in {
		if strings.ReplaceAll(value.String(), " ", "") == strings.ReplaceAll(matcher.String(), " ", "") {
			return true
		}
	}
	return false
}
