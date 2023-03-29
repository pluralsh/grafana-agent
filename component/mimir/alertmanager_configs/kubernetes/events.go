package alertmanager_configs

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/ghodss/yaml" // Used for CRD compatibility instead of gopkg.in/yaml.v2
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	promv1alpha1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1alpha1"
	amConfig "github.com/prometheus/alertmanager/config"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// This type must be hashable, so it is kept simple. The indexer will maintain a
// cache of current state, so this is mostly used for logging.
type event struct {
	typ       eventType
	objectKey string
}

type eventType string

const (
	eventTypeResourceChanged eventType = "resource-changed"
	eventTypeSyncMimir       eventType = "sync-mimir"
)

type queuedEventHandler struct {
	log   log.Logger
	queue workqueue.RateLimitingInterface
}

func newQueuedEventHandler(log log.Logger, queue workqueue.RateLimitingInterface) *queuedEventHandler {
	return &queuedEventHandler{
		log:   log,
		queue: queue,
	}
}

// OnAdd implements the cache.ResourceEventHandler interface.
func (c *queuedEventHandler) OnAdd(obj interface{}) {
	c.publishEvent(obj)
}

// OnUpdate implements the cache.ResourceEventHandler interface.
func (c *queuedEventHandler) OnUpdate(oldObj, newObj interface{}) {
	c.publishEvent(newObj)
}

// OnDelete implements the cache.ResourceEventHandler interface.
func (c *queuedEventHandler) OnDelete(obj interface{}) {
	c.publishEvent(obj)
}

func (c *queuedEventHandler) publishEvent(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		level.Error(c.log).Log("msg", "failed to get key for object", "err", err)
		return
	}

	c.queue.AddRateLimited(event{
		typ:       eventTypeResourceChanged,
		objectKey: key,
	})
}

func (c *Component) eventLoop(ctx context.Context) {
	for {
		eventInterface, shutdown := c.queue.Get()
		if shutdown {
			level.Info(c.log).Log("msg", "shutting down event loop")
			return
		}

		evt := eventInterface.(event)
		c.metrics.eventsTotal.WithLabelValues(string(evt.typ)).Inc()
		err := c.processEvent(ctx, evt)

		if err != nil {
			retries := c.queue.NumRequeues(evt)
			if retries < 5 {
				c.metrics.eventsRetried.WithLabelValues(string(evt.typ)).Inc()
				c.queue.AddRateLimited(evt)
				level.Error(c.log).Log(
					"msg", "failed to process event, will retry",
					"retries", fmt.Sprintf("%d/5", retries),
					"err", err,
				)
				continue
			} else {
				c.metrics.eventsFailed.WithLabelValues(string(evt.typ)).Inc()
				level.Error(c.log).Log(
					"msg", "failed to process event, max retries exceeded",
					"retries", fmt.Sprintf("%d/5", retries),
					"err", err,
				)
				c.reportUnhealthy(err)
			}
		} else {
			c.reportHealthy()
		}

		c.queue.Forget(evt)
	}
}

func (c *Component) processEvent(ctx context.Context, e event) error {
	defer c.queue.Done(e)

	switch e.typ {
	case eventTypeResourceChanged:
		level.Info(c.log).Log("msg", "processing event", "type", e.typ, "key", e.objectKey)
	case eventTypeSyncMimir:
		level.Debug(c.log).Log("msg", "syncing current state from ruler")
		err := c.syncMimir(ctx)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown event type: %s", e.typ)
	}

	return c.reconcileState(ctx)
}

func (c *Component) syncMimir(ctx context.Context) error {
	config, _, err := c.mimirClient.GetAlertmanagerConfig(ctx)
	if err != nil {
		level.Error(c.log).Log("msg", "failed to get alertmanager config from mimir", "err", err)
		return err
	}

	level.Info(c.log).Log("msg", "got current alertmanager config", "config", config)

	c.currentState = config

	level.Info(c.log).Log("msg", "config in currentState", "config", c.currentState)

	if c.currentState.Route.Receiver == "" {
		c.currentState.Route.Receiver = "null"
		c.currentState.Receivers = append(c.currentState.Receivers, &amConfig.Receiver{Name: "null"})
	}

	c.managedState = &amConfig.Config{
		Route:             &amConfig.Route{},
		Receivers:         []*amConfig.Receiver{},
		TimeIntervals:     []amConfig.TimeInterval{},
		MuteTimeIntervals: []amConfig.MuteTimeInterval{},
	}
	c.unmanagedState = &amConfig.Config{
		Route:             &amConfig.Route{},
		Receivers:         []*amConfig.Receiver{},
		TimeIntervals:     []amConfig.TimeInterval{},
		MuteTimeIntervals: []amConfig.MuteTimeInterval{},
	}

	var unmanagedRoutes []*amConfig.Route
	var managedRoutes []*amConfig.Route

	for _, r := range config.Route.Routes {
		if !isManagedByMimir(c.args.MimirNameSpacePrefix, r.Receiver) {
			unmanagedRoutes = append(unmanagedRoutes, r)
		} else {
			managedRoutes = append(managedRoutes, r)
		}
	}

	// level.Info(c.log).Log("msg", "processed routes", "managed", managedRoutes)
	// level.Info(c.log).Log("msg", "processed routes", "unmanaged", unmanagedRoutes)

	// TODO: is this needed for inhibit rules?
	// TODO: we might actually need to dedupe here since we have no way of identifying which inhibit rule is managed by an agent
	// This would be a problem if multiple agents run against a single mimir tenant, causing us to not be able to delete the inhibit rules
	// var unmanagedInhibitRules []*amConfig.InhibitRule
	// var managedInhibitRules []*amConfig.InhibitRule

	// for _, inhibitRule := range config.InhibitRules {
	// 	if !isManagedMimirNamespace(c.args.MimirNameSpacePrefix, inhibitRule.SourceMatch["namespace"]) {
	// 		unmanagedInhibitRules = append(unmanagedInhibitRules, inhibitRule)
	// 	} else {
	// 		managedInhibitRules = append(managedInhibitRules, inhibitRule)
	// 	}
	// }

	var unmanagedReceivers []*amConfig.Receiver
	var managedReceivers []*amConfig.Receiver

	for _, receiver := range config.Receivers {
		if !isManagedByMimir(c.args.MimirNameSpacePrefix, receiver.Name) {
			unmanagedReceivers = append(unmanagedReceivers, receiver)
		} else {
			managedReceivers = append(managedReceivers, receiver)
		}
	}

	// level.Info(c.log).Log("msg", "processed receivers", "managed", managedReceivers)
	// level.Info(c.log).Log("msg", "processed receivers", "unmanaged", unmanagedReceivers)

	var unmanagedMuteTimeInterval []amConfig.MuteTimeInterval
	var managedMuteTimeInterval []amConfig.MuteTimeInterval

	for _, muteTimeInterval := range config.MuteTimeIntervals {
		if !isManagedByMimir(c.args.MimirNameSpacePrefix, muteTimeInterval.Name) {
			unmanagedMuteTimeInterval = append(unmanagedMuteTimeInterval, muteTimeInterval)
		} else {
			managedMuteTimeInterval = append(managedMuteTimeInterval, muteTimeInterval)
		}
	}

	c.managedState.Route.Routes = managedRoutes
	// c.managedState.InhibitRules = managedInhibitRules
	c.managedState.Receivers = managedReceivers
	c.managedState.MuteTimeIntervals = managedMuteTimeInterval

	c.unmanagedState.Route.Routes = unmanagedRoutes
	// c.unmanagedState.InhibitRules = unmanagedInhibitRules
	c.unmanagedState.Receivers = unmanagedReceivers
	c.unmanagedState.MuteTimeIntervals = unmanagedMuteTimeInterval

	return nil
}

func (c *Component) reconcileState(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	clusterState, err := c.loadStateFromK8s()
	if err != nil {
		return err
	}
	// c.wantedState = &amConfig.Config{
	// 	Route:             &amConfig.Route{},
	// 	Receivers:         []*amConfig.Receiver{},
	// 	TimeIntervals:     []amConfig.TimeInterval{},
	// 	MuteTimeIntervals: []amConfig.MuteTimeInterval{},
	// }
	desiredState, err := c.convertAlertmanagerConfigs(clusterState)
	if err != nil {
		return err
	}

	level.Info(c.log).Log("msg", "converted alertmanagerconfigs", "desiredState", desiredState)

	routes := c.buildRoutes(desiredState.Route.Routes, c.managedState.Route.Routes)
	receivers := c.buildReceivers(desiredState.Receivers, c.managedState.Receivers)
	// timeIntervals := c.buildTimeIntervals(desiredState.TimeIntervals, c.managedState.TimeIntervals) //TODO: reenable

	// level.Info(c.log).Log("msg", "built routes", "routers", routes)
	// level.Info(c.log).Log("msg", "built receivers", "receivers", receivers)
	// level.Info(c.log).Log("msg", "built time intervals", "time intervals", timeIntervals)

	c.updatedState = *c.currentState

	level.Info(c.log).Log("msg", "state to be applied copied from current", "updatedState", c.updatedState)

	c.updatedState.Route.Routes = make([]*amConfig.Route, len(routes))
	for _, route := range routes {
		c.updatedState.Route.Routes = append(c.updatedState.Route.Routes, route)
	}

	c.updatedState.Receivers = make([]*amConfig.Receiver, len(receivers))
	for _, receiver := range receivers {
		c.updatedState.Receivers = append(c.updatedState.Receivers, receiver)
	}

	//TODO: reenable
	// c.updatedState.TimeIntervals = make([]amConfig.TimeInterval, len(timeIntervals))
	// for _, timeInterval := range timeIntervals {
	// 	c.updatedState.TimeIntervals = append(c.updatedState.TimeIntervals, timeInterval)
	// }

	// copy(c.updatedState.Route.Routes, routes)
	// copy(c.updatedState.Receivers, receivers)
	// copy(c.updatedState.TimeIntervals, timeIntervals)

	level.Info(c.log).Log("msg", "state to be applied after adding built changes", "updatedState", c.updatedState)

	return c.applyChanges(ctx, c.updatedState, nil)
}

//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs
//TODO: check why there are receivers with empty name names in the config that is being pushed, this might be from adding the unmanaged configs

func defaultAlertmanagerConfiguration() []byte {
	return []byte(`route:
  receiver: 'null'
receivers:
- name: 'null'`)
}

func (c *Component) loadStateFromK8s() (amConfigsByNamespace, error) {
	matchedNamespaces, err := c.namespaceLister.List(c.namespaceSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	res := make(map[string]*promv1alpha1.AlertmanagerConfig)

	// desiredState := make(amConfigsByNamespace)
	for _, ns := range matchedNamespaces {
		amConfigs, err := c.amConfigLister.AlertmanagerConfigs(ns.Name).List(c.amConfigSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to list rules: %w", err)
		}

		for _, amConf := range amConfigs {

			res[amConf.Namespace+"/"+amConf.Name] = amConf

			// mimirNs := mimirNamespaceForRuleCRD(c.args.MimirNameSpacePrefix, amConf)

			// amConfs, err := convertCRDAmConfigToAmConfig(amConf.Spec)
			// if err != nil {
			// 	return nil, fmt.Errorf("failed to convert rule group: %w", err)
			// }

			// desiredState[mimirNs] = amConfs
		}
	}

	return res, nil
}

func (c *Component) convertAlertmanagerConfigs(amConfigs map[string]*promv1alpha1.AlertmanagerConfig) (*amConfig.Config, error) {
	amConfigIdentifiers := make([]string, len(amConfigs))
	i := 0
	for k := range amConfigs {
		amConfigIdentifiers[i] = k
		i++
	}
	sort.Strings(amConfigIdentifiers)

	output := &amConfig.Config{
		Route:             &amConfig.Route{},
		Receivers:         []*amConfig.Receiver{},
		TimeIntervals:     []amConfig.TimeInterval{},
		MuteTimeIntervals: []amConfig.MuteTimeInterval{},
	}

	subRoutes := make([]*amConfig.Route, 0, len(amConfigs))
	for _, amConfigIdentifier := range amConfigIdentifiers {
		crKey := types.NamespacedName{
			Name:      amConfigs[amConfigIdentifier].Name,
			Namespace: amConfigs[amConfigIdentifier].Namespace,
		}

		// Add inhibitRules to baseConfig.InhibitRules.
		for _, inhibitRule := range amConfigs[amConfigIdentifier].Spec.InhibitRules {
			output.InhibitRules = append(output.InhibitRules,
				convertInhibitRule(inhibitRule, crKey),
			)
		}

		// Skip early if there's no route definition.
		if amConfigs[amConfigIdentifier].Spec.Route == nil {
			continue
		}

		subRoutes = append(subRoutes,
			c.convertRoute(
				amConfigs[amConfigIdentifier].Spec.Route,
				crKey,
			),
		)

		for _, receiver := range amConfigs[amConfigIdentifier].Spec.Receivers {
			receivers, err := c.convertReceiver(c.ctx, &receiver, crKey)
			if err != nil {
				return nil, errors.Wrapf(err, "AlertmanagerConfig %s", crKey.String())
			}
			output.Receivers = append(output.Receivers, receivers)
		}

		for _, muteTimeInterval := range amConfigs[amConfigIdentifier].Spec.MuteTimeIntervals {
			mti, err := convertMuteTimeInterval(&muteTimeInterval, crKey, c.args.MimirNameSpacePrefix)
			if err != nil {
				return nil, errors.Wrapf(err, "AlertmanagerConfig %s", crKey.String())
			}
			output.MuteTimeIntervals = append(output.MuteTimeIntervals, *mti)
		}
	}

	// For alerts to be processed by the AlertmanagerConfig routes, they need
	// to appear before the routes defined in the main configuration.
	// Because all first-level AlertmanagerConfig routes have "continue: true",
	// alerts will fall through.
	output.Route.Routes = append(subRoutes, output.Route.Routes...)

	return output, nil
}

func keyFunc(obj interface{}) (string, bool) {
	k, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		return k, false
	}
	return k, true
}

func convertCRDAmConfigToAmConfig(crd promv1alpha1.AlertmanagerConfigSpec) (*amConfig.Config, error) {
	buf, err := yaml.Marshal(crd)
	if err != nil {
		return nil, err
	}

	config, err := amConfig.Load(string(buf))
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Component) applyChanges(ctx context.Context, conf amConfig.Config, temps map[string]string) error {
	// if len(diffs) == 0 {
	// 	return nil
	// }

	if err := c.mimirClient.CreateAlertmanagerConfig(ctx, conf.String(), temps); err != nil {
		return err
	}
	level.Info(c.log).Log("msg", "updated alertmanager config")

	// for _, diff := range diffs {
	// 	switch diff.Kind {
	// 	case ruleGroupDiffKindAdd:
	// 		err := c.mimirClient.CreateRuleGroup(ctx, namespace, diff.Desired)
	// 		if err != nil {
	// 			return err
	// 		}
	// 		level.Info(c.log).Log("msg", "added rule group", "namespace", namespace, "group", diff.Desired.Name)
	// 	case ruleGroupDiffKindRemove:
	// 		err := c.mimirClient.DeleteRuleGroup(ctx, namespace, diff.Actual.Name)
	// 		if err != nil {
	// 			return err
	// 		}
	// 		level.Info(c.log).Log("msg", "removed rule group", "namespace", namespace, "group", diff.Actual.Name)
	// 	case ruleGroupDiffKindUpdate:
	// 		err := c.mimirClient.CreateRuleGroup(ctx, namespace, diff.Desired)
	// 		if err != nil {
	// 			return err
	// 		}
	// 		level.Info(c.log).Log("msg", "updated rule group", "namespace", namespace, "group", diff.Desired.Name)
	// 	default:
	// 		level.Error(c.log).Log("msg", "unknown rule group diff kind", "kind", diff.Kind)
	// 	}
	// }

	// resync mimir state after applying changes
	return c.syncMimir(ctx)
}

// mimirMakeNamespacedString returns the namespace that the rule CRD should be
// stored in mimir. This function, along with isManagedNamespace, is used to
// determine if a rule CRD is managed by the agent.
func mimirMakeNamespacedString(prefix, in string, crKey types.NamespacedName) string {
	if in == "" {
		return "" // TODO: should this be prefix?
	}
	return fmt.Sprintf("%s/%s/%s/%s", prefix, crKey.Namespace, crKey.Name, in)
}

// isManagedByMimir returns true if the object is managed by the agent.
// Unmanaged objects are left as is by the operator.
func isManagedByMimir(prefix, namespace string) bool {
	prefixPart := regexp.QuoteMeta(prefix)
	namespacePart := `.+`
	namePart := `.+`
	uuidPart := `.+`
	managedNamespaceRegex := regexp.MustCompile(
		fmt.Sprintf("^%s/%s/%s/%s$", prefixPart, namespacePart, namePart, uuidPart),
	)
	return managedNamespaceRegex.MatchString(namespace)
}
