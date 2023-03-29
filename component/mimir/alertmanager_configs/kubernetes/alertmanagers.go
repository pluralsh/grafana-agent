package alertmanager_configs

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/grafana/agent/component"
	mimirClient "github.com/grafana/agent/pkg/mimir/client"
	"github.com/pkg/errors"
	promListers "github.com/prometheus-operator/prometheus-operator/pkg/client/listers/monitoring/v1alpha1"
	alertmanagerConfig "github.com/prometheus/alertmanager/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/weaveworks/common/instrument"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	coreListers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	_ "k8s.io/component-base/metrics/prometheus/workqueue"
	controller "sigs.k8s.io/controller-runtime"

	promExternalVersions "github.com/prometheus-operator/prometheus-operator/pkg/client/informers/externalversions"
	promVersioned "github.com/prometheus-operator/prometheus-operator/pkg/client/versioned"
)

func init() {
	component.Register(component.Registration{
		Name:    "mimir.alertmanager_configs.kubernetes",
		Args:    Arguments{},
		Exports: nil,
		Build: func(o component.Options, c component.Arguments) (component.Component, error) {
			return NewComponent(o, c.(Arguments))
		},
	})
}

type Component struct {
	log  log.Logger
	opts component.Options
	args Arguments

	mimirClient mimirClient.Interface
	k8sClient   kubernetes.Interface
	ctx         context.Context
	// cmClient         corev1client.ConfigMapsGetter
	// sClient          corev1client.SecretsGetter
	objStore cache.Store

	promClient       promVersioned.Interface
	amConfigLister   promListers.AlertmanagerConfigLister
	amConfigInformer cache.SharedIndexInformer

	namespaceLister   coreListers.NamespaceLister
	namespaceInformer cache.SharedIndexInformer
	informerStopChan  chan struct{}
	ticker            *time.Ticker

	queue         workqueue.RateLimitingInterface
	configUpdates chan ConfigUpdate

	namespaceSelector labels.Selector
	amConfigSelector  labels.Selector

	currentState   *alertmanagerConfig.Config
	managedState   *alertmanagerConfig.Config
	unmanagedState *alertmanagerConfig.Config

	// clusterState *alertmanagerConfig.Config

	// wantedState  *alertmanagerConfig.Config
	updatedState alertmanagerConfig.Config

	metrics   *metrics
	healthMut sync.RWMutex
	health    component.Health
}

type metrics struct {
	configUpdatesTotal prometheus.Counter

	eventsTotal   *prometheus.CounterVec
	eventsFailed  *prometheus.CounterVec
	eventsRetried *prometheus.CounterVec

	mimirClientTiming *prometheus.HistogramVec
}

func (m *metrics) Register(r prometheus.Registerer) error {
	r.MustRegister(
		m.configUpdatesTotal,
		m.eventsTotal,
		m.eventsFailed,
		m.eventsRetried,
		m.mimirClientTiming,
	)
	return nil
}

func newMetrics() *metrics {
	return &metrics{
		configUpdatesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Subsystem: "mimir_alertmanager_configs",
			Name:      "config_updates_total",
			Help:      "Total number of times the configuration has been updated.",
		}),
		eventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Subsystem: "mimir_alertmanager_configs",
			Name:      "events_total",
			Help:      "Total number of events processed, partitioned by event type.",
		}, []string{"type"}),
		eventsFailed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Subsystem: "mimir_alertmanager_configs",
			Name:      "events_failed_total",
			Help:      "Total number of events that failed to be processed, even after retries, partitioned by event type.",
		}, []string{"type"}),
		eventsRetried: prometheus.NewCounterVec(prometheus.CounterOpts{
			Subsystem: "mimir_alertmanager_configs",
			Name:      "events_retried_total",
			Help:      "Total number of retries across all events, partitioned by event type.",
		}, []string{"type"}),
		mimirClientTiming: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Subsystem: "mimir_alertmanager_configs",
			Name:      "mimir_client_request_duration_seconds",
			Help:      "Duration of requests to the Mimir API.",
			Buckets:   instrument.DefBuckets,
		}, instrument.HistogramCollectorBuckets),
	}
}

type ConfigUpdate struct {
	args Arguments
	err  chan error
}

var _ component.Component = (*Component)(nil)
var _ component.DebugComponent = (*Component)(nil)
var _ component.HealthComponent = (*Component)(nil)

func NewComponent(o component.Options, args Arguments) (*Component, error) {
	metrics := newMetrics()
	err := metrics.Register(o.Registerer)
	if err != nil {
		return nil, fmt.Errorf("registering metrics failed: %w", err)
	}

	c := &Component{
		log:           o.Logger,
		opts:          o,
		args:          args,
		configUpdates: make(chan ConfigUpdate),
		ticker:        time.NewTicker(args.SyncInterval),
		metrics:       metrics,
	}

	err = c.init()
	if err != nil {
		return nil, fmt.Errorf("initializing component failed: %w", err)
	}

	return c, nil
}

func (c *Component) Run(ctx context.Context) error {
	err := c.startup(ctx)
	if err != nil {
		level.Error(c.log).Log("msg", "starting up component failed", "err", err)
		c.reportUnhealthy(err)
	}

	for {
		select {
		case update := <-c.configUpdates:
			c.metrics.configUpdatesTotal.Inc()
			c.shutdown()

			c.args = update.args
			err := c.init()
			if err != nil {
				level.Error(c.log).Log("msg", "updating configuration failed", "err", err)
				c.reportUnhealthy(err)
				update.err <- err
				continue
			}

			err = c.startup(ctx)
			if err != nil {
				level.Error(c.log).Log("msg", "updating configuration failed", "err", err)
				c.reportUnhealthy(err)
				update.err <- err
				continue
			}

			update.err <- nil
		case <-ctx.Done():
			c.shutdown()
			return nil
		case <-c.ticker.C:
			c.queue.Add(event{
				typ: eventTypeSyncMimir,
			})
		}
	}
}

// startup launches the informers and starts the event loop.
func (c *Component) startup(ctx context.Context) error {
	c.queue = workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "mimir.alertmanager_configs.kubernetes")
	c.informerStopChan = make(chan struct{})
	c.ctx = ctx

	c.startNamespaceInformer()
	c.startAlertmanagerConfigsInformer()
	err := c.syncMimir(ctx)
	if err != nil {
		return err
	}
	go c.eventLoop(ctx)
	return nil
}

func (c *Component) shutdown() {
	close(c.informerStopChan)
	c.queue.ShutDownWithDrain()
}

func (c *Component) Update(newConfig component.Arguments) error {
	errChan := make(chan error)
	c.configUpdates <- ConfigUpdate{
		args: newConfig.(Arguments),
		err:  errChan,
	}
	return <-errChan
}

func (c *Component) init() error {
	level.Info(c.log).Log("msg", "initializing with new configuration")

	// TODO: allow overriding some stuff in RestConfig and k8s client options?
	restConfig, err := controller.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get k8s config: %w", err)
	}

	c.k8sClient, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	c.promClient, err = promVersioned.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create prometheus operator client: %w", err)
	}

	c.objStore = cache.NewStore(assetKeyFunc)

	httpClient := c.args.HTTPClientConfig.Convert()

	c.mimirClient, err = mimirClient.New(c.log, mimirClient.Config{
		ID:               c.args.TenantID,
		Address:          c.args.Address,
		UseLegacyRoutes:  c.args.UseLegacyRoutes,
		HTTPClientConfig: *httpClient,
	}, c.metrics.mimirClientTiming)
	if err != nil {
		return err
	}

	c.ticker.Reset(c.args.SyncInterval)

	c.namespaceSelector, err = convertSelectorToListOptions(c.args.AlertmanagerConfigNamespaceSelector)
	if err != nil {
		return err
	}

	c.amConfigSelector, err = convertSelectorToListOptions(c.args.AlertmanagerConfigSelector)
	if err != nil {
		return err
	}

	return nil
}

func assetKeyFunc(obj interface{}) (string, error) {
	switch v := obj.(type) {
	case *v1.ConfigMap:
		return fmt.Sprintf("0/%s/%s", v.GetNamespace(), v.GetName()), nil
	case *v1.Secret:
		return fmt.Sprintf("1/%s/%s", v.GetNamespace(), v.GetName()), nil
	}
	return "", errors.Errorf("unsupported type: %T", obj)
}

func convertSelectorToListOptions(selector LabelSelector) (labels.Selector, error) {
	matchExpressions := []metav1.LabelSelectorRequirement{}

	for _, me := range selector.MatchExpressions {
		matchExpressions = append(matchExpressions, metav1.LabelSelectorRequirement{
			Key:      me.Key,
			Operator: metav1.LabelSelectorOperator(me.Operator),
			Values:   me.Values,
		})
	}

	return metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
		MatchLabels:      selector.MatchLabels,
		MatchExpressions: matchExpressions,
	})
}

func (c *Component) startNamespaceInformer() {
	factory := informers.NewSharedInformerFactoryWithOptions(
		c.k8sClient,
		24*time.Hour,
		informers.WithTweakListOptions(func(lo *metav1.ListOptions) {
			lo.LabelSelector = c.namespaceSelector.String()
		}),
	)

	namespaces := factory.Core().V1().Namespaces()
	c.namespaceLister = namespaces.Lister()
	c.namespaceInformer = namespaces.Informer()
	c.namespaceInformer.AddEventHandler(newQueuedEventHandler(c.log, c.queue))

	factory.Start(c.informerStopChan)
	factory.WaitForCacheSync(c.informerStopChan)
}

func (c *Component) startAlertmanagerConfigsInformer() {
	factory := promExternalVersions.NewSharedInformerFactoryWithOptions(
		c.promClient,
		24*time.Hour,
		promExternalVersions.WithTweakListOptions(func(lo *metav1.ListOptions) {
			lo.LabelSelector = c.amConfigSelector.String()
		}),
	)

	amConfigs := factory.Monitoring().V1alpha1().AlertmanagerConfigs()
	c.amConfigLister = amConfigs.Lister()
	c.amConfigInformer = amConfigs.Informer()
	c.amConfigInformer.AddEventHandler(newQueuedEventHandler(c.log, c.queue))

	factory.Start(c.informerStopChan)
	factory.WaitForCacheSync(c.informerStopChan)
}
