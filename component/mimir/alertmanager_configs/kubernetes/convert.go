package alertmanager_configs

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus-operator/prometheus-operator/pkg/alertmanager/validation"
	promv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	promv1alpha1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1alpha1"
	amConfig "github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/pkg/labels"
	"github.com/prometheus/alertmanager/timeinterval"
	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/sigv4"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// GetKey processes the given SecretOrConfigMap selector and returns the referenced data.
func (c *Component) GetKey(ctx context.Context, namespace string, sel promv1.SecretOrConfigMap) (string, error) {
	switch {
	case sel.Secret != nil:
		return c.GetSecretKey(ctx, namespace, *sel.Secret)
	case sel.ConfigMap != nil:
		return c.GetConfigMapKey(ctx, namespace, *sel.ConfigMap)
	default:
		return "", nil
	}
}

// GetConfigMapKey processes the given ConfigMapKeySelector and returns the referenced data.
func (c *Component) GetConfigMapKey(ctx context.Context, namespace string, sel v1.ConfigMapKeySelector) (string, error) {
	obj, exists, err := c.objStore.Get(&v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sel.Name,
			Namespace: namespace,
		},
	})
	if err != nil {
		return "", errors.Wrapf(err, "unexpected store error when getting configmap %q", sel.Name)
	}

	if !exists {
		cm, err := c.k8sClient.CoreV1().ConfigMaps(namespace).Get(ctx, sel.Name, metav1.GetOptions{})
		if err != nil {
			return "", errors.Wrapf(err, "unable to get configmap %q", sel.Name)
		}
		if err = c.objStore.Add(cm); err != nil {
			return "", errors.Wrapf(err, "unexpected store error when adding configmap %q", sel.Name)
		}
		obj = cm
	}

	cm := obj.(*v1.ConfigMap)
	if _, found := cm.Data[sel.Key]; !found {
		return "", errors.Errorf("key %q in configmap %q not found", sel.Key, sel.Name)
	}

	return cm.Data[sel.Key], nil
}

// GetSecretKey processes the given SecretKeySelector and returns the referenced data.
func (c *Component) GetSecretKey(ctx context.Context, namespace string, sel v1.SecretKeySelector) (string, error) {
	obj, exists, err := c.objStore.Get(&v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sel.Name,
			Namespace: namespace,
		},
	})
	if err != nil {
		return "", errors.Wrapf(err, "unexpected store error when getting secret %q", sel.Name)
	}

	if !exists {
		secret, err := c.k8sClient.CoreV1().Secrets(namespace).Get(ctx, sel.Name, metav1.GetOptions{})
		if err != nil {
			return "", errors.Wrapf(err, "unable to get secret %q", sel.Name)
		}
		if err = c.objStore.Add(secret); err != nil {
			return "", errors.Wrapf(err, "unexpected store error when adding secret %q", sel.Name)
		}
		obj = secret
	}

	secret := obj.(*v1.Secret)
	if _, found := secret.Data[sel.Key]; !found {
		return "", errors.Errorf("key %q in secret %q not found", sel.Key, sel.Name)
	}

	return string(secret.Data[sel.Key]), nil
}

func (c *Component) convertTLSConfig(ctx context.Context, in *promv1.SafeTLSConfig, crKey types.NamespacedName) *commoncfg.TLSConfig {
	out := commoncfg.TLSConfig{
		ServerName:         in.ServerName,
		InsecureSkipVerify: in.InsecureSkipVerify,
	}

	//TODO: fix these functions
	// if in.CA != (promv1.SecretOrConfigMap{}) {
	// 	out.CAFile = path.Join(tlsAssetsDir, assets.TLSAssetKeyFromSelector(crKey.Namespace, in.CA).String())
	// }
	// if in.Cert != (promv1.SecretOrConfigMap{}) {
	// 	out.CertFile = path.Join(tlsAssetsDir, assets.TLSAssetKeyFromSelector(crKey.Namespace, in.Cert).String())
	// }
	// if in.KeySecret != nil {
	// 	out.KeyFile = path.Join(tlsAssetsDir, assets.TLSAssetKeyFromSecretSelector(crKey.Namespace, in.KeySecret).String())
	// }

	return &out
}

func (c *Component) convertHTTPConfig(ctx context.Context, in promv1alpha1.HTTPConfig, crKey types.NamespacedName) (*commoncfg.HTTPClientConfig, error) {
	out := &commoncfg.HTTPClientConfig{
		FollowRedirects: *in.FollowRedirects,
	}

	outProxyURL, err := url.Parse(in.ProxyURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pagerduty url")
	}
	out.ProxyURL = commoncfg.URL{URL: outProxyURL}

	if in.BasicAuth != nil {
		username, err := c.GetSecretKey(ctx, crKey.Namespace, in.BasicAuth.Username)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get BasicAuth username")
		}

		password, err := c.GetSecretKey(ctx, crKey.Namespace, in.BasicAuth.Password)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get BasicAuth password")
		}

		if username != "" || password != "" {
			out.BasicAuth = &commoncfg.BasicAuth{Username: username, Password: commoncfg.Secret(password)}
		}
	}

	if in.Authorization != nil {
		credentials, err := c.GetSecretKey(ctx, crKey.Namespace, *in.Authorization.Credentials)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get Authorization credentials")
		}

		if credentials != "" {
			authorizationType := in.Authorization.Type
			if authorizationType == "" {
				authorizationType = "Bearer"
			}
			out.Authorization = &commoncfg.Authorization{Type: authorizationType, Credentials: commoncfg.Secret(credentials)}
		}
	}

	if in.TLSConfig != nil {
		out.TLSConfig = *c.convertTLSConfig(ctx, in.TLSConfig, crKey)
	}

	if in.BearerTokenSecret != nil {
		bearerToken, err := c.GetSecretKey(ctx, crKey.Namespace, *in.BearerTokenSecret)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get bearer token")
		}
		out.BearerToken = commoncfg.Secret(bearerToken)
	}

	if in.OAuth2 != nil {
		clientID, err := c.GetKey(ctx, crKey.Namespace, in.OAuth2.ClientID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get clientID")
		}

		clientSecret, err := c.GetSecretKey(ctx, crKey.Namespace, in.OAuth2.ClientSecret)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get client secret")
		}
		out.OAuth2 = &commoncfg.OAuth2{
			ClientID:       clientID,
			ClientSecret:   commoncfg.Secret(clientSecret),
			Scopes:         in.OAuth2.Scopes,
			TokenURL:       in.OAuth2.TokenURL,
			EndpointParams: in.OAuth2.EndpointParams,
		}
	}

	return out, nil
}

func (c *Component) getValidURLFromSecret(ctx context.Context, namespace string, selector v1.SecretKeySelector) (*url.URL, error) {
	getUrl, err := c.GetSecretKey(ctx, namespace, selector)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	getUrl = strings.TrimSpace(getUrl)
	if _, err := validation.ValidateURL(getUrl); err != nil {
		return nil, errors.Wrapf(err, "invalid URL %q in key %q from secret %q", getUrl, selector.Key, selector.Name)
	}
	outUrl, err := url.Parse(getUrl)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pagerduty url")
	}
	return outUrl, nil
}

// function that converts promv1alpha1.InhibitRule to amConfig.InhibitRule
func convertInhibitRule(inhibitRule promv1alpha1.InhibitRule, crKey types.NamespacedName) *amConfig.InhibitRule {
	var sourceMatchers amConfig.Matchers
	var targetMatchers amConfig.Matchers

	// todo (pgough) the following config are deprecated and can be removed when
	// support matrix has reached >= 0.22.0
	// sourceMatch := map[string]string{}
	// sourceMatchRE := map[string]string{}
	// targetMatch := map[string]string{}
	// targetMatchRE := map[string]string{}

	for _, sm := range inhibitRule.SourceMatch {

		matcher, err := labels.ParseMatcher(sm.String())
		if err != nil {
			// panic(err)
			continue
		}

		sourceMatchers = append(sourceMatchers, matcher)

		// sourceMatchers = append(sourceMatchers, &labels.Matcher{
		// 	Name:  sm.Name,
		// 	Value: sm.Value,
		// 	Type:  labels.MatchType(sm.MatchType),
		// })

		// prefer matchers to deprecated syntax
		// if sm.MatchType != "" {
		// 	sourceMatchers = append(sourceMatchers, sm)
		// 	continue
		// }

		// if matchersV2Allowed {
		// 	if sm.Regex {
		// 		sourceMatchers = append(sourceMatchers, inhibitRuleRegexToV2(sm.Name, sm.Value))
		// 	} else {
		// 		sourceMatchers = append(sourceMatchers, inhibitRuleToV2(sm.Name, sm.Value))
		// 	}
		// 	continue
		// }

		// if sm.Regex {
		// 	sourceMatchRE[sm.Name] = sm.Value
		// } else {
		// 	sourceMatch[sm.Name] = sm.Value
		// }
	}

	for _, tm := range inhibitRule.TargetMatch {

		matcher, err := labels.ParseMatcher(tm.String())
		if err != nil {
			// panic(err)
			continue
		}

		targetMatchers = append(targetMatchers, matcher)
		// prefer matchers to deprecated config
		// if tm.MatchType != "" {
		// 	targetMatchers = append(targetMatchers, tm.String())
		// 	continue
		// }

		// if matchersV2Allowed {
		// 	if tm.Regex {
		// 		targetMatchers = append(targetMatchers, inhibitRuleRegexToV2(tm.Name, tm.Value))
		// 	} else {
		// 		targetMatchers = append(targetMatchers, inhibitRuleToV2(tm.Name, tm.Value))
		// 	}
		// 	continue
		// }

		// if tm.Regex {
		// 	targetMatchRE[tm.Name] = tm.Value
		// } else {
		// 	targetMatch[tm.Name] = tm.Value
		// }
	}

	equal := model.LabelNames{}
	for _, e := range inhibitRule.Equal {
		equal = append(equal, model.LabelName(e))
	}

	outRule := &amConfig.InhibitRule{
		// SourceMatch: sourceMatch,
		// SourceMatchRE:  sourceMatchRE,
		SourceMatchers: sourceMatchers,
		// TargetMatch:    targetMatch,
		// TargetMatchRE:  targetMatchRE,
		TargetMatchers: targetMatchers,
		Equal:          equal,
	}

	//TODO: make this configurable
	nsMatcher, err := labels.NewMatcher(labels.MatchEqual, inhibitRuleNamespaceKey, crKey.Namespace)
	if err != nil {
		// panic(err)
	}

	if !contains(nsMatcher, outRule.SourceMatchers) {
		outRule.SourceMatchers = append(outRule.SourceMatchers, nsMatcher)
	}
	if !contains(nsMatcher, outRule.TargetMatchers) {
		outRule.TargetMatchers = append(outRule.TargetMatchers, nsMatcher)
	}

	return outRule
}

// function that converts *promv1alpha1.Route to *amConfig.Route
func (c *Component) convertRoute(in *promv1alpha1.Route, crKey types.NamespacedName) *amConfig.Route {
	if in == nil {
		return nil
	}
	var matchers amConfig.Matchers

	// deprecated
	// match := map[string]string{}
	// matchRE := map[string]string{}

	for _, matcher := range in.Matchers {
		// prefer matchers to deprecated config
		outMatcher, err := labels.ParseMatcher(matcher.String())
		if err != nil {
			// panic(err)
			continue
		}
		matchers = append(matchers, outMatcher)

		// if matcher.Regex {
		// 	matchRE[matcher.Name] = matcher.Value
		// } else {
		// 	match[matcher.Name] = matcher.Value
		// }
	}

	var routes []*amConfig.Route
	if len(in.Routes) > 0 {
		routes = make([]*amConfig.Route, len(in.Routes))
		children, err := in.ChildRoutes()
		if err != nil {
			// The controller should already have checked that ChildRoutes()
			// doesn't return an error when selecting AlertmanagerConfig CRDs.
			// If there's an error here, we have a serious bug in the code.
			panic(err)
		}
		for i := range children {
			routes[i] = c.convertRoute(&children[i], crKey)
		}
	}

	receiver := mimirMakeNamespacedString(c.args.MimirNameSpacePrefix, in.Receiver, crKey)

	var prefixedMuteTimeIntervals []string
	if len(in.MuteTimeIntervals) > 0 {
		for _, mti := range in.MuteTimeIntervals {
			prefixedMuteTimeIntervals = append(prefixedMuteTimeIntervals, mimirMakeNamespacedString(c.args.MimirNameSpacePrefix, mti, crKey))
		}
	}

	var prefixedActiveTimeIntervals []string
	if len(in.ActiveTimeIntervals) > 0 {
		for _, ati := range in.ActiveTimeIntervals {
			prefixedActiveTimeIntervals = append(prefixedActiveTimeIntervals, mimirMakeNamespacedString(c.args.MimirNameSpacePrefix, ati, crKey))
		}
	}

	outRoute := &amConfig.Route{
		Receiver:   receiver,
		GroupByStr: in.GroupBy,
		// TODO: check if there's a better way to set continue
		Continue: true, // Needs to be true to allow multiple routes to match.
		// Match:               match,
		// MatchRE:             matchRE,
		Matchers:            matchers,
		Routes:              routes,
		MuteTimeIntervals:   prefixedMuteTimeIntervals,
		ActiveTimeIntervals: prefixedActiveTimeIntervals,
	}

	if in.GroupWait != "" {
		groupWait, _ := time.ParseDuration(in.GroupWait)
		outGroupWait := model.Duration(groupWait)
		outRoute.GroupWait = &outGroupWait
	}

	if in.GroupInterval != "" {
		groupInterval, _ := time.ParseDuration(in.GroupInterval)
		outGroupInterval := model.Duration(groupInterval)
		outRoute.GroupInterval = &outGroupInterval
	}

	if in.RepeatInterval != "" {
		repeatInterval, _ := time.ParseDuration(in.RepeatInterval)
		outRepeatInterval := model.Duration(repeatInterval)
		outRoute.RepeatInterval = &outRepeatInterval
	}

	//TODO: make this configurable
	nsMatcher, err := labels.NewMatcher(labels.MatchEqual, inhibitRuleNamespaceKey, crKey.Namespace)
	if err != nil {
		// panic(err)
	}
	outRoute.Matchers = append(outRoute.Matchers, nsMatcher)

	return outRoute
}

// function that converts *promv1alpha1.Receiver to *amConfig.Receiver
func (c *Component) convertReceiver(ctx context.Context, in *promv1alpha1.Receiver, crKey types.NamespacedName) (*amConfig.Receiver, error) {
	if in == nil {
		return nil, nil
	}

	var pagerdutyConfigs []*amConfig.PagerdutyConfig

	if l := len(in.PagerDutyConfigs); l > 0 {
		pagerdutyConfigs = make([]*amConfig.PagerdutyConfig, l)
		for i := range in.PagerDutyConfigs {
			receiver, err := c.convertPagerdutyConfig(ctx, in.PagerDutyConfigs[i], crKey)
			if err != nil {
				return nil, errors.Wrapf(err, "PagerDutyConfig[%d]", i)
			}
			pagerdutyConfigs[i] = receiver
		}
	}

	var slackConfigs []*amConfig.SlackConfig
	if l := len(in.SlackConfigs); l > 0 {
		slackConfigs = make([]*amConfig.SlackConfig, l)
		for i := range in.SlackConfigs {
			receiver, err := c.convertSlackConfig(ctx, in.SlackConfigs[i], crKey)
			if err != nil {
				return nil, errors.Wrapf(err, "SlackConfig[%d]", i)
			}
			slackConfigs[i] = receiver
		}
	}

	var webhookConfigs []*amConfig.WebhookConfig
	if l := len(in.WebhookConfigs); l > 0 {
		webhookConfigs = make([]*amConfig.WebhookConfig, l)
		for i := range in.WebhookConfigs {
			receiver, err := c.convertWebhookConfig(ctx, in.WebhookConfigs[i], crKey)
			if err != nil {
				return nil, errors.Wrapf(err, "WebhookConfig[%d]", i)
			}
			webhookConfigs[i] = receiver
		}
	}

	var opsgenieConfigs []*amConfig.OpsGenieConfig
	if l := len(in.OpsGenieConfigs); l > 0 {
		opsgenieConfigs = make([]*amConfig.OpsGenieConfig, l)
		for i := range in.OpsGenieConfigs {
			receiver, err := c.convertOpsgenieConfig(ctx, in.OpsGenieConfigs[i], crKey)
			if err != nil {
				return nil, errors.Wrapf(err, "OpsGenieConfigs[%d]", i)
			}
			opsgenieConfigs[i] = receiver
		}
	}

	var weChatConfigs []*amConfig.WechatConfig
	if l := len(in.WeChatConfigs); l > 0 {
		weChatConfigs = make([]*amConfig.WechatConfig, l)
		for i := range in.WeChatConfigs {
			receiver, err := c.convertWeChatConfig(ctx, in.WeChatConfigs[i], crKey)
			if err != nil {
				return nil, errors.Wrapf(err, "WeChatConfig[%d]", i)
			}
			weChatConfigs[i] = receiver
		}
	}

	var emailConfigs []*amConfig.EmailConfig
	if l := len(in.EmailConfigs); l > 0 {
		emailConfigs = make([]*amConfig.EmailConfig, l)
		for i := range in.EmailConfigs {
			receiver, err := c.convertEmailConfig(ctx, in.EmailConfigs[i], crKey)
			if err != nil {
				return nil, errors.Wrapf(err, "EmailConfig[%d]", i)
			}
			emailConfigs[i] = receiver
		}
	}

	var victorOpsConfigs []*amConfig.VictorOpsConfig
	if l := len(in.VictorOpsConfigs); l > 0 {
		victorOpsConfigs = make([]*amConfig.VictorOpsConfig, l)
		for i := range in.VictorOpsConfigs {
			receiver, err := c.convertVictorOpsConfig(ctx, in.VictorOpsConfigs[i], crKey)
			if err != nil {
				return nil, errors.Wrapf(err, "VictorOpsConfig[%d]", i)
			}
			victorOpsConfigs[i] = receiver
		}
	}

	var pushoverConfigs []*amConfig.PushoverConfig
	if l := len(in.PushoverConfigs); l > 0 {
		pushoverConfigs = make([]*amConfig.PushoverConfig, l)
		for i := range in.PushoverConfigs {
			receiver, err := c.convertPushoverConfig(ctx, in.PushoverConfigs[i], crKey)
			if err != nil {
				return nil, errors.Wrapf(err, "PushoverConfig[%d]", i)
			}
			pushoverConfigs[i] = receiver
		}
	}

	var snsConfigs []*amConfig.SNSConfig
	if l := len(in.SNSConfigs); l > 0 {
		snsConfigs = make([]*amConfig.SNSConfig, l)
		for i := range in.SNSConfigs {
			receiver, err := c.convertSnsConfig(ctx, in.SNSConfigs[i], crKey)
			if err != nil {
				return nil, errors.Wrapf(err, "SNSConfig[%d]", i)
			}
			snsConfigs[i] = receiver
		}
	}

	var telegramConfigs []*amConfig.TelegramConfig
	if l := len(in.TelegramConfigs); l > 0 {
		telegramConfigs = make([]*amConfig.TelegramConfig, l)
		for i := range in.TelegramConfigs {
			receiver, err := c.convertTelegramConfig(ctx, in.TelegramConfigs[i], crKey)
			if err != nil {
				return nil, errors.Wrapf(err, "TelegramConfig[%d]", i)
			}
			telegramConfigs[i] = receiver
		}
	}

	return &amConfig.Receiver{
		Name:             mimirMakeNamespacedString(c.args.MimirNameSpacePrefix, in.Name, crKey),
		OpsGenieConfigs:  opsgenieConfigs,
		PagerdutyConfigs: pagerdutyConfigs,
		SlackConfigs:     slackConfigs,
		WebhookConfigs:   webhookConfigs,
		WechatConfigs:    weChatConfigs,
		EmailConfigs:     emailConfigs,
		VictorOpsConfigs: victorOpsConfigs,
		PushoverConfigs:  pushoverConfigs,
		SNSConfigs:       snsConfigs,
		TelegramConfigs:  telegramConfigs,
	}, nil
}

func convertMuteTimeInterval(in *promv1alpha1.MuteTimeInterval, crKey types.NamespacedName, prefix string) (*amConfig.MuteTimeInterval, error) {
	outMuteTimeInterval := &amConfig.MuteTimeInterval{}

	for _, muteTimeInterval := range in.TimeIntervals {
		ti := timeinterval.TimeInterval{}

		for _, time := range muteTimeInterval.Times {
			parsedTime, err := time.Parse()
			if err != nil {
				return nil, err
			}
			ti.Times = append(ti.Times, timeinterval.TimeRange{
				StartMinute: parsedTime.Start,
				EndMinute:   parsedTime.End,
			})
		}

		for _, wd := range muteTimeInterval.Weekdays {
			parsedWeekday, err := wd.Parse()
			if err != nil {
				return nil, err
			}
			ti.Weekdays = append(ti.Weekdays, timeinterval.WeekdayRange{
				InclusiveRange: timeinterval.InclusiveRange{
					Begin: parsedWeekday.Start,
					End:   parsedWeekday.End,
				},
			})
		}

		for _, dom := range muteTimeInterval.DaysOfMonth {
			ti.DaysOfMonth = append(ti.DaysOfMonth, timeinterval.DayOfMonthRange{
				InclusiveRange: timeinterval.InclusiveRange{
					Begin: dom.Start,
					End:   dom.End,
				},
			})
		}

		for _, month := range muteTimeInterval.Months {
			parsedMonth, err := month.Parse()
			if err != nil {
				return nil, err
			}
			ti.Months = append(ti.Months, timeinterval.MonthRange{
				InclusiveRange: timeinterval.InclusiveRange{
					Begin: parsedMonth.Start,
					End:   parsedMonth.End,
				},
			})
		}

		for _, year := range muteTimeInterval.Years {
			parsedYear, err := year.Parse()
			if err != nil {
				return nil, err
			}
			ti.Years = append(ti.Years, timeinterval.YearRange{
				InclusiveRange: timeinterval.InclusiveRange{
					Begin: parsedYear.Start,
					End:   parsedYear.End,
				},
			})
		}

		outMuteTimeInterval.Name = mimirMakeNamespacedString(prefix, in.Name, crKey)
		outMuteTimeInterval.TimeIntervals = append(outMuteTimeInterval.TimeIntervals, ti)
	}

	return outMuteTimeInterval, nil
}

func (c *Component) convertPagerdutyConfig(ctx context.Context, in promv1alpha1.PagerDutyConfig, crKey types.NamespacedName) (*amConfig.PagerdutyConfig, error) {
	out := &amConfig.PagerdutyConfig{
		NotifierConfig: amConfig.NotifierConfig{
			VSendResolved: *in.SendResolved,
		},
		Class:       in.Class,
		Client:      in.Client,
		ClientURL:   in.ClientURL,
		Component:   in.Component,
		Description: in.Description,
		Group:       in.Group,
		Severity:    in.Severity,
	}

	outUrl, err := url.Parse(in.URL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pagerduty url")
	}
	out.URL = &amConfig.URL{URL: outUrl}

	if in.RoutingKey != nil {
		routingKey, err := c.GetSecretKey(ctx, crKey.Namespace, *in.RoutingKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get routing key")
		}
		out.RoutingKey = amConfig.Secret(routingKey)
	}

	if in.ServiceKey != nil {
		serviceKey, err := c.GetSecretKey(ctx, crKey.Namespace, *in.ServiceKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get service key")
		}
		out.ServiceKey = amConfig.Secret(serviceKey)
	}

	var details map[string]string
	if l := len(in.Details); l > 0 {
		details = make(map[string]string, l)
		for _, d := range in.Details {
			details[d.Key] = d.Value
		}
	}
	out.Details = details

	var linkConfigs []amConfig.PagerdutyLink
	if l := len(in.PagerDutyLinkConfigs); l > 0 {
		linkConfigs = make([]amConfig.PagerdutyLink, l)
		for i, lc := range in.PagerDutyLinkConfigs {
			linkConfigs[i] = amConfig.PagerdutyLink{
				Href: lc.Href,
				Text: lc.Text,
			}
		}
	}
	out.Links = linkConfigs

	var imageConfig []amConfig.PagerdutyImage
	if l := len(in.PagerDutyImageConfigs); l > 0 {
		imageConfig = make([]amConfig.PagerdutyImage, l)
		for i, ic := range in.PagerDutyImageConfigs {
			imageConfig[i] = amConfig.PagerdutyImage{
				Src:  ic.Src,
				Alt:  ic.Alt,
				Href: ic.Href,
			}
		}
	}
	out.Images = imageConfig

	if in.HTTPConfig != nil {
		httpConfig, err := c.convertHTTPConfig(ctx, *in.HTTPConfig, crKey)
		if err != nil {
			return nil, err
		}
		out.HTTPConfig = httpConfig
	}

	return out, nil
}

func (c *Component) convertSlackConfig(ctx context.Context, in promv1alpha1.SlackConfig, crKey types.NamespacedName) (*amConfig.SlackConfig, error) {
	out := &amConfig.SlackConfig{
		NotifierConfig: amConfig.NotifierConfig{
			VSendResolved: *in.SendResolved,
		},
		Channel:     in.Channel,
		Username:    in.Username,
		Color:       in.Color,
		Title:       in.Title,
		TitleLink:   in.TitleLink,
		Pretext:     in.Pretext,
		Text:        in.Text,
		ShortFields: in.ShortFields,
		Footer:      in.Footer,
		Fallback:    in.Fallback,
		CallbackID:  in.CallbackID,
		IconEmoji:   in.IconEmoji,
		IconURL:     in.IconURL,
		ImageURL:    in.ImageURL,
		ThumbURL:    in.ThumbURL,
		LinkNames:   in.LinkNames,
		MrkdwnIn:    in.MrkdwnIn,
	}

	if in.APIURL != nil {
		getUrl, err := c.getValidURLFromSecret(ctx, crKey.Namespace, *in.APIURL)
		if err != nil {
			return nil, err
		}
		out.APIURL = &amConfig.SecretURL{URL: getUrl}
	}

	var actions []*amConfig.SlackAction
	if l := len(in.Actions); l > 0 {
		actions = make([]*amConfig.SlackAction, l)
		for i, a := range in.Actions {
			action := &amConfig.SlackAction{
				Type:  a.Type,
				Text:  a.Text,
				URL:   a.URL,
				Style: a.Style,
				Name:  a.Name,
				Value: a.Value,
			}

			if a.ConfirmField != nil {
				action.ConfirmField = &amConfig.SlackConfirmationField{
					Text:        a.ConfirmField.Text,
					Title:       a.ConfirmField.Title,
					OkText:      a.ConfirmField.OkText,
					DismissText: a.ConfirmField.DismissText,
				}
			}

			actions[i] = action
		}
		out.Actions = actions
	}

	if l := len(in.Fields); l > 0 {
		fields := make([]*amConfig.SlackField, l)
		for i, f := range in.Fields {
			field := &amConfig.SlackField{
				Title: f.Title,
				Value: f.Value,
			}

			if f.Short != nil {
				field.Short = f.Short
			}
			fields[i] = field
		}
		out.Fields = fields
	}

	if in.HTTPConfig != nil {
		httpConfig, err := c.convertHTTPConfig(ctx, *in.HTTPConfig, crKey)
		if err != nil {
			return nil, err
		}
		out.HTTPConfig = httpConfig
	}

	return out, nil
}

func (c *Component) convertWebhookConfig(ctx context.Context, in promv1alpha1.WebhookConfig, crKey types.NamespacedName) (*amConfig.WebhookConfig, error) {
	out := &amConfig.WebhookConfig{
		NotifierConfig: amConfig.NotifierConfig{
			VSendResolved: *in.SendResolved,
		},
	}

	if in.URLSecret != nil {
		getUrl, err := c.getValidURLFromSecret(ctx, crKey.Namespace, *in.URLSecret)
		if err != nil {
			return nil, err
		}
		out.URL = &amConfig.URL{URL: getUrl}
	} else if in.URL != nil {
		getUrl, err := validation.ValidateURL(*in.URL)
		if err != nil {
			return nil, err
		}
		out.URL = getUrl
	}

	if in.HTTPConfig != nil {
		httpConfig, err := c.convertHTTPConfig(ctx, *in.HTTPConfig, crKey)
		if err != nil {
			return nil, err
		}
		out.HTTPConfig = httpConfig
	}

	if in.MaxAlerts > 0 {
		out.MaxAlerts = uint64(in.MaxAlerts)
	}

	return out, nil
}

func (c *Component) convertOpsgenieConfig(ctx context.Context, in promv1alpha1.OpsGenieConfig, crKey types.NamespacedName) (*amConfig.OpsGenieConfig, error) {
	out := &amConfig.OpsGenieConfig{
		NotifierConfig: amConfig.NotifierConfig{
			VSendResolved: *in.SendResolved,
		},
		Message:     in.Message,
		Description: in.Description,
		Source:      in.Source,
		Tags:        in.Tags,
		Note:        in.Note,
		Priority:    in.Priority,
		Actions:     in.Actions,
		Entity:      in.Entity,
		// UpdateAlerts: in.UpdateAlerts, //TODO: seems to be removed in v1alpha1
	}
	outAPIURL, err := url.Parse(in.APIURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pagerduty url")
	}
	out.APIURL = &amConfig.URL{URL: outAPIURL}

	if in.APIKey != nil {
		apiKey, err := c.GetSecretKey(ctx, crKey.Namespace, *in.APIKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get API key")
		}
		out.APIKey = amConfig.Secret(apiKey)
	}

	var details map[string]string
	if l := len(in.Details); l > 0 {
		details = make(map[string]string, l)
		for _, d := range in.Details {
			details[d.Key] = d.Value
		}
	}
	out.Details = details

	var responders []amConfig.OpsGenieConfigResponder
	if l := len(in.Responders); l > 0 {
		responders = make([]amConfig.OpsGenieConfigResponder, 0, l)
		for _, r := range in.Responders {
			responder := amConfig.OpsGenieConfigResponder{
				ID:       r.ID,
				Name:     r.Name,
				Username: r.Username,
				Type:     r.Type,
			}
			responders = append(responders, responder)
		}
	}
	out.Responders = responders

	if in.HTTPConfig != nil {
		httpConfig, err := c.convertHTTPConfig(ctx, *in.HTTPConfig, crKey)
		if err != nil {
			return nil, err
		}
		out.HTTPConfig = httpConfig
	}

	return out, nil
}

func (c *Component) convertWeChatConfig(ctx context.Context, in promv1alpha1.WeChatConfig, crKey types.NamespacedName) (*amConfig.WechatConfig, error) {
	out := &amConfig.WechatConfig{
		NotifierConfig: amConfig.NotifierConfig{
			VSendResolved: *in.SendResolved,
		},
		CorpID:      in.CorpID,
		AgentID:     in.AgentID,
		ToUser:      in.ToUser,
		ToParty:     in.ToParty,
		ToTag:       in.ToTag,
		Message:     in.Message,
		MessageType: in.MessageType,
	}
	outAPIURL, err := url.Parse(in.APIURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pagerduty url")
	}
	out.APIURL = &amConfig.URL{URL: outAPIURL}

	if in.APISecret != nil {
		apiSecret, err := c.GetSecretKey(ctx, crKey.Namespace, *in.APISecret)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get API secret")
		}
		out.APISecret = amConfig.Secret(apiSecret)
	}

	if in.HTTPConfig != nil {
		httpConfig, err := c.convertHTTPConfig(ctx, *in.HTTPConfig, crKey)
		if err != nil {
			return nil, err
		}
		out.HTTPConfig = httpConfig
	}

	return out, nil
}

func (c *Component) convertEmailConfig(ctx context.Context, in promv1alpha1.EmailConfig, crKey types.NamespacedName) (*amConfig.EmailConfig, error) {
	out := &amConfig.EmailConfig{
		NotifierConfig: amConfig.NotifierConfig{
			VSendResolved: *in.SendResolved,
		},
		To:           in.To,
		From:         in.From,
		Hello:        in.Hello,
		AuthUsername: in.AuthUsername,
		AuthIdentity: in.AuthIdentity,
		HTML:         in.HTML,
		Text:         in.Text,
		RequireTLS:   in.RequireTLS,
	}

	if in.Smarthost != "" {
		out.Smarthost.Host, out.Smarthost.Port, _ = net.SplitHostPort(in.Smarthost)
	}

	if in.AuthPassword != nil {
		authPassword, err := c.GetSecretKey(ctx, crKey.Namespace, *in.AuthPassword)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get auth password")
		}
		out.AuthPassword = amConfig.Secret(authPassword)
	}

	if in.AuthSecret != nil {
		authSecret, err := c.GetSecretKey(ctx, crKey.Namespace, *in.AuthSecret)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get auth secret")
		}
		out.AuthSecret = amConfig.Secret(authSecret)
	}

	if l := len(in.Headers); l > 0 {
		headers := make(map[string]string, l)
		for _, d := range in.Headers {
			headers[d.Key] = d.Value
		}
		out.Headers = headers
	}

	if in.TLSConfig != nil {
		out.TLSConfig = *c.convertTLSConfig(ctx, in.TLSConfig, crKey)
	}

	return out, nil
}

func (c *Component) convertVictorOpsConfig(ctx context.Context, in promv1alpha1.VictorOpsConfig, crKey types.NamespacedName) (*amConfig.VictorOpsConfig, error) {
	out := &amConfig.VictorOpsConfig{
		NotifierConfig: amConfig.NotifierConfig{
			VSendResolved: *in.SendResolved,
		},
		RoutingKey:        in.RoutingKey,
		MessageType:       in.MessageType,
		EntityDisplayName: in.EntityDisplayName,
		StateMessage:      in.StateMessage,
		MonitoringTool:    in.MonitoringTool,
	}
	outAPIURL, err := url.Parse(in.APIURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pagerduty url")
	}
	out.APIURL = &amConfig.URL{URL: outAPIURL}

	if in.APIKey != nil {
		apiKey, err := c.GetSecretKey(ctx, crKey.Namespace, *in.APIKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get API key")
		}
		out.APIKey = amConfig.Secret(apiKey)
	}

	var customFields map[string]string
	if l := len(in.CustomFields); l > 0 {
		// from https://github.com/prometheus/alertmanager/blob/a7f9fdadbecbb7e692d2cd8d3334e3d6de1602e1/config/notifiers.go#L497
		reservedFields := map[string]struct{}{
			"routing_key":         {},
			"message_type":        {},
			"state_message":       {},
			"entity_display_name": {},
			"monitoring_tool":     {},
			"entity_id":           {},
			"entity_state":        {},
		}
		customFields = make(map[string]string, l)
		for _, d := range in.CustomFields {
			if _, ok := reservedFields[d.Key]; ok {
				return nil, errors.Errorf("VictorOps config contains custom field %s which cannot be used as it conflicts with the fixed/static fields", d.Key)
			}
			customFields[d.Key] = d.Value
		}
	}
	out.CustomFields = customFields

	if in.HTTPConfig != nil {
		httpConfig, err := c.convertHTTPConfig(ctx, *in.HTTPConfig, crKey)
		if err != nil {
			return nil, err
		}
		out.HTTPConfig = httpConfig
	}
	return out, nil
}

func (c *Component) convertPushoverConfig(ctx context.Context, in promv1alpha1.PushoverConfig, crKey types.NamespacedName) (*amConfig.PushoverConfig, error) {
	out := &amConfig.PushoverConfig{
		NotifierConfig: amConfig.NotifierConfig{
			VSendResolved: *in.SendResolved,
		},
		Title:    in.Title,
		Message:  in.Message,
		URL:      in.URL,
		URLTitle: in.URLTitle,
		Priority: in.Priority,
		HTML:     in.HTML,
	}

	{
		userKey, err := c.GetSecretKey(ctx, crKey.Namespace, *in.UserKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get user key")
		}
		if userKey == "" {
			return nil, errors.Errorf("mandatory field %q is empty", "userKey")
		}
		out.UserKey = amConfig.Secret(userKey)
	}

	{
		token, err := c.GetSecretKey(ctx, crKey.Namespace, *in.Token)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get token")
		}
		if token == "" {
			return nil, errors.Errorf("mandatory field %q is empty", "token")
		}
		out.Token = amConfig.Secret(token)
	}

	{
		if in.Retry != "" {
			// retry, _ := time.ParseDuration(in.Retry)
			// out.Retry = amConfig.duration(retry) // TODO: this field isn't exported and can't be set
		}

		if in.Expire != "" {
			// 	expire, _ := time.ParseDuration(in.Expire)
			// 	out.Expire = duration(expire) // TODO: this field isn't exported and can't be set
		}
	}

	if in.HTTPConfig != nil {
		httpConfig, err := c.convertHTTPConfig(ctx, *in.HTTPConfig, crKey)
		if err != nil {
			return nil, err
		}
		out.HTTPConfig = httpConfig
	}

	return out, nil
}

func (c *Component) convertTelegramConfig(ctx context.Context, in promv1alpha1.TelegramConfig, crKey types.NamespacedName) (*amConfig.TelegramConfig, error) {
	out := &amConfig.TelegramConfig{
		NotifierConfig: amConfig.NotifierConfig{
			VSendResolved: *in.SendResolved,
		},
		ChatID:               in.ChatID,
		Message:              in.Message,
		DisableNotifications: false,
		ParseMode:            in.ParseMode,
	}
	outAPIURL, err := url.Parse(in.APIURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pagerduty url")
	}
	out.APIUrl = &amConfig.URL{URL: outAPIURL}

	if in.HTTPConfig != nil {
		httpConfig, err := c.convertHTTPConfig(ctx, *in.HTTPConfig, crKey)
		if err != nil {
			return nil, err
		}
		out.HTTPConfig = httpConfig
	}

	if in.BotToken != nil {
		botToken, err := c.GetSecretKey(ctx, crKey.Namespace, *in.BotToken)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get bot token")
		}
		if botToken == "" {
			return nil, fmt.Errorf("mandatory field %q is empty", "botToken")
		}
		out.BotToken = amConfig.Secret(botToken)
	}

	return out, nil
}

func (c *Component) convertSnsConfig(ctx context.Context, in promv1alpha1.SNSConfig, crKey types.NamespacedName) (*amConfig.SNSConfig, error) {
	out := &amConfig.SNSConfig{
		NotifierConfig: amConfig.NotifierConfig{
			VSendResolved: *in.SendResolved,
		},
		APIUrl:      in.ApiURL,
		TopicARN:    in.TopicARN,
		PhoneNumber: in.PhoneNumber,
		TargetARN:   in.TargetARN,
		Subject:     in.Subject,
		Message:     in.Message,
		Attributes:  in.Attributes,
	}

	if in.HTTPConfig != nil {
		httpConfig, err := c.convertHTTPConfig(ctx, *in.HTTPConfig, crKey)
		if err != nil {
			return nil, err
		}
		out.HTTPConfig = httpConfig
	}

	if in.Sigv4 != nil {
		out.Sigv4 = sigv4.SigV4Config{
			Region:  in.Sigv4.Region,
			Profile: in.Sigv4.Profile,
			RoleARN: in.Sigv4.RoleArn,
		}

		if in.Sigv4.AccessKey != nil && in.Sigv4.SecretKey != nil {
			accessKey, err := c.GetSecretKey(ctx, crKey.Namespace, *in.Sigv4.AccessKey)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get access key")
			}

			secretKey, err := c.GetSecretKey(ctx, crKey.Namespace, *in.Sigv4.SecretKey)
			if err != nil {
				return nil, errors.Wrap(err, "failed to get AWS secret key")

			}
			out.Sigv4.AccessKey = accessKey
			out.Sigv4.SecretKey = commoncfg.Secret(secretKey)
		}
	}

	return out, nil
}

// sanitize the config against a specific Alertmanager version
// types may be sanitized in one of two ways:
// 1. stripping the unsupported config and log a warning
// 2. error which ensures that config will not be reconciled - this will be logged by a calling function
// func sanitizeConfig(cfg *amConfig.Config, amVersion semver.Version, logger log.Logger) error {
// 	if cfg == nil {
// 		return nil
// 	}

// 	if err := sanitizeGlobalConfig(cfg.Global, amVersion, logger); err != nil {
// 		return err
// 	}

// 	for _, receiver := range cfg.Receivers {
// 		if err := sanitizeReceiver(receiver, amVersion, logger); err != nil {
// 			return err
// 		}
// 	}

// 	for i, rule := range cfg.InhibitRules {
// 		if err := rule.sanitize(amVersion, logger); err != nil {
// 			return errors.Wrapf(err, "inhibit_rules[%d]", i)
// 		}
// 	}

// 	if len(cfg.MuteTimeIntervals) > 0 && amVersion.LT(semver.MustParse("0.22.0")) {
// 		// mute time intervals are unsupported < 0.22.0, and we already log the situation
// 		// when handling the routes so just set to nil
// 		cfg.MuteTimeIntervals = nil
// 	}

// 	if len(cfg.TimeIntervals) > 0 && amVersion.LT(semver.MustParse("0.24.0")) {
// 		// time intervals are unsupported < 0.24.0, and we already log the situation
// 		// when handling the routes so just set to nil
// 		cfg.TimeIntervals = nil
// 	}

// 	for _, ti := range cfg.MuteTimeIntervals {
// 		if err := ti.sanitize(amVersion, logger); err != nil {
// 			return errors.Wrapf(err, "mute_time_intervals[%s]", ti.Name)
// 		}
// 	}

// 	for _, ti := range cfg.TimeIntervals {
// 		if err := ti.sanitize(amVersion, logger); err != nil {
// 			return errors.Wrapf(err, "time_intervals[%s]", ti.Name)
// 		}
// 	}

// 	return cfg.Route.sanitize(amVersion, logger)
// }

// // sanitize globalConfig
// func sanitizeGlobalConfig(gc *amConfig.GlobalConfig, amVersion semver.Version, logger log.Logger) error {
// 	if gc == nil {
// 		return nil
// 	}

// 	if gc.HTTPConfig != nil {
// 		if err := sanitizeHttpClientConfig(gc.HTTPConfig, amVersion, logger); err != nil {
// 			return err
// 		}
// 	}

// 	// We need to sanitize the config for slack globally
// 	// As of v0.22.0 Alertmanager config supports passing URL via file name
// 	if gc.SlackAPIURLFile != "" {
// 		if gc.SlackAPIURL != nil {
// 			msg := "'slack_api_url' and 'slack_api_url_file' are mutually exclusive - 'slack_api_url' has taken precedence"
// 			level.Warn(logger).Log("msg", msg)
// 			gc.SlackAPIURLFile = ""
// 		}

// 		if amVersion.LT(semver.MustParse("0.22.0")) {
// 			msg := "'slack_api_url_file' supported in Alertmanager >= 0.22.0 only - dropping field from provided config"
// 			level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 			gc.SlackAPIURLFile = ""
// 		}
// 	}

// 	if gc.OpsGenieAPIKeyFile != "" && amVersion.LT(semver.MustParse("0.24.0")) {
// 		msg := "'opsgenie_api_key_file' supported in Alertmanager >= 0.24.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		gc.OpsGenieAPIKeyFile = ""
// 	}

// 	if gc.SMTPAuthPasswordFile != "" && amVersion.LT(semver.MustParse("0.25.0")) {
// 		msg := "'smtp_auth_password_file' supported in Alertmanager >= 0.25.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		gc.SMTPAuthPasswordFile = ""
// 	}

// 	if gc.SMTPAuthPassword != "" && gc.SMTPAuthPasswordFile != "" {
// 		msg := "'smtp_auth_password' and 'smtp_auth_password_file' are mutually exclusive - 'smtp_auth_password' has taken precedence"
// 		level.Warn(logger).Log("msg", msg)
// 		gc.SMTPAuthPasswordFile = ""
// 	}

// 	if gc.VictorOpsAPIKeyFile != "" && amVersion.LT(semver.MustParse("0.25.0")) {
// 		msg := "'victorops_api_key_file' supported in Alertmanager >= 0.25.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		gc.VictorOpsAPIKeyFile = ""
// 	}

// 	if gc.VictorOpsAPIKey != "" && gc.VictorOpsAPIKeyFile != "" {
// 		msg := "'victorops_api_key' and 'victorops_api_key_file' are mutually exclusive - 'victorops_api_key' has taken precedence"
// 		level.Warn(logger).Log("msg", msg)
// 		gc.VictorOpsAPIKeyFile = ""
// 	}

// 	return nil
// }

// func sanitizeHttpClientConfig(hc *commoncfg.HTTPClientConfig, amVersion semver.Version, logger log.Logger) error {
// 	if hc == nil {
// 		return nil
// 	}

// 	if hc.Authorization != nil && !amVersion.GTE(semver.MustParse("0.22.0")) {
// 		return fmt.Errorf("'authorization' set in 'http_config' but supported in Alertmanager >= 0.22.0 only")
// 	}

// 	if hc.OAuth2 != nil && !amVersion.GTE(semver.MustParse("0.22.0")) {
// 		return fmt.Errorf("'oauth2' set in 'http_config' but supported in Alertmanager >= 0.22.0 only")
// 	}

// 	if hc.FollowRedirects != false && !amVersion.GTE(semver.MustParse("0.22.0")) {
// 		msg := "'follow_redirects' set in 'http_config' but supported in Alertmanager >= 0.22.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		hc.FollowRedirects = false
// 	}

// 	if hc.EnableHTTP2 != false && !amVersion.GTE(semver.MustParse("0.25.0")) {
// 		msg := "'enable_http2' set in 'http_config' but supported in Alertmanager >= 0.25.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		hc.EnableHTTP2 = false
// 	}

// 	// TODO: check if this pointer initialization is necessary and doesn't break anything
// 	if err := sanitizeTLSConfig(&hc.TLSConfig, amVersion, logger); err != nil {
// 		return err
// 	}

// 	return sanitizeOAuth2(hc.OAuth2, amVersion, logger)
// }

// var tlsVersions = map[string]int{
// 	"":      0x0000,
// 	"TLS13": tls.VersionTLS13,
// 	"TLS12": tls.VersionTLS12,
// 	"TLS11": tls.VersionTLS11,
// 	"TLS10": tls.VersionTLS10,
// }

// func sanitizeTLSConfig(tc *commoncfg.TLSConfig, amVersion semver.Version, logger log.Logger) error {
// 	if tc == nil {
// 		return nil
// 	}

// 	if tc.MinVersion.String() != "" && !amVersion.GTE(semver.MustParse("0.25.0")) {
// 		msg := "'min_version' set in 'tls_config' but supported in Alertmanager >= 0.25.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		tc.MinVersion = commoncfg.TLSVersion(0x0000)
// 	}

// 	if tc.MaxVersion.String() != "" && !amVersion.GTE(semver.MustParse("0.25.0")) {
// 		msg := "'max_version' set in 'tls_config' but supported in Alertmanager >= 0.25.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		tc.MaxVersion = commoncfg.TLSVersion(0x0000)
// 	}

// 	minVersion, found := tlsVersions[tc.MinVersion.String()]
// 	if !found {
// 		return fmt.Errorf("unknown TLS version: %s", tc.MinVersion)
// 	}

// 	maxVersion, found := tlsVersions[tc.MaxVersion.String()]
// 	if !found {
// 		return fmt.Errorf("unknown TLS version: %s", tc.MaxVersion)
// 	}

// 	if minVersion != 0 && maxVersion != 0 && minVersion > maxVersion {
// 		return fmt.Errorf("max TLS version %q must be greater than or equal to min TLS version %q", tc.MaxVersion, tc.MinVersion)
// 	}

// 	return nil
// }

// func sanitizeOAuth2(o *commoncfg.OAuth2, amVersion semver.Version, logger log.Logger) error {
// 	if o == nil {
// 		return nil
// 	}

// 	if o.ProxyURL.String() != "" && !amVersion.GTE(semver.MustParse("0.25.0")) {
// 		msg := "'proxy_url' set in 'oauth2' but supported in Alertmanager >= 0.25.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		o.ProxyURL = commoncfg.URL{}
// 	}

// 	return nil
// }

// // sanitize the receiver
// func sanitizeReceiver(r *amConfig.Receiver, amVersion semver.Version, logger log.Logger) error {
// 	if r == nil {
// 		return nil
// 	}
// 	withLogger := log.With(logger, "receiver", r.Name)

// 	for _, conf := range r.EmailConfigs {
// 		if err := sanitizeEmailConfig(conf, amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	for _, conf := range r.OpsGenieConfigs {
// 		if err := sanitizeOpsGenieConfigs(conf, amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	for _, conf := range r.PagerdutyConfigs {
// 		if err := conf.sanitize(amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	for _, conf := range r.PushoverConfigs {
// 		if err := conf.sanitize(amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	for _, conf := range r.SlackConfigs {
// 		if err := conf.sanitize(amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	for _, conf := range r.VictorOpsConfigs {
// 		if err := conf.sanitize(amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	for _, conf := range r.WebhookConfigs {
// 		if err := conf.sanitize(amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	for _, conf := range r.WeChatConfigs {
// 		if err := conf.sanitize(amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	for _, conf := range r.SNSConfigs {
// 		if err := conf.sanitize(amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	for _, conf := range r.TelegramConfigs {
// 		if err := conf.sanitize(amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	for _, conf := range r.DiscordConfigs {
// 		if err := conf.sanitize(amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	for _, conf := range r.WebexConfigs {
// 		if err := conf.sanitize(amVersion, withLogger); err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }

// func sanitizeEmailConfig(ec *amConfig.EmailConfig, amVersion semver.Version, logger log.Logger) error {
// 	if ec.AuthPasswordFile != "" && amVersion.LT(semver.MustParse("0.25.0")) {
// 		msg := "'auth_password_file' supported in Alertmanager >= 0.25.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		ec.AuthPasswordFile = ""
// 	}

// 	if ec.AuthPassword != "" && ec.AuthPasswordFile != "" {
// 		level.Warn(logger).Log("msg", "'auth_password' and 'auth_password_file' are mutually exclusive for email receiver config - 'auth_password' has taken precedence")
// 		ec.AuthPasswordFile = ""
// 	}

// 	return nil
// }

// func sanitizeOpsGenieConfigs(ogc *amConfig.OpsGenieConfig, amVersion semver.Version, logger log.Logger) error {
// 	if err := sanitizeHttpClientConfig(ogc.HTTPConfig, amVersion, logger); err != nil {
// 		return err
// 	}

// 	lessThanV0_24 := amVersion.LT(semver.MustParse("0.24.0"))

// 	if ogc.Actions != "" && lessThanV0_24 {
// 		msg := "opsgenie_config 'actions' supported in Alertmanager >= 0.24.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		ogc.Actions = ""
// 	}

// 	if ogc.Entity != "" && lessThanV0_24 {
// 		msg := "opsgenie_config 'entity' supported in Alertmanager >= 0.24.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		ogc.Entity = ""
// 	}
// 	if ogc.UpdateAlerts != nil && lessThanV0_24 {
// 		msg := "update_alerts 'entity' supported in Alertmanager >= 0.24.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		ogc.UpdateAlerts = nil
// 	}
// 	for _, responder := range ogc.Responders {
// 		if err := responder.sanitize(amVersion, logger); err != nil {
// 			return err
// 		}
// 	}

// 	if ogc.APIKey != "" && ogc.APIKeyFile != "" {
// 		level.Warn(logger).Log("msg", "'api_key' and 'api_key_file' are mutually exclusive for OpsGenie receiver config - 'api_key' has taken precedence")
// 		ogc.APIKeyFile = ""
// 	}

// 	if ogc.APIKeyFile == "" {
// 		return nil
// 	}

// 	if lessThanV0_24 {
// 		msg := "'api_key_file' supported in Alertmanager >= 0.24.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		ogc.APIKeyFile = ""
// 	}

// 	return nil
// }

// func (ops *opsgenieResponder) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	if ops.Type == "teams" && amVersion.LT(semver.MustParse("0.24.0")) {
// 		return fmt.Errorf("'teams' set in 'opsgenieResponder' but supported in Alertmanager >= 0.24.0 only")
// 	}
// 	return nil
// }

// func (pdc *pagerdutyConfig) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	lessThanV0_25 := amVersion.LT(semver.MustParse("0.25.0"))

// 	if pdc.Source != "" && lessThanV0_25 {
// 		msg := "'source' supported in Alertmanager >= 0.25.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		pdc.Source = ""
// 	}

// 	if pdc.RoutingKeyFile != "" && lessThanV0_25 {
// 		msg := "'routing_key_file' supported in Alertmanager >= 0.25.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		pdc.RoutingKeyFile = ""
// 	}

// 	if pdc.ServiceKeyFile != "" && lessThanV0_25 {
// 		msg := "'service_key_file' supported in Alertmanager >= 0.25.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		pdc.ServiceKeyFile = ""
// 	}

// 	if pdc.ServiceKey != "" && pdc.ServiceKeyFile != "" {
// 		msg := "'service_key' and 'service_key_file' are mutually exclusive for pagerdury receiver config - 'service_key' has taken precedence"
// 		level.Warn(logger).Log("msg", msg)
// 		pdc.ServiceKeyFile = ""
// 	}

// 	if pdc.RoutingKey != "" && pdc.RoutingKeyFile != "" {
// 		msg := "'routing_key' and 'routing_key_file' are mutually exclusive for pagerdury receiver config - 'routing_key' has taken precedence"
// 		level.Warn(logger).Log("msg", msg)
// 		pdc.RoutingKeyFile = ""
// 	}

// 	return pdc.HTTPConfig.sanitize(amVersion, logger)
// }

// func (poc *pushoverConfig) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	return poc.HTTPConfig.sanitize(amVersion, logger)
// }

// func (sc *slackConfig) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	if err := sc.HTTPConfig.sanitize(amVersion, logger); err != nil {
// 		return err
// 	}

// 	if sc.APIURLFile == "" {
// 		return nil
// 	}

// 	// We need to sanitize the config for slack receivers
// 	// As of v0.22.0 Alertmanager config supports passing URL via file name
// 	if sc.APIURLFile != "" && amVersion.LT(semver.MustParse("0.22.0")) {
// 		msg := "'api_url_file' supported in Alertmanager >= 0.22.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		sc.APIURLFile = ""
// 	}

// 	if sc.APIURL != "" && sc.APIURLFile != "" {
// 		msg := "'api_url' and 'api_url_file' are mutually exclusive for slack receiver config - 'api_url' has taken precedence"
// 		level.Warn(logger).Log("msg", msg)
// 		sc.APIURLFile = ""
// 	}

// 	return nil
// }

// func (voc *victorOpsConfig) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	if err := voc.HTTPConfig.sanitize(amVersion, logger); err != nil {
// 		return err
// 	}

// 	if voc.APIKeyFile != "" && amVersion.LT(semver.MustParse("0.25.0")) {
// 		msg := "'api_key_file' supported in Alertmanager >= 0.25.0 only - dropping field from provided config"
// 		level.Warn(logger).Log("msg", msg, "current_version", amVersion.String())
// 		voc.APIKeyFile = ""
// 	}

// 	if voc.APIKey != "" && voc.APIKeyFile != "" {
// 		msg := "'api_key' and 'api_key_file' are mutually exclusive for victorops receiver config - 'api_url' has taken precedence"
// 		level.Warn(logger).Log("msg", msg)
// 		voc.APIKeyFile = ""
// 	}

// 	return nil
// }

// func (whc *webhookConfig) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	return whc.HTTPConfig.sanitize(amVersion, logger)
// }

// func (wcc *weChatConfig) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	return wcc.HTTPConfig.sanitize(amVersion, logger)
// }

// func (sc *snsConfig) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	return sc.HTTPConfig.sanitize(amVersion, logger)
// }

// func (tc *telegramConfig) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	telegramAllowed := amVersion.GTE(semver.MustParse("0.24.0"))
// 	if !telegramAllowed {
// 		return fmt.Errorf(`invalid syntax in receivers config; telegram integration is available in Alertmanager >= 0.24.0`)
// 	}

// 	if tc.ChatID == 0 {
// 		return errors.Errorf("mandatory field %q is empty", "chatID")
// 	}

// 	if tc.BotToken == "" {
// 		return fmt.Errorf("mandatory field %q is empty", "botToken")
// 	}

// 	return tc.HTTPConfig.sanitize(amVersion, logger)
// }

// func (tc *discordConfig) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	discordAllowed := amVersion.GTE(semver.MustParse("0.25.0"))
// 	if !discordAllowed {
// 		return fmt.Errorf(`invalid syntax in receivers config; discord integration is available in Alertmanager >= 0.25.0`)
// 	}

// 	return tc.HTTPConfig.sanitize(amVersion, logger)
// }

// func (tc *webexConfig) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	webexAllowed := amVersion.GTE(semver.MustParse("0.25.0"))
// 	if !webexAllowed {
// 		return fmt.Errorf(`invalid syntax in receivers config; webex integration is available in Alertmanager >= 0.25.0`)
// 	}

// 	if tc.RoomID == "" {
// 		return errors.Errorf("mandatory field %q is empty", "room_id")
// 	}

// 	return tc.HTTPConfig.sanitize(amVersion, logger)
// }

// func (ir *inhibitRule) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	matchersV2Allowed := amVersion.GTE(semver.MustParse("0.22.0"))

// 	if !matchersV2Allowed {
// 		// check if rule has provided invalid syntax and error if true
// 		if checkNotEmptyStrSlice(ir.SourceMatchers, ir.TargetMatchers) {
// 			msg := fmt.Sprintf(`target_matchers and source_matchers matching is supported in Alertmanager >= 0.22.0 only (target_matchers=%v, source_matchers=%v)`, ir.TargetMatchers, ir.SourceMatchers)
// 			return errors.New(msg)
// 		}
// 		return nil
// 	}

// 	// we log a warning if the rule continues to use deprecated values in addition
// 	// to the namespace label we have injected - but we won't convert these
// 	if checkNotEmptyMap(ir.SourceMatch, ir.TargetMatch, ir.SourceMatchRE, ir.TargetMatchRE) {
// 		msg := "inhibit rule is using a deprecated match syntax which will be removed in future versions"
// 		level.Warn(logger).Log("msg", msg, "source_match", ir.SourceMatch, "target_match", ir.TargetMatch, "source_match_re", ir.SourceMatchRE, "target_match_re", ir.TargetMatchRE)
// 	}

// 	// ensure empty data structures are assigned nil so their yaml output is sanitized
// 	ir.TargetMatch = convertMapToNilIfEmpty(ir.TargetMatch)
// 	ir.TargetMatchRE = convertMapToNilIfEmpty(ir.TargetMatchRE)
// 	ir.SourceMatch = convertMapToNilIfEmpty(ir.SourceMatch)
// 	ir.SourceMatchRE = convertMapToNilIfEmpty(ir.SourceMatchRE)
// 	ir.TargetMatchers = convertSliceToNilIfEmpty(ir.TargetMatchers)
// 	ir.SourceMatchers = convertSliceToNilIfEmpty(ir.SourceMatchers)
// 	ir.Equal = convertSliceToNilIfEmpty(ir.Equal)

// 	return nil
// }

// func (ti *timeInterval) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	if amVersion.GTE(semver.MustParse("0.25.0")) {
// 		return nil
// 	}

// 	for i, tis := range ti.TimeIntervals {
// 		if tis.Location != nil {
// 			level.Warn(logger).Log("msg", "time_interval location is supported in Alertmanager >= 0.25.0 only - dropping config")
// 			ti.TimeIntervals[i].Location = nil
// 		}
// 	}

// 	return nil
// }

// // sanitize a route and all its child routes.
// // Warns if the config is using deprecated syntax against a later version.
// // Returns an error if the config could potentially break routing logic
// func (r *route) sanitize(amVersion semver.Version, logger log.Logger) error {
// 	if r == nil {
// 		return nil
// 	}

// 	matchersV2Allowed := amVersion.GTE(semver.MustParse("0.22.0"))
// 	muteTimeIntervalsAllowed := matchersV2Allowed
// 	activeTimeIntervalsAllowed := amVersion.GTE(semver.MustParse("0.24.0"))
// 	withLogger := log.With(logger, "receiver", r.Receiver)

// 	if !matchersV2Allowed && checkNotEmptyStrSlice(r.Matchers) {
// 		return fmt.Errorf(`invalid syntax in route config for 'matchers' comparison based matching is supported in Alertmanager >= 0.22.0 only (matchers=%v)`, r.Matchers)
// 	}

// 	if matchersV2Allowed && checkNotEmptyMap(r.Match, r.MatchRE) {
// 		msg := "'matchers' field is using a deprecated syntax which will be removed in future versions"
// 		level.Warn(withLogger).Log("msg", msg, "match", fmt.Sprint(r.Match), "match_re", fmt.Sprint(r.MatchRE))
// 	}

// 	if !muteTimeIntervalsAllowed {
// 		msg := "named mute time intervals in route is supported in Alertmanager >= 0.22.0 only - dropping config"
// 		level.Warn(withLogger).Log("msg", msg, "mute_time_intervals", fmt.Sprint(r.MuteTimeIntervals))
// 		r.MuteTimeIntervals = nil
// 	}

// 	if !activeTimeIntervalsAllowed {
// 		msg := "active time intervals in route is supported in Alertmanager >= 0.24.0 only - dropping config"
// 		level.Warn(withLogger).Log("msg", msg, "active_time_intervals", fmt.Sprint(r.ActiveTimeIntervals))
// 		r.ActiveTimeIntervals = nil
// 	}

// 	for i, child := range r.Routes {
// 		if err := child.sanitize(amVersion, logger); err != nil {
// 			return errors.Wrapf(err, "route[%d]", i)
// 		}
// 	}
// 	// Set to nil if empty so that it doesn't show up in the resulting yaml.
// 	r.Match = convertMapToNilIfEmpty(r.Match)
// 	r.MatchRE = convertMapToNilIfEmpty(r.MatchRE)
// 	r.Matchers = convertSliceToNilIfEmpty(r.Matchers)
// 	return nil
// }

// func checkNotEmptyMap(in ...map[string]string) bool {
// 	for _, input := range in {
// 		if len(input) > 0 {
// 			return true
// 		}
// 	}
// 	return false
// }

// func checkNotEmptyStrSlice(in ...[]string) bool {
// 	for _, input := range in {
// 		if len(input) > 0 {
// 			return true
// 		}
// 	}
// 	return false
// }

// func convertMapToNilIfEmpty(in map[string]string) map[string]string {
// 	if len(in) > 0 {
// 		return in
// 	}
// 	return nil
// }

// func convertSliceToNilIfEmpty(in []string) []string {
// 	if len(in) > 0 {
// 		return in
// 	}
// 	return nil
// }

// // contains will return true if any slice value with all whitespace removed
// // is equal to the provided value with all whitespace removed
// func contains(value string, in []string) bool {
// 	for _, str := range in {
// 		if strings.ReplaceAll(value, " ", "") == strings.ReplaceAll(str, " ", "") {
// 			return true
// 		}
// 	}
// 	return false
// }

// func inhibitRuleToV2(name, value string) string {
// 	return promv1alpha1.Matcher{
// 		Name:      name,
// 		Value:     value,
// 		MatchType: promv1alpha1.MatchEqual,
// 	}.String()
// }

// func inhibitRuleRegexToV2(name, value string) string {
// 	return promv1alpha1.Matcher{
// 		Name:      name,
// 		Value:     value,
// 		MatchType: promv1alpha1.MatchRegexp,
// 	}.String()
// }

// func checkIsV2Matcher(in ...[]promv1alpha1.Matcher) bool {
// 	for _, input := range in {
// 		for _, matcher := range input {
// 			if matcher.MatchType != "" {
// 				return true
// 			}
// 		}
// 	}
// 	return false
// }
