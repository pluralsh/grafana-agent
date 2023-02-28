package alertmanagers

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
	promv1beta1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1beta1"
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

// convert promv1beta1.SecretKeySelector to v1.SecretKeySelector
func convertSecretKeySelector(in promv1beta1.SecretKeySelector) v1.SecretKeySelector {
	return v1.SecretKeySelector{
		LocalObjectReference: v1.LocalObjectReference{
			Name: in.Name,
		},
		Key: in.Key,
	}
}

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

func (c *Component) convertHTTPConfig(ctx context.Context, in promv1beta1.HTTPConfig, crKey types.NamespacedName) (*commoncfg.HTTPClientConfig, error) {
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
		bearerToken, err := c.GetSecretKey(ctx, crKey.Namespace, convertSecretKeySelector(*in.BearerTokenSecret))
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

// function that converts promv1beta1.InhibitRule to amConfig.InhibitRule
func convertInhibitRule(inhibitRule promv1beta1.InhibitRule, crKey types.NamespacedName) *amConfig.InhibitRule {
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

// function that converts *promv1beta1.Route to *amConfig.Route
func (c *Component) convertRoute(in *promv1beta1.Route, crKey types.NamespacedName) *amConfig.Route {
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

	groupWait, _ := time.ParseDuration(in.GroupWait)
	groupInterval, _ := time.ParseDuration(in.GroupInterval)
	repeatInterval, _ := time.ParseDuration(in.RepeatInterval)

	outGroupWait := model.Duration(groupWait)
	outGroupInterval := model.Duration(groupInterval)
	outRepeatInterval := model.Duration(repeatInterval)

	outRoute := &amConfig.Route{
		Receiver:       receiver,
		GroupByStr:     in.GroupBy,
		GroupWait:      &outGroupWait,
		GroupInterval:  &outGroupInterval,
		RepeatInterval: &outRepeatInterval,
		Continue:       in.Continue,
		// Match:               match,
		// MatchRE:             matchRE,
		Matchers:            matchers,
		Routes:              routes,
		MuteTimeIntervals:   prefixedMuteTimeIntervals,
		ActiveTimeIntervals: prefixedActiveTimeIntervals,
	}

	//TODO: make this configurable
	nsMatcher, err := labels.NewMatcher(labels.MatchEqual, inhibitRuleNamespaceKey, crKey.Namespace)
	if err != nil {
		// panic(err)
	}
	outRoute.Matchers = append(outRoute.Matchers, nsMatcher)

	return outRoute
}

// function that converts *promv1beta1.Receiver to *amConfig.Receiver
func (c *Component) convertReceiver(ctx context.Context, in *promv1beta1.Receiver, crKey types.NamespacedName) (*amConfig.Receiver, error) {
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

func convertTimeInterval(in *promv1beta1.TimeInterval, crKey types.NamespacedName, prefix string) (*amConfig.TimeInterval, error) {
	outTimeInterval := &amConfig.TimeInterval{}

	for _, timeInterval := range in.TimeIntervals {
		ti := timeinterval.TimeInterval{}

		for _, time := range timeInterval.Times {
			parsedTime, err := time.Parse()
			if err != nil {
				return nil, err
			}
			ti.Times = append(ti.Times, timeinterval.TimeRange{
				StartMinute: parsedTime.Start,
				EndMinute:   parsedTime.End,
			})
		}

		for _, wd := range timeInterval.Weekdays {
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

		for _, dom := range timeInterval.DaysOfMonth {
			ti.DaysOfMonth = append(ti.DaysOfMonth, timeinterval.DayOfMonthRange{
				InclusiveRange: timeinterval.InclusiveRange{
					Begin: dom.Start,
					End:   dom.End,
				},
			})
		}

		for _, month := range timeInterval.Months {
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

		for _, year := range timeInterval.Years {
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

		outTimeInterval.Name = mimirMakeNamespacedString(prefix, in.Name, crKey)
		outTimeInterval.TimeIntervals = append(outTimeInterval.TimeIntervals, ti)
	}

	return outTimeInterval, nil
}

func (c *Component) convertPagerdutyConfig(ctx context.Context, in promv1beta1.PagerDutyConfig, crKey types.NamespacedName) (*amConfig.PagerdutyConfig, error) {
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
		routingKey, err := c.GetSecretKey(ctx, crKey.Namespace, convertSecretKeySelector(*in.RoutingKey))
		if err != nil {
			return nil, errors.Wrap(err, "failed to get routing key")
		}
		out.RoutingKey = amConfig.Secret(routingKey)
	}

	if in.ServiceKey != nil {
		serviceKey, err := c.GetSecretKey(ctx, crKey.Namespace, convertSecretKeySelector(*in.ServiceKey))
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

func (c *Component) convertSlackConfig(ctx context.Context, in promv1beta1.SlackConfig, crKey types.NamespacedName) (*amConfig.SlackConfig, error) {
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
		getUrl, err := c.getValidURLFromSecret(ctx, crKey.Namespace, convertSecretKeySelector(*in.APIURL))
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

func (c *Component) convertWebhookConfig(ctx context.Context, in promv1beta1.WebhookConfig, crKey types.NamespacedName) (*amConfig.WebhookConfig, error) {
	out := &amConfig.WebhookConfig{
		NotifierConfig: amConfig.NotifierConfig{
			VSendResolved: *in.SendResolved,
		},
	}

	if in.URLSecret != nil {
		getUrl, err := c.getValidURLFromSecret(ctx, crKey.Namespace, convertSecretKeySelector(*in.URLSecret))
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

func (c *Component) convertOpsgenieConfig(ctx context.Context, in promv1beta1.OpsGenieConfig, crKey types.NamespacedName) (*amConfig.OpsGenieConfig, error) {
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
		// UpdateAlerts: in.UpdateAlerts, //TODO: seems to be removed in v1beta1
	}
	outAPIURL, err := url.Parse(in.APIURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pagerduty url")
	}
	out.APIURL = &amConfig.URL{URL: outAPIURL}

	if in.APIKey != nil {
		apiKey, err := c.GetSecretKey(ctx, crKey.Namespace, convertSecretKeySelector(*in.APIKey))
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

func (c *Component) convertWeChatConfig(ctx context.Context, in promv1beta1.WeChatConfig, crKey types.NamespacedName) (*amConfig.WechatConfig, error) {
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
		apiSecret, err := c.GetSecretKey(ctx, crKey.Namespace, convertSecretKeySelector(*in.APISecret))
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

func (c *Component) convertEmailConfig(ctx context.Context, in promv1beta1.EmailConfig, crKey types.NamespacedName) (*amConfig.EmailConfig, error) {
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
		authPassword, err := c.GetSecretKey(ctx, crKey.Namespace, convertSecretKeySelector(*in.AuthPassword))
		if err != nil {
			return nil, errors.Wrap(err, "failed to get auth password")
		}
		out.AuthPassword = amConfig.Secret(authPassword)
	}

	if in.AuthSecret != nil {
		authSecret, err := c.GetSecretKey(ctx, crKey.Namespace, convertSecretKeySelector(*in.AuthSecret))
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

func (c *Component) convertVictorOpsConfig(ctx context.Context, in promv1beta1.VictorOpsConfig, crKey types.NamespacedName) (*amConfig.VictorOpsConfig, error) {
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
		apiKey, err := c.GetSecretKey(ctx, crKey.Namespace, convertSecretKeySelector(*in.APIKey))
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

func (c *Component) convertPushoverConfig(ctx context.Context, in promv1beta1.PushoverConfig, crKey types.NamespacedName) (*amConfig.PushoverConfig, error) {
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
		userKey, err := c.GetSecretKey(ctx, crKey.Namespace, convertSecretKeySelector(*in.UserKey))
		if err != nil {
			return nil, errors.Wrap(err, "failed to get user key")
		}
		if userKey == "" {
			return nil, errors.Errorf("mandatory field %q is empty", "userKey")
		}
		out.UserKey = amConfig.Secret(userKey)
	}

	{
		token, err := c.GetSecretKey(ctx, crKey.Namespace, convertSecretKeySelector(*in.Token))
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

func (c *Component) convertTelegramConfig(ctx context.Context, in promv1beta1.TelegramConfig, crKey types.NamespacedName) (*amConfig.TelegramConfig, error) {
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
		botToken, err := c.GetSecretKey(ctx, crKey.Namespace, convertSecretKeySelector(*in.BotToken))
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

func (c *Component) convertSnsConfig(ctx context.Context, in promv1beta1.SNSConfig, crKey types.NamespacedName) (*amConfig.SNSConfig, error) {
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
