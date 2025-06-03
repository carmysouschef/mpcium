package node

type TopicComposer struct {
	action    string
	curveType string
	walletID  string
}

func NewTopicComposer(action string, curveType string, walletID string) *TopicComposer {
	return &TopicComposer{
		action:    action,
		curveType: curveType,
		walletID:  walletID,
	}
}

func (t *TopicComposer) ComposeBroadcastTopic() string {
	return t.action + ":broadcast:" + t.curveType + ":" + t.walletID
}

func (t *TopicComposer) ComposeDirectTopic(nodeID string) string {
	return t.action + ":direct:" + t.curveType + ":" + nodeID + ":" + t.walletID
}

func (t *TopicComposer) ComposeKeyInfoTopic() string {
	return t.curveType + ":" + t.walletID
}
