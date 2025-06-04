package mpc

type CurveType string
type Purpose string

const (
	CurveECDSA CurveType = "ecdsa"
	CurveEDDSA CurveType = "eddsa"

	PurposeKeygen    Purpose = "keygen"
	PurposeSign      Purpose = "sign"
	PurposeResharing Purpose = "resharing"
)

const (
	TypeGenerateWalletSuccess = "mpc.mpc_keygen_success.%s"
)

type KeygenSuccessEvent struct {
	WalletID    string `json:"wallet_id"`
	ECDSAPubKey []byte `json:"ecdsa_pub_key"`
	EDDSAPubKey []byte `json:"eddsa_pub_key"`
}

type ResharingSuccessEvent struct {
	WalletID     string `json:"wallet_id"`
	NewThreshold int    `json:"new_threshold"`
}
