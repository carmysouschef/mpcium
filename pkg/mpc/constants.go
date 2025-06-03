package mpc

type CurveType string

const (
	CurveECDSA CurveType = "ecdsa"
	CurveEDDSA CurveType = "eddsa"
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
