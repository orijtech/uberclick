package uberclick

type NonceLookup interface {
	ValidateAndDestroyNonce(apiKey, nonce string) *Err
}

func validateAPIKeyAndNonce(apiKey, nonce string) *Err {
	// TODO: Complete this method
	if apiKey == "" {
		return errBlankAPIKey
	}
	if nonce == "" {
		return errBlankNonce
	}

	// TODO: Implement and use
	return nil
}
