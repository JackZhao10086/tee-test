package teeskscli

type keyResult struct {
	PublicKey any
}

type keyLookupResult struct {
	Exists    bool
	PublicKey any
	Note      string
}

type signResult struct {
	Signature []byte
	PublicKey any
}
