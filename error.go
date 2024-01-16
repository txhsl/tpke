package tpke

type CustomError struct {
	Period  string
	Message string
}

func (err *CustomError) Error() string {
	return err.Period + ": " + err.Message
}

func NewAESError(msg string) *CustomError {
	return &CustomError{
		Period:  "aes encryption",
		Message: msg,
	}
}

func NewTPKEError(msg string) *CustomError {
	return &CustomError{
		Period:  "threshold encryption",
		Message: msg,
	}
}

func NewDKGError(msg string) *CustomError {
	return &CustomError{
		Period:  "dkg",
		Message: msg,
	}
}

func NewSigError(msg string) *CustomError {
	return &CustomError{
		Period:  "threshold signature",
		Message: msg,
	}
}

func NewAESMessageError() *CustomError {
	return NewAESError("empty message")
}

func NewAESEncryptionError() *CustomError {
	return NewAESError("encryption faild")
}

func NewAESCiphertextError() *CustomError {
	return NewAESError("empty ciphertext")
}

func NewAESDecryptionError() *CustomError {
	return NewAESError("decryption failed")
}

func NewTPKENotEnoughShareError() *CustomError {
	return NewTPKEError("not enough share")
}

func NewTPKECiphertextError() *CustomError {
	return NewTPKEError("invalid ciphertext")
}

func NewTPKEDecryptionError() *CustomError {
	return NewTPKEError("decryption failed")
}

func NewSigNotEnoughShareError() *CustomError {
	return NewSigError("not enough share")
}

func NewSigAggregationError() *CustomError {
	return NewSigError("aggregation failed")
}

func NewDKGPVSSError() *CustomError {
	return NewDKGError("invalid pvss")
}

func NewDKGSecretError() *CustomError {
	return NewDKGError("invalid secret")
}
