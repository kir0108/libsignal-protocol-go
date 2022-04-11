package ecc

import (
	"crypto/sha512"
	ed25519 "github.com/teserakt-io/golang-ed25519"
	"github.com/teserakt-io/golang-ed25519/edwards25519"
)

// Package curve25519sign implements a signature scheme based on Curve25519 keys.
// See https://moderncrypto.org/mail-archive/curves/2014/000205.html for details.
//
//func sign(privateKey *[32]byte, message []byte, random [64]byte) *[64]byte {
//	h := sha512.New()
//	h.Write(privateKey[:32])
//
//	var digest1, messageDigest, hramDigest [64]byte
//	var expandedSecretKey [32]byte
//	h.Sum(digest1[:0])
//	copy(expandedSecretKey[:], digest1[:])
//	expandedSecretKey[0] &= 248
//	expandedSecretKey[31] &= 63
//	expandedSecretKey[31] |= 64
//
//	h.Reset()
//	h.Write(digest1[32:])
//	h.Write(message)
//	h.Sum(messageDigest[:0])
//
//	var messageDigestReduced [32]byte
//	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)
//	var R edwards25519.ExtendedGroupElement
//	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)
//
//	var encodedR [32]byte
//	R.ToBytes(&encodedR)
//
//	h.Reset()
//	h.Write(encodedR[:])
//	h.Write(privateKey[32:])
//	h.Write(message)
//	h.Sum(hramDigest[:0])
//	var hramDigestReduced [32]byte
//	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)
//
//	var s [32]byte
//	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)
//
//	signature := new([64]byte)
//	copy(signature[:], encodedR[:])
//	copy(signature[32:], s[:])
//
//	return signature
//}

//func verify(publicKey [32]byte, message []byte, signature *[64]byte) bool {
//	var A edwards25519.ExtendedGroupElement
//	var publicKeyBytes [32]byte
//	copy(publicKeyBytes[:], publicKey[:])
//	if !A.FromBytes(&publicKeyBytes) {
//		return false
//	}
//	edwards25519.FeNeg(&A.X, &A.X)
//	edwards25519.FeNeg(&A.T, &A.T)
//
//	h := sha512.New()
//	h.Write(signature[:32])
//	h.Write(publicKey[:])
//	h.Write(message)
//	var digest [64]byte
//	h.Sum(digest[:0])
//
//	var hReduced [32]byte
//	edwards25519.ScReduce(&hReduced, &digest)
//
//	var R edwards25519.ProjectiveGroupElement
//	var s [32]byte
//	copy(s[:], signature[32:])
//
//	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
//	// the range [0, order) in order to prevent signature malleability.
//	if !edwards25519.ScMinimal(&s) {
//		return false
//	}
//
//	edwards25519.GeDoubleScalarMultVartime(&R, &hReduced, &A, &s)
//
//	var checkR [32]byte
//	R.ToBytes(&checkR)
//	return bytes.Equal(signature[:32], checkR[:])
//}

// sign signs the message with privateKey and returns a signature as a byte slice.
func sign(privateKey *[32]byte, message []byte, random [64]byte) *[64]byte {

	// Calculate Ed25519 public key from Curve25519 private key
	var A edwards25519.ExtendedGroupElement
	var publicKey [32]byte
	edwards25519.GeScalarMultBase(&A, privateKey)
	A.ToBytes(&publicKey)

	// Calculate r
	diversifier := [32]byte{
		0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	var r [64]byte
	hash := sha512.New()
	hash.Write(diversifier[:])
	hash.Write(privateKey[:])
	hash.Write(message)
	hash.Write(random[:])
	hash.Sum(r[:0])

	// Calculate R
	var rReduced [32]byte
	edwards25519.ScReduce(&rReduced, &r)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &rReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	// Calculate S = r + SHA2-512(R || A_ed || msg) * a  (mod L)
	var hramDigest [64]byte
	hash.Reset()
	hash.Write(encodedR[:])
	hash.Write(publicKey[:])
	hash.Write(message)
	hash.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, privateKey, &rReduced)

	signature := new([64]byte)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])
	signature[63] |= publicKey[31] & 0x80

	return signature
}

//// verify checks whether the message has a valid signature.
func verify(publicKey [32]byte, message []byte, signature *[64]byte) bool {

	publicKey[31] &= 0x7F

	var edY, one, montX, montXMinusOne, montXPlusOne edwards25519.FieldElement
	edwards25519.FeFromBytes(&montX, &publicKey)
	edwards25519.FeOne(&one)
	edwards25519.FeSub(&montXMinusOne, &montX, &one)
	edwards25519.FeAdd(&montXPlusOne, &montX, &one)
	edwards25519.FeInvert(&montXPlusOne, &montXPlusOne)
	edwards25519.FeMul(&edY, &montXMinusOne, &montXPlusOne)

	var A_ed [32]byte
	edwards25519.FeToBytes(&A_ed, &edY)

	A_ed[31] |= signature[63] & 0x80
	signature[63] &= 0x7F
	var publicKeyEd ed25519.PublicKey = A_ed[:]

	return ed25519.Verify(publicKeyEd, message, signature[:])
}
