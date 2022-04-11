package tests

import (
	"fmt"
	"github.com/kir0108/libsignal-protocol-go/util/keyhelper"
	"testing"
)

func TestRegistrationID(t *testing.T) {
	regID := keyhelper.GenerateRegistrationID()
	fmt.Println(regID)
}
