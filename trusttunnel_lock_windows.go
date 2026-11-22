package main

import (
	"errors"
	"os"
)

func lockTrustTunnel() (*os.File, error) {
	return nil, errors.New("TrustTunnel setup requires Linux")
}
