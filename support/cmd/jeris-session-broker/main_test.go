package main

import "testing"

func TestIsLoopbackListen(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8781", "localhost:8781", "[::1]:8781"} {
		if !isLoopbackListen(addr) {
			t.Fatalf("%q should be loopback", addr)
		}
	}
	for _, addr := range []string{"0.0.0.0:8781", ":8781", "192.168.1.10:8781", "[::]:8781"} {
		if isLoopbackListen(addr) {
			t.Fatalf("%q should not be loopback-only", addr)
		}
	}
}
