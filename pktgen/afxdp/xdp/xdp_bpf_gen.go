//go:build linux

package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" xdpProg xdp_redirect_map.c
