package relay

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/flynn/noise"
)

// Known-answer test for the hive-tunnel/1 Noise primitives. The relay only
// splices tunnel bytes, but the test harness drives Noise through flynn/noise
// (and, under it, golang.org/x/crypto ChaCha20-Poly1305 / Curve25519). This
// replays the frozen cross-language transcripts in testdata/tunnel_vectors.json
// with the vector's fixed static and ephemeral keys (ephemerals are fed as the
// handshake's randomness, exactly as the hive generator does) and requires every wire
// byte, the handshake hash and every transport frame to match exactly, so a
// dependency or toolchain bump that changes the tunnel's bytes fails here.

type noiseKATTranscript struct {
	Protocol        string `json:"protocol"`
	PrologueHex     string `json:"prologueHex"`
	PskHex          string `json:"pskHex"`
	PhoneEphPrivHex string `json:"phoneEphemeralPrivHex"`
	HostEphPrivHex  string `json:"hostEphemeralPrivHex"`
	Msg1Payload     string `json:"msg1Payload"`
	Msg1Hex         string `json:"msg1Hex"`
	Msg2Payload     string `json:"msg2Payload"`
	Msg2Hex         string `json:"msg2Hex"`
	HandshakeHash   string `json:"handshakeHashHex"`
	Transport       []struct {
		Dir          string `json:"dir"`
		PlaintextHex string `json:"plaintextHex"`
		WireHex      string `json:"wireHex"`
	} `json:"transport"`
}

func katKeypair(t *testing.T, privHex string) noise.DHKey {
	t.Helper()
	priv := mustHex(t, privHex)
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return noise.DHKey{Private: priv, Public: k.PublicKey().Bytes()}
}

func TestTunnelNoise_KnownAnswer(t *testing.T) {
	v := loadTunnelVectors(t)
	raw, err := os.ReadFile("testdata/tunnel_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Session    noiseKATTranscript `json:"session"`
		Enrollment noiseKATTranscript `json:"enrollment"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	phoneStatic := katKeypair(t, v.Keys.PhoneStaticPriv)
	hostStatic := katKeypair(t, v.Keys.HostStaticPrivHex)
	if !bytes.Equal(phoneStatic.Public, mustB64u(t, v.Keys.PhoneStaticPub)) ||
		!bytes.Equal(hostStatic.Public, mustB64u(t, v.Keys.HostStaticPub)) {
		t.Fatal("X25519 static public keys do not match the vectors")
	}
	// The prologue is the relay's own domain-separated context string.
	wantPrologue := tunnelCtx("noise", []byte(v.HostID))

	for name, tr := range map[string]noiseKATTranscript{"session": doc.Session, "enrollment": doc.Enrollment} {
		t.Run(name, func(t *testing.T) {
			prologue := mustHex(t, tr.PrologueHex)
			if !bytes.Equal(prologue, wantPrologue) {
				t.Fatal("prologue drifted from tunnelCtx(\"noise\", hostId)")
			}
			ci := noise.Config{CipherSuite: noiseSuite, Pattern: noise.HandshakeIK, Initiator: true,
				Prologue: prologue, StaticKeypair: phoneStatic, PeerStatic: hostStatic.Public,
				Random: bytes.NewReader(mustHex(t, tr.PhoneEphPrivHex))}
			cr := noise.Config{CipherSuite: noiseSuite, Pattern: noise.HandshakeIK, Initiator: false,
				Prologue: prologue, StaticKeypair: hostStatic,
				Random: bytes.NewReader(mustHex(t, tr.HostEphPrivHex))}
			if tr.PskHex != "" {
				psk := mustHex(t, tr.PskHex)
				ci.PresharedKey, ci.PresharedKeyPlacement = psk, 1
				cr.PresharedKey, cr.PresharedKeyPlacement = psk, 1
			}
			ini, err := noise.NewHandshakeState(ci)
			if err != nil {
				t.Fatal(err)
			}
			res, err := noise.NewHandshakeState(cr)
			if err != nil {
				t.Fatal(err)
			}

			m1, _, _, err := ini.WriteMessage(nil, []byte(tr.Msg1Payload))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(m1) != tr.Msg1Hex {
				t.Fatalf("msg1 bytes differ from vector (%s)", tr.Protocol)
			}
			if p, _, _, err := res.ReadMessage(nil, m1); err != nil || string(p) != tr.Msg1Payload {
				t.Fatalf("host msg1: %v", err)
			}
			m2, hRecv, hSend, err := res.WriteMessage(nil, []byte(tr.Msg2Payload))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(m2) != tr.Msg2Hex {
				t.Fatalf("msg2 bytes differ from vector (%s)", tr.Protocol)
			}
			p2, pSend, pRecv, err := ini.ReadMessage(nil, m2)
			if err != nil || string(p2) != tr.Msg2Payload {
				t.Fatalf("phone msg2: %v", err)
			}
			if hex.EncodeToString(ini.ChannelBinding()) != tr.HandshakeHash ||
				hex.EncodeToString(res.ChannelBinding()) != tr.HandshakeHash {
				t.Fatal("handshake hash differs from vector")
			}

			for i, x := range tr.Transport {
				enc, dec := pSend, hRecv
				if x.Dir == "host->phone" {
					enc, dec = hSend, pRecv
				}
				pt := mustHex(t, x.PlaintextHex)
				wire, err := enc.Encrypt(nil, nil, pt)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(wire) != x.WireHex {
					t.Fatalf("transport frame %d (%s) differs from vector", i, x.Dir)
				}
				back, err := dec.Decrypt(nil, nil, wire)
				if err != nil || !bytes.Equal(back, pt) {
					t.Fatalf("transport frame %d does not round-trip: %v", i, err)
				}
			}
		})
	}
}
