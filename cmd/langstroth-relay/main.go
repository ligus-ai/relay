// Command langstroth-relay is the open-source Langstroth relay binary: a content-blind
// rendezvous + envelope-forwarding server. It wires the default (open) behavior
// of the relay library; a downstream binary can import the same
// library and inject custom seams (see seams.go).
//
// Run the server (default):   langstroth-relay
// Generate an issuer keypair: langstroth-relay keygen
// Mint an access token:       langstroth-relay issue --key <priv-hex> --sub <id> [...]
// Check a configuration:      langstroth-relay check [--json] [--url URL]
// Everything else:            langstroth-relay help [topic]
package main

import "github.com/langstroth-ai/langstroth-relay"

func main() { relay.Main() }
