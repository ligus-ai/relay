// Command langstroth-relay is the open-source Langstroth relay binary: a content-blind
// rendezvous + envelope-forwarding server. It wires the default (open) behavior
// of the relay package (internal/relay); seams for custom behavior are in
// internal/relay/seams.go.
//
// Run the server (default):   langstroth-relay
// Generate an issuer keypair: langstroth-relay keygen
// Mint an access token:       langstroth-relay issue --key <priv-hex> --sub <id> [...]
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/langstroth-ai/langstroth-relay/internal/relay"
)

func main() {
	// Structured JSON logs (request lines come from the observability middleware).
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "keygen":
			fatalIf(cmdKeygen())
			return
		case "issue":
			fatalIf(cmdIssue(args[1:]))
			return
		case "bootstrap-agent":
			fatalIf(cmdBootstrapAgent(args[1:]))
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}
	relay.Serve()
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "langstroth-relay: %v\n", err)
		os.Exit(1)
	}
}
