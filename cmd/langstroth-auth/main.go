// Command langstroth-auth signs people in with any OIDC provider and mints
// short-lived relay access tokens (hrt1) for them, with a small SCIM 2.0
// endpoint for provisioning and deprovisioning. It runs beside the relay,
// never inside it; the relay only needs the issuer public key.
//
// It gates transport only: workspace membership stays in each workspace's
// signed roster. See langstrothauth/ and docs (langstroth-auth).
package main

import "github.com/langstroth-ai/langstroth-relay/internal/langstrothauth"

func main() { langstrothauth.Main() }
