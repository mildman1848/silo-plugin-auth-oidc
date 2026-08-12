// Command silo-plugin-auth-oidc implements Silo's auth_provider.v1 contract
// for generic OAuth2/OIDC single sign-on providers.
package main

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"
	"github.com/mildman1848/silo-plugin-auth-oidc/internal/provider"
	"google.golang.org/protobuf/encoding/protojson"
)

//go:embed manifest.json
var manifestFS embed.FS

var version = "0.1.0"

type runtimeServer struct {
	pluginv1.UnimplementedRuntimeServer
	manifest *pluginv1.PluginManifest
	provider *provider.OIDCProvider
}

func (r *runtimeServer) GetManifest(context.Context, *pluginv1.GetManifestRequest) (*pluginv1.GetManifestResponse, error) {
	return &pluginv1.GetManifestResponse{Manifest: r.manifest}, nil
}

func (r *runtimeServer) Configure(_ context.Context, req *pluginv1.ConfigureRequest) (*pluginv1.ConfigureResponse, error) {
	if r.provider != nil {
		if err := r.provider.Configure(req.GetConfig()); err != nil {
			return nil, err
		}
	}
	return &pluginv1.ConfigureResponse{}, nil
}

func main() {
	manifest, err := loadManifest()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(os.Args) > 1 && os.Args[1] == "manifest" {
		out, err := protojson.MarshalOptions{Multiline: true, EmitUnpopulated: false}.Marshal(manifest)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}
	authProvider := &provider.OIDCProvider{}
	rt := &runtimeServer{manifest: manifest, provider: authProvider}
	runtime.Serve(runtime.ServeConfig{Servers: runtime.CapabilityServers{Runtime: rt, AuthProvider: authProvider}})
}

func loadManifest() (*pluginv1.PluginManifest, error) {
	data, err := manifestFS.ReadFile("manifest.json")
	if err != nil {
		return nil, err
	}
	checksum := sha256.Sum256([]byte(strings.TrimSpace(version)))
	data = []byte(strings.ReplaceAll(string(data), "__CHECKSUM__", hex.EncodeToString(checksum[:])))
	data = []byte(strings.ReplaceAll(string(data), "\"version\": \"0.1.0\"", fmt.Sprintf("\"version\": \"%s\"", version)))
	var manifest pluginv1.PluginManifest
	if err := protojson.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}
