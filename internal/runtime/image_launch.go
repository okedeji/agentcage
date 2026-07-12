package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ImageLaunch pulls an OCI image and returns the command it launches with, its
// ENTRYPOINT followed by its CMD. It lets import wrap a container-image server
// without the operator spelling out --entrypoint. It returns nil (and no error)
// when the image declares no command, leaving the caller to ask for one.
//
// It pulls first because nerdctl can only inspect an image already in the store;
// BuildKit shares that store, so the later build reuses the pull rather than
// fetching the image twice.
func ImageLaunch(ctx context.Context, imageRef string) ([]string, error) {
	p, err := DefaultProvisioner()
	if err != nil {
		return nil, err
	}
	defer func() { _ = p.Close() }()

	if err := runNerdctl(p.Nerdctl(ctx, "pull", "-q", imageRef), "pulling "+imageRef); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	cmd := p.Nerdctl(ctx, "image", "inspect", imageRef, "--format", "{{json .Config.Entrypoint}}\t{{json .Config.Cmd}}")
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("reading %s launch command: %w", imageRef, err)
	}
	return parseImageLaunch(out.String())
}

// parseImageLaunch reads the two JSON arrays image inspect prints, ENTRYPOINT
// then CMD, and joins them into the argv the container runs.
func parseImageLaunch(s string) ([]string, error) {
	entry, command, ok := strings.Cut(strings.TrimSpace(s), "\t")
	if !ok {
		return nil, fmt.Errorf("unexpected image inspect output %q", s)
	}
	var entrypoint, cmd []string
	if entry != "" && entry != "null" {
		if err := json.Unmarshal([]byte(entry), &entrypoint); err != nil {
			return nil, fmt.Errorf("parsing image entrypoint: %w", err)
		}
	}
	if command != "" && command != "null" {
		if err := json.Unmarshal([]byte(command), &cmd); err != nil {
			return nil, fmt.Errorf("parsing image cmd: %w", err)
		}
	}
	return append(entrypoint, cmd...), nil
}
