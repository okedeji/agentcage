package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/cagefile"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/ui"
)

func cmdPack(args []string) {
	fs := flag.NewFlagSet("pack", flag.ContinueOnError)
	tagFlag := fs.String("tag", "latest", "agent tag (e.g. latest, v1.2.0)")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage pack [--tag <tag>] <directory>")
		os.Exit(1)
	}

	dir := fs.Arg(0)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		ui.Fail("%s is not a directory", dir)
		os.Exit(1)
	}

	// Read and validate Cagefile locally for fast failure.
	cagefilePath := filepath.Join(dir, "Cagefile")
	cagefileData, err := os.ReadFile(cagefilePath)
	if err != nil {
		ui.Fail("reading Cagefile: %v", err)
		os.Exit(1)
	}
	manifest, err := cagefile.ParseString(string(cagefileData))
	if err != nil {
		ui.Fail("invalid Cagefile: %v", err)
		os.Exit(1)
	}

	ui.Section("Pack")
	ui.Step("Agent: %s (%s, %s)", filepath.Base(dir), manifest.Runtime, manifest.Entrypoint)

	// Load config and connect to orchestrator.
	cfg := config.Defaults()
	if resolved := config.Resolve(""); resolved != "" {
		if override, loadErr := config.Load(resolved); loadErr == nil {
			cfg = config.Merge(cfg, override)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	conn, err := dialOrchestrator(ctx, cfg)
	if err != nil {
		ui.Fail("connecting to orchestrator: %v", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewPackServiceClient(conn)
	stream, err := client.Pack(ctx)
	if err != nil {
		ui.Fail("starting pack stream: %v", err)
		os.Exit(1)
	}

	// Send metadata first.
	if err := stream.Send(&pb.PackRequest{
		Payload: &pb.PackRequest_Metadata{
			Metadata: &pb.PackMetadata{
				CagefileContent: string(cagefileData),
				DirectoryName:   resolvedDirName(dir),
				Tag:             *tagFlag,
			},
		},
	}); err != nil {
		ui.Fail("sending metadata: %v", err)
		os.Exit(1)
	}

	// Tar and stream the source directory.
	ui.Step("Uploading source...")
	if err := streamSourceDir(stream, dir); err != nil {
		ui.Fail("uploading source: %v", err)
		os.Exit(1)
	}

	// Close send side to signal upload complete.
	if err := stream.CloseSend(); err != nil {
		ui.Fail("closing upload: %v", err)
		os.Exit(1)
	}

	// Receive progress updates and final result.
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			ui.Fail("pack failed: %v", err)
			os.Exit(1)
		}

		switch p := resp.Payload.(type) {
		case *pb.PackResponse_Progress:
			ui.Step("[%s] %s", p.Progress.Stage, p.Progress.Message)
		case *pb.PackResponse_Result:
			sizeMB := float64(p.Result.SizeBytes) / (1024 * 1024)
			ref := p.Result.BundleRef
			shortRef := ref[:12]

			// Tag the bundle in the local tag store.
			tagName := p.Result.Name + ":" + p.Result.Tag
			tagStorePath := filepath.Join(config.HomeDir(), "data", "tags.json")
			ts := cagefile.NewTagStore(tagStorePath)
			if tagErr := ts.Tag(tagName, ref); tagErr != nil {
				ui.Fail("tagging bundle: %v", tagErr)
			}

			fmt.Println()
			ui.OK("Packed: %s → %s (%.1f MB)", tagName, shortRef, sizeMB)
			ui.Info("Runtime", p.Result.Runtime)
			ui.Info("Entrypoint", p.Result.Entrypoint)
			ui.Info("Ref", shortRef)
			fmt.Println()
			fmt.Println("  Next:")
			fmt.Printf("    # Quick run against a target\n")
			fmt.Printf("    agentcage run --agent %s --target <domain> --customer-id <id>\n", tagName)
			fmt.Println()
			fmt.Printf("    # Repeatable run from a plan file\n")
			fmt.Printf("    agentcage run --plan plan.yaml\n")
			fmt.Println()
		}
	}
}

// streamSourceDir creates a gzipped tar of the directory and streams
// it as chunks to the PackService.
func streamSourceDir(stream pb.PackService_PackClient, dir string) error {
	pr, pw := io.Pipe()

	// Tar in background, stream chunks in foreground.
	go func() {
		gw := gzip.NewWriter(pw)
		tw := tar.NewWriter(gw)

		walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip common non-source directories.
			name := info.Name()
			if info.IsDir() && (name == "node_modules" || name == "__pycache__" ||
				name == ".git" || name == "vendor" || name == ".venv") {
				return filepath.SkipDir
			}

			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}

			// Skip symlinks and non-regular files.
			if !info.Mode().IsRegular() && !info.IsDir() {
				return nil
			}

			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			hdr.Name = rel

			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			_, err = io.Copy(tw, f)
			return err
		})

		_ = tw.Close()
		_ = gw.Close()
		_ = pw.CloseWithError(walkErr)
	}()

	// Stream chunks from the pipe.
	buf := make([]byte, 64*1024) // 64KB chunks
	for {
		n, err := pr.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			if sendErr := stream.Send(&pb.PackRequest{
				Payload: &pb.PackRequest_Chunk{Chunk: chunk},
			}); sendErr != nil {
				return sendErr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// reorderArgs moves flags (--key val) before positional args so
// Go's flag package handles them regardless of position.
func reorderArgs(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			positional = append(positional, args[i])
		}
	}
	return append(flags, positional...)
}

func resolvedDirName(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return filepath.Base(dir)
	}
	return filepath.Base(abs)
}

