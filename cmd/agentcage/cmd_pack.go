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
	"time"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/cagefile"
	"github.com/okedeji/agentcage/internal/config"
	"github.com/okedeji/agentcage/internal/ui"
)

func cmdPack(args []string) {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentcage pack <directory>")
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
				DirectoryName:   filepath.Base(dir),
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
			fmt.Println()
			ui.OK("Packed: %s v%s (%.1f MB)", p.Result.Name, p.Result.Version, sizeMB)
			ui.Info("Runtime", p.Result.Runtime)
			ui.Info("Entrypoint", p.Result.Entrypoint)
			ui.Info("Bundle ref", p.Result.BundleRef[:12]+"...")
			fmt.Println()
			ui.Step("Run: agentcage run --plan plan.yaml")
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

