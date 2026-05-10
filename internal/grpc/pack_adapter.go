package grpc

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/okedeji/agentcage/api/proto"
	"github.com/okedeji/agentcage/internal/cagefile"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PackConfig holds dependencies for the pack service handler.
type PackConfig struct {
	BundleStoreDir    string
	SDKTarball        string
	AgentcageVersion  string
}

type packAdapter struct {
	pb.UnimplementedPackServiceServer
	config PackConfig
}

func (a *packAdapter) Pack(stream pb.PackService_PackServer) error {
	ctx := stream.Context()

	// Phase 1: Receive metadata (first message).
	firstMsg, err := stream.Recv()
	if err != nil {
		return packErr("receiving metadata: %v", err)
	}
	meta := firstMsg.GetMetadata()
	if meta == nil {
		return packErr("first message must be PackMetadata")
	}

	sendProgress := func(stage, message string, pct int32) {
		_ = stream.Send(&pb.PackResponse{
			Payload: &pb.PackResponse_Progress{
				Progress: &pb.PackProgress{
					Stage:   stage,
					Message: message,
					Percent: pct,
				},
			},
		})
	}

	sendProgress("uploading", "receiving source files", 0)

	// Phase 2: Receive source tar chunks into a temp file.
	tmpTar, err := os.CreateTemp("", "agentcage-pack-upload-*.tar.gz")
	if err != nil {
		return packErr("creating temp file: %v", err)
	}
	defer func() {
		_ = tmpTar.Close()
		_ = os.Remove(tmpTar.Name())
	}()

	var totalBytes int64
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return packErr("receiving chunk: %v", err)
		}
		chunk := msg.GetChunk()
		if chunk == nil {
			continue
		}
		n, err := tmpTar.Write(chunk)
		if err != nil {
			return packErr("writing chunk: %v", err)
		}
		totalBytes += int64(n)
	}
	_ = tmpTar.Close()

	sendProgress("uploading", fmt.Sprintf("received %d bytes", totalBytes), 100)

	// Phase 3: Unpack source to a directory named after the agent so
	// the bundle manifest picks up the correct name.
	sendProgress("unpacking", "extracting source files", 0)
	tmpParent, err := os.MkdirTemp("", "agentcage-pack-*")
	if err != nil {
		return packErr("creating work dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpParent) }()

	dirName := meta.GetDirectoryName()
	if dirName == "" {
		dirName = "agent"
	}
	workDir := filepath.Join(tmpParent, dirName)

	if err := os.MkdirAll(workDir, 0755); err != nil {
		return packErr("creating agent dir: %v", err)
	}
	if err := extractTarGz(tmpTar.Name(), workDir); err != nil {
		return packErr("extracting source: %v", err)
	}
	sendProgress("unpacking", "source extracted", 100)

	// Phase 4: Parse Cagefile.
	sendProgress("parsing", "validating Cagefile", 0)
	manifest, err := cagefile.ParseString(meta.GetCagefileContent())
	if err != nil {
		return packErr("parsing Cagefile: %v", err)
	}
	sendProgress("parsing", "Cagefile valid", 100)

	// Phase 5: Install dependencies.
	sendProgress("installing", "installing dependencies", 0)
	if err := cagefile.InstallDependencies(ctx, manifest, workDir, a.config.SDKTarball, func(msg string) {
		sendProgress("installing", msg, -1)
	}); err != nil {
		return packErr("installing dependencies: %v", err)
	}
	sendProgress("installing", "dependencies installed", 100)

	// Phase 6: Bundle into .cage file.
	sendProgress("bundling", "creating .cage archive", 0)
	outPath := filepath.Join(os.TempDir(), "agentcage-pack-output.cage")
	bundleTag := meta.GetTag()
	if bundleTag == "" {
		bundleTag = "latest"
	}
	bundleManifest, err := cagefile.PackToFile(workDir, bundleTag, a.config.AgentcageVersion, outPath, 2<<30, nil)
	if err != nil {
		return packErr("packing bundle: %v", err)
	}
	defer func() { _ = os.Remove(outPath) }()
	sendProgress("bundling", "archive created", 100)

	// Phase 7: Store in BundleStore.
	sendProgress("storing", "storing bundle", 0)
	store, err := cagefile.NewBundleStore(a.config.BundleStoreDir)
	if err != nil {
		return packErr("creating bundle store: %v", err)
	}
	bundleRef, err := store.Store(outPath)
	if err != nil {
		return packErr("storing bundle: %v", err)
	}

	info, _ := os.Stat(store.Path(bundleRef))
	var sizeBytes int64
	if info != nil {
		sizeBytes = info.Size()
	}
	// Phase 8: Send result.
	_ = stream.Send(&pb.PackResponse{
		Payload: &pb.PackResponse_Result{
			Result: &pb.PackResult{
				BundleRef:  bundleRef,
				Name:       bundleManifest.Name,
				Tag:        bundleManifest.Tag,
				Runtime:    bundleManifest.Runtime,
				Entrypoint: bundleManifest.Entrypoint,
				SizeBytes:  sizeBytes,
			},
		},
	})

	return nil
}

func packErr(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

func extractTarGz(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, hdr.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)) {
			return fmt.Errorf("path traversal: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(target, 0755)
		case tar.TypeReg:
			_ = os.MkdirAll(filepath.Dir(target), 0755)
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0755)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				_ = out.Close()
				return err
			}
			_ = out.Close()
		}
	}
	return nil
}

func (a *packAdapter) ListAgents(_ context.Context, _ *pb.ListAgentsRequest) (*pb.ListAgentsResponse, error) {
	dir := a.config.BundleStoreDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return &pb.ListAgentsResponse{}, nil
		}
		return nil, status.Errorf(codes.Internal, "reading bundle store: %v", err)
	}

	ts := cagefile.NewTagStore(filepath.Join(filepath.Dir(dir), "tags.json"))
	var agents []*pb.AgentInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cage") {
			continue
		}
		ref := strings.TrimSuffix(e.Name(), ".cage")
		info, _ := e.Info()
		agent := &pb.AgentInfo{
			Ref:       ref,
			Tags:      ts.TagsForRef(ref),
			SizeBytes: info.Size(),
		}
		if f, err := os.Open(filepath.Join(dir, e.Name())); err == nil {
			if m, mErr := cagefile.ReadManifestFromBundle(f); mErr == nil {
				agent.Name = m.Name
				agent.Runtime = m.Runtime
				agent.Entrypoint = m.Entrypoint
				agent.FilesHash = m.FilesHash
			}
			_ = f.Close()
		}
		agents = append(agents, agent)
	}
	return &pb.ListAgentsResponse{Agents: agents}, nil
}

func (a *packAdapter) InspectAgent(_ context.Context, req *pb.InspectAgentRequest) (*pb.InspectAgentResponse, error) {
	if req.GetQuery() == "" {
		return nil, status.Error(codes.InvalidArgument, "query is required")
	}

	store, err := cagefile.NewBundleStore(a.config.BundleStoreDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	ts := cagefile.NewTagStore(filepath.Join(filepath.Dir(a.config.BundleStoreDir), "tags.json"))
	fullRef, err := resolveQuery(store, ts, req.GetQuery())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}

	f, err := os.Open(store.Path(fullRef))
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	defer func() { _ = f.Close() }()

	manifest, err := cagefile.ReadManifestFromBundle(f)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reading manifest: %v", err)
	}

	info, _ := os.Stat(store.Path(fullRef))
	return &pb.InspectAgentResponse{
		Agent: &pb.AgentInfo{
			Ref:        fullRef,
			Name:       manifest.Name,
			Tags:       ts.TagsForRef(fullRef),
			Runtime:    manifest.Runtime,
			Entrypoint: manifest.Entrypoint,
			SizeBytes:  info.Size(),
			FilesHash:  manifest.FilesHash,
		},
	}, nil
}

func (a *packAdapter) RemoveAgent(_ context.Context, req *pb.RemoveAgentRequest) (*pb.RemoveAgentResponse, error) {
	if req.GetQuery() == "" {
		return nil, status.Error(codes.InvalidArgument, "query is required")
	}

	store, err := cagefile.NewBundleStore(a.config.BundleStoreDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	ts := cagefile.NewTagStore(filepath.Join(filepath.Dir(a.config.BundleStoreDir), "tags.json"))
	fullRef, err := resolveQuery(store, ts, req.GetQuery())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}

	for _, tag := range ts.TagsForRef(fullRef) {
		_ = ts.Untag(tag)
	}
	if err := os.Remove(store.Path(fullRef)); err != nil {
		return nil, status.Errorf(codes.Internal, "removing bundle: %v", err)
	}
	return &pb.RemoveAgentResponse{Ref: fullRef}, nil
}

func resolveQuery(store *cagefile.BundleStore, ts *cagefile.TagStore, query string) (string, error) {
	if strings.Contains(query, ":") {
		if ref, err := ts.Resolve(query); err == nil {
			return ref, nil
		}
	}
	if ref, err := store.Resolve(query); err == nil {
		return ref, nil
	}
	if !strings.Contains(query, ":") {
		if ref, err := ts.Resolve(query + ":latest"); err == nil {
			return ref, nil
		}
	}
	return "", fmt.Errorf("agent '%s' not found", query)
}
