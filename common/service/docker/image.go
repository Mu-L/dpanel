package docker

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/containers/image/v5/copy"
	dockerarchive "github.com/containers/image/v5/docker/archive"
	"github.com/containers/image/v5/oci/archive"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	"github.com/donknap/dpanel/common/function"
	"github.com/donknap/dpanel/common/service/docker/imports"
	"github.com/donknap/dpanel/common/types/fs"
	"github.com/mcuadros/go-version"
)

func (self Client) ImageInspectFileList(ctx context.Context, imageID string) (pathInfo []*fs.FileData, path []string, err error) {
	imageInfo, err := self.Client.ImageInspect(ctx, imageID)
	if err != nil {
		return nil, nil, err
	}
	dockerVersion, _ := self.Client.ServerVersion(ctx)
	// 如果当前 docker 版本大于 25 则获取 rootfs 否则直接查找 tar 的文件
	layers := function.PluckArrayWalk(imageInfo.RootFS.Layers, func(i string) (string, bool) {
		if _, after, ok := strings.Cut(i, "sha256:"); ok {
			return fmt.Sprintf("blobs/sha256/%s", after), true
		}
		return "", false
	})
	out, err := self.Client.ImageSave(ctx, []string{
		imageID,
	})

	tarReader := tar.NewReader(out)
	for {
		header, err := tarReader.Next()
		if err != nil {
			break
		}
		var tarFileList []*fs.FileData
		if version.Compare(dockerVersion.Version, "25", ">=") && function.InArray(layers, header.Name) {
			tarFileList, err = getFileListFromTar(tar.NewReader(tarReader))
			if err != nil {
				slog.Debug("docker image inspect file list", "error", err)
				continue
			}
		} else if strings.HasSuffix(header.Name, ".tar") {
			tarFileList, err = getFileListFromTar(tar.NewReader(tarReader))
			if err != nil {
				slog.Debug("docker image inspect file list", "error", err)
				continue
			}
		} else if strings.HasSuffix(header.Name, ".tar.gz") || strings.HasSuffix(header.Name, "tgz") {
			gzReader, err := gzip.NewReader(tarReader)
			if err != nil {
				return nil, nil, err
			}
			tarFileList, err = getFileListFromTar(tar.NewReader(gzReader))
			_ = gzReader.Close()
			if err != nil {
				slog.Debug("docker image inspect file list", "error", err)
				continue
			}
		}
		pathInfo = append(pathInfo, tarFileList...)
	}
	sort.Slice(pathInfo, func(i, j int) bool {
		return pathInfo[i].IsDir && !pathInfo[j].IsDir
	})
	sort.Slice(pathInfo, func(i, j int) bool {
		if pathInfo[i].IsDir != pathInfo[j].IsDir {
			return pathInfo[i].IsDir
		}
		return pathInfo[i].Name < pathInfo[j].Name
	})

	path = make([]string, 0)
	pathInfo = function.PluckArrayWalk(pathInfo, func(i *fs.FileData) (*fs.FileData, bool) {
		if function.InArray(path, i.Name) {
			return nil, false
		} else {
			path = append(path, i.Name)
			return i, true
		}
	})
	return pathInfo, path, nil
}

func (self Client) ImageLoadFromOci(ctx context.Context, ociPath string, imageName string) error {
	tarPath := filepath.Join(filepath.Dir(ociPath), function.GetMd5(ociPath)+".tar")
	defer os.Remove(tarPath)
	err := ExtractCurPlatformImageTarFromOci(ctx, ociPath, tarPath, imageName)
	if err != nil {
		return err
	}
	importFile, err := imports.NewFileImport("", imports.WithImportTarFile(tarPath))
	if err != nil {
		return err
	}
	defer importFile.Close()

	_, err = self.Client.ImageLoad(ctx,
		importFile.Reader(),
	)
	return err
}

func ExtractCurPlatformImageTarFromOci(ctx context.Context, ociPath string, tarPath string, imageName string) error {
	srcRef, err := archive.NewReference(ociPath, "")
	if err != nil {
		return fmt.Errorf("无法打开 OCI 源: %w", err)
	}
	if imageName != "" {
		tarPath = tarPath + ":" + imageName
	}
	destRef, err := dockerarchive.ParseReference(tarPath)
	if err != nil {
		return fmt.Errorf("创建目标引用失败: %w", err)
	}

	defaultPolicy := &signature.Policy{
		Default: []signature.PolicyRequirement{
			signature.NewPRInsecureAcceptAnything(),
		},
	}
	policyContext, err := signature.NewPolicyContext(defaultPolicy)
	if err != nil {
		return err
	}
	defer policyContext.Destroy()

	currentOS, currentArch := getPlatformForCurrentSystem()
	sysCtx := &types.SystemContext{
		ArchitectureChoice: currentArch,
		OSChoice:           currentOS,
	}
	copyOptions := &copy.Options{
		SourceCtx:      sysCtx,
		DestinationCtx: sysCtx,
	}
	_, err = copy.Image(ctx, policyContext, destRef, srcRef, copyOptions)

	return err
}

func getFileListFromTar(tarReader *tar.Reader) (files []*fs.FileData, err error) {
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		// always ensure relative path notations are not parsed as part of the filename
		name := path.Clean(header.Name)
		if name == "." {
			continue
		}

		switch header.Typeflag {
		case tar.TypeXGlobalHeader:
			return nil, fmt.Errorf("unexptected tar file: (XGlobalHeader): type=%v name=%s", header.Typeflag, name)
		case tar.TypeXHeader:
			return nil, fmt.Errorf("unexptected tar file (XHeader): type=%v name=%s", header.Typeflag, name)
		default:
			files = append(files, &fs.FileData{
				Path:      filepath.Join("/", header.Name),
				Name:      filepath.Join("/", header.Name),
				Mod:       os.FileMode(header.Mode),
				ModStr:    os.FileMode(header.Mode).String(),
				ModTime:   header.ModTime,
				Change:    fs.ChangeDefault,
				Size:      header.Size,
				User:      fmt.Sprintf("%d", header.Uid),
				Group:     fmt.Sprintf("%d", header.Gid),
				LinkName:  header.Linkname,
				IsDir:     header.Typeflag == tar.TypeDir,
				IsSymlink: false,
			})
		}
	}
	return files, nil
}

func getPlatformForCurrentSystem() (string, string) {
	currentOS := runtime.GOOS
	currentArch := runtime.GOARCH

	// macOS 特殊处理：Docker 在 macOS 上运行 Linux 容器
	if currentOS == "darwin" {
		currentOS = "linux"
		// Apple Silicon
		if currentArch == "arm64" {
			currentArch = "arm64"
		} else {
			// Intel Mac
			currentArch = "amd64"
		}
	}

	return currentOS, currentArch
}
