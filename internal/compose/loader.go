package compose

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/template"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/sirupsen/logrus"
)

// DefaultFileNames are the file names Docker Compose looks for, in order of
// preference, when no file is given explicitly.
var DefaultFileNames = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

// maxFileSize guards against accidentally scanning huge non-Compose files.
const maxFileSize = 16 << 20

type sourceFile struct {
	display string
	abs     string
	content []byte
	raw     *rawInfo
}

// Load reads one or more Compose files (merged in order, like repeated
// "docker compose -f" flags) and returns the normalized project. A single
// directory argument is resolved like Docker Compose does: the first default
// file name found is used, together with its override file if present.
//
// Interpolation is deterministic: StackSentry does not read the shell
// environment or .env files. Variables resolve to the defaults written in
// the file; variables without a default resolve to an empty string and are
// reported by rule SST-CFG-001.
func Load(ctx context.Context, paths []string) (*Project, error) {
	if len(paths) == 0 {
		return nil, &LoadError{Kind: ErrNotFound, Path: ".", Detail: "no Compose file given"}
	}
	displays, err := resolveFiles(paths)
	if err != nil {
		return nil, err
	}
	files := make([]sourceFile, 0, len(displays))
	for _, display := range displays {
		f, err := readSource(display)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	model, warnings, err := loadModel(ctx, files)
	if err != nil {
		return nil, err
	}
	project := normalize(model, files)
	project.Warnings = append(project.Warnings, warnings...)
	if len(project.Services) == 0 {
		detail := ""
		for _, f := range files {
			if f.raw.hasInclude {
				detail = " (services defined via \"include\" are not analyzed in this version)"
			}
		}
		return nil, &LoadError{Kind: ErrNoServices, Path: files[0].display, Detail: detail}
	}
	return project, nil
}

// resolveFiles expands a single directory argument into the Compose files
// Docker Compose would use and verifies that explicit files exist.
func resolveFiles(paths []string) ([]string, error) {
	if len(paths) == 1 {
		info, err := os.Stat(paths[0])
		if err != nil {
			return nil, statError(paths[0], err)
		}
		if info.IsDir() {
			return discover(paths[0])
		}
	}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, statError(p, err)
		}
		if info.IsDir() {
			return nil, &LoadError{Kind: ErrRead, Path: p, Detail: "is a directory; pass a single directory or a list of files"}
		}
	}
	return paths, nil
}

func discover(dir string) ([]string, error) {
	for _, name := range DefaultFileNames {
		candidate := filepath.Join(dir, name)
		if isFile(candidate) {
			files := []string{candidate}
			ext := filepath.Ext(name)
			base := strings.TrimSuffix(name, ext)
			for _, oext := range []string{".yaml", ".yml"} {
				override := filepath.Join(dir, base+".override"+oext)
				if isFile(override) {
					files = append(files, override)
					break
				}
			}
			return files, nil
		}
	}
	return nil, &LoadError{Kind: ErrNotFound, Path: dir,
		Detail: "no Compose file found (looked for " + strings.Join(DefaultFileNames, ", ") + ")"}
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func statError(path string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return &LoadError{Kind: ErrNotFound, Path: path, Err: err}
	case errors.Is(err, fs.ErrPermission):
		return &LoadError{Kind: ErrPermission, Path: path, Err: err}
	default:
		return &LoadError{Kind: ErrRead, Path: path, Detail: err.Error(), Err: err}
	}
}

func readSource(display string) (sourceFile, error) {
	abs, err := filepath.Abs(display)
	if err != nil {
		return sourceFile{}, &LoadError{Kind: ErrRead, Path: display, Detail: err.Error(), Err: err}
	}
	f, err := os.Open(abs)
	if err != nil {
		return sourceFile{}, statError(display, err)
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return sourceFile{}, statError(display, err)
	}
	if len(content) > maxFileSize {
		return sourceFile{}, &LoadError{Kind: ErrRead, Path: display, Detail: fmt.Sprintf("file is larger than %d MiB", maxFileSize>>20)}
	}
	raw, err := analyzeRaw(display, content)
	if err != nil {
		return sourceFile{}, err
	}
	return sourceFile{display: display, abs: abs, content: content, raw: raw}, nil
}

// logMu serializes access to logrus' global logger, which compose-go uses
// to emit warnings.
var logMu sync.Mutex

type warningHook struct{ messages []string }

func (h *warningHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h *warningHook) Fire(e *logrus.Entry) error {
	// Unset variables are reported by SST-CFG-001 and the obsolete "version"
	// attribute is detected from the raw YAML, because compose-go only warns
	// about it once per process.
	if e.Level <= logrus.WarnLevel && !strings.Contains(e.Message, "variable is not set") &&
		!strings.Contains(e.Message, "attribute `version` is obsolete") {
		h.messages = append(h.messages, e.Message)
	}
	return nil
}

func loadModel(ctx context.Context, files []sourceFile) (*types.Project, []string, error) {
	details := types.ConfigDetails{
		WorkingDir:  filepath.Dir(files[0].abs),
		Environment: types.Mapping{},
	}
	for _, f := range files {
		details.ConfigFiles = append(details.ConfigFiles, types.ConfigFile{Filename: f.abs, Content: f.content})
	}
	name := loader.NormalizeProjectName(filepath.Base(details.WorkingDir))
	if name == "" {
		name = "stacksentry"
	}

	logMu.Lock()
	defer logMu.Unlock()
	std := logrus.StandardLogger()
	hook := &warningHook{}
	prevHooks := std.ReplaceHooks(logrus.LevelHooks{})
	prevOut := std.Out
	std.AddHook(hook)
	std.SetOutput(io.Discard)
	defer func() {
		std.ReplaceHooks(prevHooks)
		std.SetOutput(prevOut)
	}()

	project, err := loader.LoadWithContext(ctx, details, func(o *loader.Options) {
		o.SetProjectName(name, false)
		o.SkipInclude = true
		o.SkipResolveEnvironment = true
		o.SkipResolveLabels = true
		o.ResolvePaths = false
		o.Profiles = []string{"*"}
		o.Interpolate.Substitute = lenientSubstitute
	})
	if err != nil {
		detail := strings.TrimPrefix(relativize(err.Error(), files), "validating "+files[0].display+": ")
		return nil, nil, &LoadError{Kind: ErrInvalidCompose, Path: files[0].display, Detail: detail, Err: err}
	}
	var warnings []string
	for _, m := range hook.messages {
		warnings = append(warnings, relativize(m, files))
	}
	sort.Strings(warnings)
	return project, warnings, nil
}

// lenientSubstitute interpolates like Compose but treats missing required
// variables (${VAR:?err}) as empty instead of failing, so that a file can be
// analyzed without the deployment environment.
func lenientSubstitute(value string, mapping template.Mapping) (string, error) {
	return template.SubstituteWithOptions(value, mapping,
		template.WithoutLogging,
		template.WithReplacementFunction(func(s string, m template.Mapping, cfg *template.Config) (string, error) {
			out, err := template.DefaultReplacementFunc(s, m, cfg)
			var missing *template.MissingRequiredError
			if errors.As(err, &missing) {
				return "", nil
			}
			return out, err
		}))
}

// relativize replaces absolute file names in compose-go messages with the
// paths the user supplied.
func relativize(msg string, files []sourceFile) string {
	for _, f := range files {
		msg = strings.ReplaceAll(msg, f.abs, f.display)
	}
	return msg
}
