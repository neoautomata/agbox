package msb

import (
	"fmt"
	"strconv"
	"strings"
)

// Category describes an installable group of packages and tools for the base sandbox.
type Category struct {
	Name        string
	Aliases     []string
	Summary     string
	Details     []string
	BuildScript func() string
}

// guestDefaultPath defines the PATH variable for the non-root guest user.
// It includes directories used by pipx, cargo, and go install.
const guestDefaultPath = "/home/agent/.local/bin:/home/agent/.cargo/bin:/home/agent/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func categories() []Category {
	return []Category{
		{
			Name:    "core",
			Aliases: []string{"base", "cli"},
			Summary: "Build tools, C headers, ccache, Python, uv, pipx, PDF tools, FUSE, shellcheck, mdformat-gfm, and CLI utilities",
			Details: []string{
				"apt: build-essential, pkg-config, cmake, ninja-build, ccache, fuse3, libffi-dev, libssl-dev, libsqlite3-dev, sqlite3",
				"apt: ca-certificates, curl, wget, git, htop, ncdu, net-tools, iproute2, dnsutils, rsync, unzip, zip, vim",
				"apt: jq, ripgrep, fd-find, shellcheck, less, procps, psmisc, lsof, strace, tree, file, openssh-client",
				"apt: poppler-utils, qpdf, python3-pypdf, python3, python3-pip, python3-setuptools, python3-venv, python3-wheel, pipx",
				"tools: uv (/usr/local/bin/uv), mdformat + mdformat-gfm (pipx), CMAKE_*_COMPILER_LAUNCHER=/usr/bin/ccache",
			},
			BuildScript: scriptCategoryCore,
		},
		{
			Name:    "go",
			Aliases: []string{"golang"},
			Summary: "Go toolchain and tools (dlv, gopls, golangci-lint, staticcheck, govulncheck, goimports, protoc-gen-go)",
			Details: []string{
				"toolchain: latest upstream Go in /usr/local/go (or apt golang-go) + protobuf-compiler",
				"go install: dlv, gopls, golangci-lint, goimports, staticcheck, govulncheck, protoc-gen-go, protoc-gen-go-grpc",
			},
			BuildScript: scriptCategoryGo,
		},
		{
			Name:    "rust",
			Aliases: []string{"cargo", "rustup"},
			Summary: "Rust stable toolchain via rustup (clippy, rustfmt, rust-analyzer, rust-src) and native linkers",
			Details: []string{
				"apt: clang, lld, pkg-config, libssl-dev, libudev-dev, libusb-1.0-0-dev, protobuf-compiler, sccache",
				"rustup: stable toolchain with clippy, rustfmt, rust-analyzer, rust-src",
			},
			BuildScript: scriptCategoryRust,
		},
		{
			Name:    "esphome",
			Aliases: []string{"esp"},
			Summary: "ESPHome, bundled PlatformIO (pre-warmed ESP32/ESP32-S3), esptool, and USB hardware libraries",
			Details: []string{
				"apt: libudev-dev, libusb-1.0-0-dev, udev, usbutils, cmake, ninja-build, gperf, ccache, dfu-util, picocom, minicom",
				"pipx: esphome (with pio/platformio symlinks from its venv), esptool",
				"pre-warm: ~/.platformio and penv (ESP32 and ESP32-S3, esp-idf and arduino), ccache patches, ESPHOME_* env",
			},
			BuildScript: scriptCategoryESPHome,
		},
		{
			Name:    "embedded-rust",
			Aliases: []string{"esp-rust"},
			Summary: "ESP32 RISC-V Rust targets, espflash, and ldproxy",
			Details: []string{
				"rustup target: riscv32imc-unknown-none-elf, riscv32imac-unknown-none-elf",
				"cargo: espflash, cargo-espflash, ldproxy",
			},
			BuildScript: scriptCategoryEmbeddedRust,
		},
		{
			Name:    "chrome",
			Aliases: []string{"browser", "chromium", "devtools"},
			Summary: "Chromium browser, WebDriver, fonts, and Xvfb for UI tests",
			Details: []string{
				"apt: chromium, chromium-driver, xvfb, fonts-liberation, fonts-noto-color-emoji, libnss3, libgbm1",
				"config: sandbox flags (--no-sandbox --disable-dev-shm-usage) and google-chrome symlink",
			},
			BuildScript: scriptCategoryChrome,
		},
		{
			Name:    "hugo",
			Aliases: []string{"static-site"},
			Summary: "Hugo Extended static site generator",
			Details: []string{
				"binary: Hugo Extended (CGO and Sass enabled) in /usr/local/bin/hugo",
			},
			BuildScript: scriptCategoryHugo,
		},
		{
			Name:    "caddy",
			Aliases: []string{"xcaddy"},
			Summary: "Custom Caddy build via xcaddy with cloudflare, caddy-security, and caddy-l4 modules",
			Details: []string{
				"go install: github.com/caddyserver/xcaddy/cmd/xcaddy@latest",
				"xcaddy modules: github.com/caddy-dns/cloudflare, github.com/greenpau/caddy-security, github.com/mholt/caddy-l4",
			},
			BuildScript: scriptCategoryCaddy,
		},
	}
}

// ResolveCategories expands category names, 1-based indices, aliases, or "all".
// It returns deduplicated Category values in catalog order.
func ResolveCategories(specs []string) ([]Category, error) {
	catalog := categories()
	selected := make(map[string]bool, len(catalog))

	for _, rawSpec := range specs {
		for _, tok := range strings.Split(rawSpec, ",") {
			name := strings.ToLower(strings.TrimSpace(tok))
			if name == "" {
				continue
			}
			if name == "all" || name == "a" {
				for _, c := range catalog {
					selected[c.Name] = true
				}
				continue
			}
			// Match a 1-based index from 1 through len(catalog).
			if idx, err := strconv.Atoi(name); err == nil && idx >= 1 && idx <= len(catalog) {
				selected[catalog[idx-1].Name] = true
				continue
			}
			matched := false
			for _, c := range catalog {
				if c.Name == name {
					selected[c.Name] = true
					matched = true
					break
				}
				for _, alias := range c.Aliases {
					if alias == name {
						selected[c.Name] = true
						matched = true
						break
					}
				}
			}
			if !matched {
				return nil, fmt.Errorf("unknown category %q (valid: %s, or all)", tok, CategoryNamesList())
			}
		}
	}

	// Add prerequisite toolchains.
	if selected["embedded-rust"] {
		selected["rust"] = true
	}
	if selected["caddy"] {
		selected["go"] = true
	}

	var ordered []Category
	for _, c := range catalog {
		if selected[c.Name] {
			ordered = append(ordered, c)
		}
	}
	return ordered, nil
}

// CategoryNames returns the canonical category names in catalog order.
func CategoryNames() []string {
	cats := categories()
	names := make([]string, len(cats))
	for i, c := range cats {
		names[i] = c.Name
	}
	return names
}

// CategoryNamesList returns a comma-separated list of category names.
func CategoryNamesList() string {
	return strings.Join(CategoryNames(), ", ")
}

// FormatCategoriesTable formats a summary of all categories.
func FormatCategoriesTable() string {
	var b strings.Builder
	b.WriteString("Available base-image categories:\n\n")
	for i, c := range categories() {
		aliasStr := ""
		if len(c.Aliases) > 0 {
			aliasStr = fmt.Sprintf(" (aliases: %s)", strings.Join(c.Aliases, ", "))
		}
		fmt.Fprintf(&b, "  %d) %-14s %s%s\n", i+1, c.Name, c.Summary, aliasStr)
		for _, d := range c.Details {
			fmt.Fprintf(&b, "                    - %s\n", d)
		}
	}
	b.WriteString("\nPass 'all' to install every category. Or pass a comma-separated list such as --add core,go,rust.\n")
	return b.String()
}

// MergeCategoryNames merges existing category names with added categories in catalog order.
func MergeCategoryNames(existingCSV string, added []Category) string {
	have := make(map[string]bool)
	for _, tok := range strings.Split(existingCSV, ",") {
		t := strings.TrimSpace(tok)
		if t != "" {
			have[t] = true
		}
	}
	for _, c := range added {
		have[c.Name] = true
	}
	var out []string
	for _, c := range categories() {
		if have[c.Name] {
			out = append(out, c.Name)
		}
	}
	return strings.Join(out, ",")
}

// BuildCategoriesScript combines category install scripts into one bash script.
func BuildCategoriesScript(cats []Category) string {
	if len(cats) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	b.WriteString("export DEBIAN_FRONTEND=noninteractive\n")
	b.WriteString("resize2fs /dev/vdb >/dev/null 2>&1 || true\n")
	b.WriteString("mkdir -p /var/tmp && chmod 1777 /var/tmp\n")
	b.WriteString("export TMPDIR=/var/tmp\n")
	b.WriteString(ensureGuestPathProfileSnippet())
	for i, c := range cats {
		b.WriteString("\n# --- category: " + c.Name + " ---\n")
		fmt.Fprintf(&b, "echo '[agbox] (%d/%d) Installing category %s...'\n", i+1, len(cats), c.Name)
		b.WriteString(c.BuildScript())
		b.WriteByte('\n')
		b.WriteString("rm -rf /var/tmp/* /tmp/*\n")
		fmt.Fprintf(&b, "echo '[agbox] (%d/%d) Completed category %s.'\n", i+1, len(cats), c.Name)
	}
	b.WriteString("\napt-get clean\nrm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/*\n")
	b.WriteString("chown -R 1000:1000 /home/agent /workspace\n")
	b.WriteString("fstrim / >/dev/null 2>&1 || true\n")
	return b.String()
}

func ensureGuestPathProfileSnippet() string {
	return fmt.Sprintf(`mkdir -p /etc/agbox-env.d
cat > /etc/profile.d/agbox-path.sh <<'EOF'
export PATH="%s"
export PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
for _agbox_env in /etc/agbox-env.d/*.sh; do
  [ -f "$_agbox_env" ] && . "$_agbox_env"
done
unset _agbox_env
EOF
chmod 0644 /etc/profile.d/agbox-path.sh
grep -q 'agbox-path.sh' /home/agent/.bashrc 2>/dev/null || \
  echo '[ -f /etc/profile.d/agbox-path.sh ] && . /etc/profile.d/agbox-path.sh' >> /home/agent/.bashrc
grep -q 'agbox-path.sh' /home/agent/.profile 2>/dev/null || \
  echo '[ -f /etc/profile.d/agbox-path.sh ] && . /etc/profile.d/agbox-path.sh' >> /home/agent/.profile
`, guestDefaultPath)
}

func ensureCcacheEnvSnippet() string {
	return `mkdir -p /etc/agbox-env.d
cat > /etc/agbox-env.d/10-ccache.sh <<'EOF'
if [ -x /usr/bin/ccache ]; then
  export CMAKE_C_COMPILER_LAUNCHER="${CMAKE_C_COMPILER_LAUNCHER:-/usr/bin/ccache}"
  export CMAKE_CXX_COMPILER_LAUNCHER="${CMAKE_CXX_COMPILER_LAUNCHER:-/usr/bin/ccache}"
fi
EOF
chmod 0644 /etc/agbox-env.d/10-ccache.sh
`
}

func scriptCategoryCore() string {
	return `apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential ca-certificates curl wget git htop ncdu net-tools iproute2 dnsutils \
  libffi-dev libssl-dev libsqlite3-dev sqlite3 pkg-config cmake ninja-build ccache fuse3 \
  poppler-utils qpdf python3-pypdf \
  python3 python3-pip python3-setuptools python3-venv python3-wheel pipx \
  rsync unzip zip vim jq ripgrep fd-find shellcheck less procps psmisc lsof strace tree file openssh-client >/dev/null
if [ -x /usr/bin/fdfind ]; then
  ln -sfn /usr/bin/fdfind /usr/local/bin/fd
fi
echo '[agbox]   -> Installing uv system-wide in /usr/local/bin...'
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh
su - agent -c 'set -euo pipefail; export PATH="/home/agent/.local/bin:$PATH" && pipx install --force mdformat && pipx inject mdformat mdformat-gfm && rm -rf /home/agent/.cache/pip'
if [ -x /home/agent/.local/bin/mdformat ]; then
  ln -sf /home/agent/.local/bin/mdformat /usr/local/bin/mdformat
fi
` + ensureCcacheEnvSnippet()
}

func scriptCategoryGo() string {
	return `apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential ca-certificates curl git pkg-config protobuf-compiler >/dev/null

# Install the upstream Go toolchain in /usr/local/go if absent, or use apt golang-go.
if [ ! -x /usr/local/go/bin/go ]; then
  echo '[agbox]   -> Downloading upstream Go toolchain...'
  arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
  go_ver="$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL 'https://go.dev/VERSION?m=text' 2>/dev/null | head -1 || true)"
  if [[ "${go_ver}" =~ ^go[0-9]+\.[0-9]+(\.[0-9]+|(rc|beta)[0-9]+)?$ ]] && [[ "${arch}" =~ ^[a-z0-9_]+$ ]]; then
    if curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL "https://go.dev/dl/${go_ver}.linux-${arch}.tar.gz" -o /tmp/go.tgz && tar -C /usr/local -xzf /tmp/go.tgz; then
      rm -f /tmp/go.tgz
    else
      rm -rf /usr/local/go /tmp/go.tgz
    fi
  fi
  if [ ! -x /usr/local/go/bin/go ]; then
    apt-get install -y -qq --no-install-recommends golang-go >/dev/null
  fi
fi

su - agent -c '
  set -euo pipefail
  export PATH="/usr/local/go/bin:/home/agent/go/bin:$PATH"
  export TMPDIR=/var/tmp
  mkdir -p /home/agent/go/bin
  echo "[agbox]   -> Installing golangci-lint..."
  if ! curl --proto "=https" --proto-redir "=https" --tlsv1.2 -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b /home/agent/go/bin; then
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
  fi
  for pkg in \
    github.com/go-delve/delve/cmd/dlv@latest \
    golang.org/x/tools/gopls@latest \
    golang.org/x/tools/cmd/goimports@latest \
    honnef.co/go/tools/cmd/staticcheck@latest \
    golang.org/x/vuln/cmd/govulncheck@latest \
    google.golang.org/protobuf/cmd/protoc-gen-go@latest \
    google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
  do
    echo "[agbox]   -> go install ${pkg}..."
    go install "${pkg}"
  done
  go clean -cache -modcache
'
`
}

func scriptCategoryRust() string {
	return `apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential ca-certificates curl git pkg-config clang lld \
  libssl-dev libffi-dev libudev-dev libusb-1.0-0-dev protobuf-compiler sccache >/dev/null

su - agent -c '
  set -euo pipefail
  if [ ! -x /home/agent/.cargo/bin/rustup ]; then
    echo "[agbox]   -> Installing rustup stable toolchain..."
    curl --proto "=https" --proto-redir "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  fi
  . "/home/agent/.cargo/env"
  rustup update
  echo "[agbox]   -> Adding rustup components (clippy, rustfmt, rust-analyzer, rust-src)..."
  rustup component add clippy rustfmt rust-analyzer rust-src
'
`
}

func scriptCategoryESPHome() string {
	return `apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential ca-certificates curl wget git \
  libffi-dev libssl-dev libudev-dev libusb-1.0-0-dev udev usbutils \
  pkg-config cmake ninja-build gperf ccache dfu-util picocom minicom \
  python3 python3-pip python3-setuptools python3-venv python3-wheel pipx \
  rsync unzip zip >/dev/null

` + ensureCcacheEnvSnippet() + `mkdir -p /etc/agbox-env.d
cat > /etc/agbox-env.d/20-esphome.sh <<'EOF'
export ESPHOME_DATA_DIR="${ESPHOME_DATA_DIR:-/home/agent/.cache/esphome}"
export ESPHOME_NOGITIGNORE="${ESPHOME_NOGITIGNORE:-1}"
for _pio_bin in \
  /home/agent/.platformio/packages/toolchain-xtensa-esp-elf/bin \
  /home/agent/.platformio/packages/toolchain-riscv32-esp/bin \
  /home/agent/.platformio/packages/toolchain-riscv32-esp-elf/bin
do
  if [ -d "$_pio_bin" ]; then
    case ":$PATH:" in
      *":$_pio_bin:"*) ;;
      *) export PATH="$PATH:$_pio_bin" ;;
    esac
  fi
done
unset _pio_bin
EOF
chmod 0644 /etc/agbox-env.d/20-esphome.sh

su - agent -s /bin/bash <<'AGENT_EOF'
set -euo pipefail
export PATH="/home/agent/.local/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
export ESPHOME_NOGITIGNORE=1
export CMAKE_C_COMPILER_LAUNCHER=/usr/bin/ccache
export CMAKE_CXX_COMPILER_LAUNCHER=/usr/bin/ccache

echo "[agbox]   -> pipx install esphome..."
pipx install --force esphome
echo "[agbox]   -> pipx install esptool..."
pipx install --force esptool
# Avoid a separate pipx platformio venv that skews from ESPHome's bundled PlatformIO.
pipx uninstall platformio >/dev/null 2>&1 || true
esphome_venv_bin="$(dirname "$(readlink -f /home/agent/.local/bin/esphome)")"
for bin_name in pio platformio piodebuggdb; do
  if [ -x "${esphome_venv_bin}/${bin_name}" ]; then
    ln -sfn "${esphome_venv_bin}/${bin_name}" "/home/agent/.local/bin/${bin_name}"
  fi
done

prewarm_dir="/var/tmp/agbox-esphome-prewarm"
rm -rf "${prewarm_dir}"
mkdir -p "${prewarm_dir}/data"
export ESPHOME_DATA_DIR="${prewarm_dir}/data"

cat > "${prewarm_dir}/esp32-idf.yaml" <<'YAML_EOF'
esphome:
  name: prewarm-esp32-idf
esp32:
  board: esp32dev
  framework:
    type: esp-idf
YAML_EOF

cat > "${prewarm_dir}/esp32-arduino.yaml" <<'YAML_EOF'
esphome:
  name: prewarm-esp32-arduino
esp32:
  board: esp32dev
  framework:
    type: arduino
YAML_EOF

cat > "${prewarm_dir}/esp32s3-idf.yaml" <<'YAML_EOF'
esphome:
  name: prewarm-esp32s3-idf
esp32:
  board: esp32-s3-devkitc-1
  framework:
    type: esp-idf
YAML_EOF

cat > "${prewarm_dir}/esp32s3-arduino.yaml" <<'YAML_EOF'
esphome:
  name: prewarm-esp32s3-arduino
esp32:
  board: esp32-s3-devkitc-1
  framework:
    type: arduino
YAML_EOF

for cfg in esp32-idf.yaml esp32-arduino.yaml esp32s3-idf.yaml esp32s3-arduino.yaml; do
  echo "[agbox]   -> Pre-warming ~/.platformio with ${cfg}..."
  esphome compile "${prewarm_dir}/${cfg}"
done

test -d /home/agent/.platformio/penv

echo "[agbox]   -> Patching PlatformIO espressif32 builder scripts for ccache..."
python3 - <<'PY_EOF'
import glob
import os

for plat_dir in sorted(glob.glob("/home/agent/.platformio/platforms/espressif32*")):
    main_py = os.path.join(plat_dir, "builder", "main.py")
    if os.path.isfile(main_py):
        with open(main_py, "r", encoding="utf-8") as f:
            src = f.read()
        if "ccache_prefix" not in src:
            cc_old = '    CC="%s-elf-gcc" % toolchain_arch,'
            cxx_old = '    CXX="%s-elf-g++" % toolchain_arch,'
            cc_idx = src.find(cc_old)
            rep_idx = src.rfind("env.Replace(", 0, cc_idx) if cc_idx != -1 else -1
            if rep_idx != -1 and cxx_old in src:
                prefix_block = (
                    'ccache_bin = "/usr/bin/ccache"\n'
                    'ccache_prefix = (\n'
                    '    f"{ccache_bin} "\n'
                    '    if (os.path.isfile(ccache_bin) and os.access(ccache_bin, os.X_OK))\n'
                    '    else ""\n'
                    ')\n'
                )
                src = src[:rep_idx] + prefix_block + src[rep_idx:]
                src = src.replace(cc_old, '    CC=f"{ccache_prefix}%s-elf-gcc" % toolchain_arch,', 1)
                src = src.replace(cxx_old, '    CXX=f"{ccache_prefix}%s-elf-g++" % toolchain_arch,', 1)
                with open(main_py, "w", encoding="utf-8") as f:
                    f.write(src)

    espidf_py = os.path.join(plat_dir, "builder", "frameworks", "espidf.py")
    if os.path.isfile(espidf_py):
        with open(espidf_py, "r", encoding="utf-8") as f:
            src = f.read()
        if '"-DCMAKE_C_COMPILER_LAUNCHER=/usr/bin/ccache"' not in src:
            fn_idx = src.find("def run_cmake(")
            anchor = "    if extra_args:"
            anchor_idx = src.find(anchor, fn_idx) if fn_idx != -1 else -1
            if anchor_idx != -1:
                snippet = (
                    '    if os.path.isfile("/usr/bin/ccache"):\n'
                    '        cmd.extend([\n'
                    '            "-DCMAKE_C_COMPILER_LAUNCHER=/usr/bin/ccache",\n'
                    '            "-DCMAKE_CXX_COMPILER_LAUNCHER=/usr/bin/ccache",\n'
                    '        ])\n\n'
                )
                src = src[:anchor_idx] + snippet + src[anchor_idx:]
                with open(espidf_py, "w", encoding="utf-8") as f:
                    f.write(src)
PY_EOF

rm -rf "${prewarm_dir}" /home/agent/.cache/pip
AGENT_EOF
`
}

func scriptCategoryEmbeddedRust() string {
	return `su - agent -c '
  set -euo pipefail
  . "/home/agent/.cargo/env"
  echo "[agbox]   -> Adding RISC-V Rust targets..."
  rustup target add riscv32imc-unknown-none-elf riscv32imac-unknown-none-elf
  if ! command -v cargo-binstall >/dev/null 2>&1; then
    echo "[agbox]   -> Installing cargo-binstall for prebuilt binary downloads..."
    curl -L --proto "=https" --proto-redir "=https" --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash || true
  fi
  if command -v cargo-binstall >/dev/null 2>&1; then
    echo "[agbox]   -> Installing espflash, cargo-espflash, and ldproxy via cargo-binstall..."
    cargo binstall -y espflash cargo-espflash ldproxy || cargo install espflash cargo-espflash ldproxy
  else
    echo "[agbox]   -> Building espflash, cargo-espflash, and ldproxy via cargo install..."
    cargo install espflash cargo-espflash ldproxy
  fi
  rm -rf /home/agent/.cargo/registry/cache /home/agent/.cargo/git/db
'
`
}

func scriptCategoryChrome() string {
	return `apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  chromium chromium-driver xvfb fonts-liberation fonts-noto-color-emoji \
  libnss3 libatk-bridge2.0-0 libdrm2 libxkbcommon0 libgbm1 >/dev/null
mkdir -p /etc/chromium.d
echo 'export CHROMIUM_FLAGS="${CHROMIUM_FLAGS:-} --no-sandbox --disable-dev-shm-usage"' > /etc/chromium.d/agbox-flags
if [ -x /usr/bin/chromium ]; then
  ln -sfn /usr/bin/chromium /usr/local/bin/google-chrome
  ln -sfn /usr/bin/chromium /usr/local/bin/chrome
fi
`
}

func scriptCategoryHugo() string {
	return `apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential ca-certificates curl git >/dev/null

arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
hugo_ver="$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL https://api.github.com/repos/gohugoio/hugo/releases/latest 2>/dev/null | grep -oE '"tag_name": *"v[^"]+"' | head -1 | sed -E 's/.*"v([^"]+)".*/\1/' || true)"
if [[ "${hugo_ver}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9._-]+)?$ ]] && [[ "${arch}" =~ ^[a-z0-9_]+$ ]] && curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL "https://github.com/gohugoio/hugo/releases/download/v${hugo_ver}/hugo_extended_${hugo_ver}_linux-${arch}.tar.gz" -o /tmp/hugo.tgz; then
  tar -C /usr/local/bin -xzf /tmp/hugo.tgz hugo
  chmod 0755 /usr/local/bin/hugo
  rm -f /tmp/hugo.tgz
else
  apt-get install -y -qq --no-install-recommends hugo >/dev/null
fi
`
}

func scriptCategoryCaddy() string {
	return `su - agent -c '
  set -euo pipefail
  export PATH="/usr/local/go/bin:/home/agent/go/bin:$PATH"
  export TMPDIR=/var/tmp
  echo "[agbox]   -> Installing xcaddy..."
  go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
  echo "[agbox]   -> Building custom caddy binary with xcaddy..."
  xcaddy build \
    --output /home/agent/go/bin/caddy \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/greenpau/caddy-security \
    --with github.com/mholt/caddy-l4
  go clean -cache -modcache
'
install -m 0755 /home/agent/go/bin/caddy /usr/local/bin/caddy
`
}
