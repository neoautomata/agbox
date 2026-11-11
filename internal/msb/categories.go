package msb

import (
	"fmt"
	"strconv"
	"strings"
)

// Category describes an installable group of packages and developer tools for
// the base microVM.
type Category struct {
	Name        string
	Aliases     []string
	Summary     string
	Details     []string
	BuildScript func() string
}

// GuestDefaultPath is the PATH configured for the non-root guest user so tools
// installed by pipx, rustup/cargo, and go install are available in all shells.
const GuestDefaultPath = "/home/agent/.local/bin:/home/agent/.cargo/bin:/home/agent/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Categories returns the ordered catalog of base-image provisioning categories.
func Categories() []Category {
	return []Category{
		{
			Name:    "core",
			Aliases: []string{"base", "cli"},
			Summary: "Core build chain, C headers, Python/pipx, mdformat, and CLI utilities",
			Details: []string{
				"apt: build-essential, pkg-config, cmake, ninja-build, libffi-dev, libssl-dev, libsqlite3-dev, sqlite3",
				"apt: ca-certificates, curl, wget, git, htop, ncdu, net-tools, iproute2, dnsutils, rsync, unzip, zip, vim",
				"apt: jq, ripgrep, fd-find, less, procps, psmisc, lsof, strace, tree, file, openssh-client",
				"apt: python3, python3-pip, python3-setuptools, python3-venv, python3-wheel, pipx",
				"pipx: mdformat",
			},
			BuildScript: scriptCategoryCore,
		},
		{
			Name:    "go",
			Aliases: []string{"golang"},
			Summary: "Go toolchain and developer tools (dlv, gopls, golangci-lint, staticcheck, govulncheck, goimports)",
			Details: []string{
				"toolchain: latest upstream Go in /usr/local/go (fallback: apt golang-go) + protobuf-compiler",
				"go install: dlv, gopls, golangci-lint, goimports, staticcheck, govulncheck",
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
			Summary: "ESPHome, PlatformIO, esptool, and ESP-IDF/USB hardware libraries",
			Details: []string{
				"apt: libudev-dev, libusb-1.0-0-dev, udev, usbutils, cmake, ninja-build, gperf, ccache, dfu-util, picocom, minicom",
				"pipx: esphome, esptool, platformio",
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
			Summary: "Chrome/Chromium browser, WebDriver, fonts, and Xvfb for DevTools and UI testing",
			Details: []string{
				"apt: chromium, chromium-driver, xvfb, fonts-liberation, fonts-noto-color-emoji, libnss3, libgbm1",
				"config: microVM-ready flags (--no-sandbox --disable-dev-shm-usage) and google-chrome symlink",
			},
			BuildScript: scriptCategoryChrome,
		},
		{
			Name:    "hugo",
			Aliases: []string{"static-site"},
			Summary: "Hugo Extended static site generator",
			Details: []string{
				"binary: Hugo Extended (CGO/Sass enabled) installed to /usr/local/bin/hugo",
			},
			BuildScript: scriptCategoryHugo,
		},
		{
			Name:    "caddy",
			Aliases: []string{"xcaddy"},
			Summary: "Custom Caddy build via xcaddy with cloudflare, caddy-security, point-c, and tailscale modules",
			Details: []string{
				"go install: github.com/caddyserver/xcaddy/cmd/xcaddy@latest",
				"xcaddy modules: github.com/caddy-dns/cloudflare, github.com/greenpau/caddy-security, github.com/point-c/caddy/module@latest, github.com/tailscale/caddy-tailscale",
			},
			BuildScript: scriptCategoryCaddy,
		},
	}
}

// ResolveCategories expands a list of category names (or comma-separated lists,
// numeric indices, aliases, or "all") into a deduplicated slice of Category
// structs in canonical installation order.
func ResolveCategories(specs []string) ([]Category, error) {
	catalog := Categories()
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
			// Support 1-based numeric index selection (1..len(catalog)).
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
				return nil, fmt.Errorf("unknown category %q (valid categories: %s, or all)", tok, CategoryNamesList())
			}
		}
	}

	// Ensure prerequisite toolchains are included automatically.
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

// CategoryNamesList returns a comma-separated list of canonical category names.
func CategoryNamesList() string {
	cats := Categories()
	names := make([]string, len(cats))
	for i, c := range cats {
		names[i] = c.Name
	}
	return strings.Join(names, ", ")
}

// FormatCategoriesTable returns a human-readable summary of all categories.
func FormatCategoriesTable() string {
	var b strings.Builder
	b.WriteString("Available base-image categories:\n\n")
	for i, c := range Categories() {
		aliasStr := ""
		if len(c.Aliases) > 0 {
			aliasStr = fmt.Sprintf(" (aliases: %s)", strings.Join(c.Aliases, ", "))
		}
		fmt.Fprintf(&b, "  %d) %-14s %s%s\n", i+1, c.Name, c.Summary, aliasStr)
		for _, d := range c.Details {
			fmt.Fprintf(&b, "                    - %s\n", d)
		}
	}
	b.WriteString("\nUse 'all' to install every category, or pass a comma-separated list (for example: --add core,go,rust,esphome,chrome,hugo,caddy).\n")
	return b.String()
}

// MergeCategoryNames merges existing comma-separated category names with newly
// installed categories in canonical catalog order.
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
	for _, c := range Categories() {
		if have[c.Name] {
			out = append(out, c.Name)
		}
	}
	return strings.Join(out, ",")
}

// BuildCategoriesScript combines the installation scripts for the given
// categories into a single idempotent bash script.
func BuildCategoriesScript(cats []Category) string {
	if len(cats) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("set -euo pipefail\n")
	b.WriteString("export DEBIAN_FRONTEND=noninteractive\n")
	b.WriteString(ensureGuestPathProfileSnippet())
	for _, c := range cats {
		b.WriteString("\n# --- category: " + c.Name + " ---\n")
		b.WriteString(c.BuildScript())
		b.WriteByte('\n')
	}
	b.WriteString("\napt-get clean\nrm -rf /var/lib/apt/lists/*\n")
	b.WriteString("chown -R 1000:1000 /home/agent /workspace\n")
	return b.String()
}

func ensureGuestPathProfileSnippet() string {
	return fmt.Sprintf(`cat > /etc/profile.d/agbox-path.sh <<'EOF'
export PATH="%s"
EOF
chmod 0644 /etc/profile.d/agbox-path.sh
grep -q 'agbox-path.sh' /home/agent/.bashrc 2>/dev/null || \
  echo '[ -f /etc/profile.d/agbox-path.sh ] && . /etc/profile.d/agbox-path.sh' >> /home/agent/.bashrc
grep -q 'agbox-path.sh' /home/agent/.profile 2>/dev/null || \
  echo '[ -f /etc/profile.d/agbox-path.sh ] && . /etc/profile.d/agbox-path.sh' >> /home/agent/.profile
`, GuestDefaultPath)
}

func scriptCategoryCore() string {
	return `apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential ca-certificates curl wget git htop ncdu net-tools iproute2 dnsutils \
  libffi-dev libssl-dev libsqlite3-dev sqlite3 pkg-config cmake ninja-build \
  python3 python3-pip python3-setuptools python3-venv python3-wheel pipx \
  rsync unzip zip vim jq ripgrep fd-find less procps psmisc lsof strace tree file openssh-client >/dev/null
if [ -x /usr/bin/fdfind ] && [ ! -e /usr/local/bin/fd ]; then
  ln -s /usr/bin/fdfind /usr/local/bin/fd
fi
su - agent -c 'export PATH="/home/agent/.local/bin:$PATH"; pipx install --force mdformat'
`
}

func scriptCategoryGo() string {
	return `apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential ca-certificates curl git pkg-config protobuf-compiler >/dev/null

# Install upstream Go toolchain in /usr/local/go if missing, with apt fallback.
if [ ! -x /usr/local/go/bin/go ]; then
  arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
  go_ver="$(curl -fsSL 'https://go.dev/VERSION?m=text' 2>/dev/null | head -1 || true)"
  if [ -n "${go_ver}" ]; then
    if curl -fsSL "https://go.dev/dl/${go_ver}.linux-${arch}.tar.gz" -o /tmp/go.tgz; then
      rm -rf /usr/local/go
      tar -C /usr/local -xzf /tmp/go.tgz
      rm -f /tmp/go.tgz
    fi
  fi
  if [ ! -x /usr/local/go/bin/go ]; then
    apt-get install -y -qq --no-install-recommends golang-go >/dev/null
  fi
fi

su - agent -c '
  set -euo pipefail
  export PATH="/usr/local/go/bin:/home/agent/go/bin:$PATH"
  go install github.com/go-delve/delve/cmd/dlv@latest
  go install golang.org/x/tools/gopls@latest
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
  go install golang.org/x/tools/cmd/goimports@latest
  go install honnef.co/go/tools/cmd/staticcheck@latest
  go install golang.org/x/vuln/cmd/govulncheck@latest
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
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  fi
  . "/home/agent/.cargo/env"
  rustup update
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

su - agent -c '
  set -euo pipefail
  export PATH="/home/agent/.local/bin:$PATH"
  pipx install --force esphome
  pipx install --force esptool
  pipx install --force platformio
'
`
}

func scriptCategoryEmbeddedRust() string {
	return `su - agent -c '
  set -euo pipefail
  . "/home/agent/.cargo/env"
  rustup target add riscv32imc-unknown-none-elf riscv32imac-unknown-none-elf
  cargo install espflash cargo-espflash ldproxy
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
if [ -x /usr/bin/chromium ] && [ ! -e /usr/local/bin/google-chrome ]; then
  ln -s /usr/bin/chromium /usr/local/bin/google-chrome
fi
if [ -x /usr/bin/chromium ] && [ ! -e /usr/local/bin/chrome ]; then
  ln -s /usr/bin/chromium /usr/local/bin/chrome
fi
`
}

func scriptCategoryHugo() string {
	return `apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential ca-certificates curl git >/dev/null

arch="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
hugo_ver="$(curl -fsSL https://api.github.com/repos/gohugoio/hugo/releases/latest 2>/dev/null | grep -oE '"tag_name": *"v[^"]+"' | head -1 | sed -E 's/.*"v([^"]+)".*/\1/' || true)"
if [ -n "${hugo_ver}" ] && curl -fsSL "https://github.com/gohugoio/hugo/releases/download/v${hugo_ver}/hugo_extended_${hugo_ver}_linux-${arch}.tar.gz" -o /tmp/hugo.tgz; then
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
  go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
  xcaddy build \
    --output /home/agent/go/bin/caddy \
    --with github.com/caddy-dns/cloudflare \
    --with github.com/greenpau/caddy-security \
    --with github.com/point-c/caddy/module@latest \
    --with github.com/tailscale/caddy-tailscale
'
install -m 0755 /home/agent/go/bin/caddy /usr/local/bin/caddy
`
}
