# Maintainer: Your Name <your.email@example.com>

pkgname=om
pkgver=1.0.0
pkgrel=1
pkgdesc="Program Manager - Store and execute frequently used commands"
arch=('x86_64' 'aarch64')
url="https://github.com/Chitakasa/om"
license=('MIT')
depends=('gcc-libs')
makedepends=('gcc' 'make' 'nlohmann-json' 'cli11')
optdepends=(
    'bash-completion: bash completion support'
    'zsh-completions: zsh completion support'
    'fish: fish completion support'
)
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')  # Calculate actual checksum after first build

build() {
    cd "$pkgname-$pkgver"
    make
}

check() {
    cd "$pkgname-$pkgver"
    # Run tests if available
    ./om --version || return 1
}

package() {
    cd "$pkgname-$pkgver"
    
    # Install binary
    install -Dm755 om "$pkgdir/usr/bin/om"
    
    # Install man page
    install -Dm644 om.1 "$pkgdir/usr/share/man/man1/om.1"
    
    # Install completions
    install -Dm644 completions/om.bash \
        "$pkgdir/usr/share/bash-completion/completions/om"
    install -Dm644 completions/om.zsh \
        "$pkgdir/usr/share/zsh/site-functions/_om"
    install -Dm644 completions/om.fish \
        "$pkgdir/usr/share/fish/vendor_completions.d/om.fish"
    
    # Install license
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    
    # Install documentation
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}