param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$repo = "yetanotherchris/rclone-encrypt-minimaxm27"
$platforms = @("darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64")
$formulaPath = "$PSScriptRoot/Formula/rclone-encrypt-minimaxm27.rb"
$base = "https://github.com/$repo/releases/download/v$Version"

# Download each release tarball and compute its SHA256.
$hash = @{}
foreach ($platform in $platforms) {
    $url = "$base/rclone-encrypt-minimaxm27-$platform.tar.gz"
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "rclone-encrypt-minimaxm27-$platform.tar.gz"

    Write-Host "Downloading $url ..."
    Invoke-WebRequest -Uri $url -OutFile $tempFile

    $hash[$platform] = (Get-FileHash -Path $tempFile -Algorithm SHA256).Hash.ToLower()
    Write-Host "SHA256 for ${platform}: $($hash[$platform])"

    Remove-Item $tempFile
}

# Regenerate the formula wholesale so it stays correct across releases (a
# placeholder-substitution approach only works for the first release, and a
# case-insensitive replace would clobber the `version` keyword / `--version`).
$formula = @"
class RcloneEncryptMinimaxm27 < Formula
  desc "A small CLI tool that encrypts and decrypts using the rclone encryption defaults"
  homepage "https://github.com/$repo"
  version "$Version"

  on_macos do
    if Hardware::CPU.arm?
      url "$base/rclone-encrypt-minimaxm27-darwin-arm64.tar.gz"
      sha256 "$($hash['darwin-arm64'])"
    else
      url "$base/rclone-encrypt-minimaxm27-darwin-amd64.tar.gz"
      sha256 "$($hash['darwin-amd64'])"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "$base/rclone-encrypt-minimaxm27-linux-arm64.tar.gz"
      sha256 "$($hash['linux-arm64'])"
    else
      url "$base/rclone-encrypt-minimaxm27-linux-amd64.tar.gz"
      sha256 "$($hash['linux-amd64'])"
    end
  end

  def install
    bin.install "rclone-encrypt-minimaxm27-darwin-arm64" => "rclone-encrypt-minimaxm27" if OS.mac? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-minimaxm27-darwin-amd64" => "rclone-encrypt-minimaxm27" if OS.mac? && !Hardware::CPU.arm?
    bin.install "rclone-encrypt-minimaxm27-linux-arm64" => "rclone-encrypt-minimaxm27" if OS.linux? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-minimaxm27-linux-amd64" => "rclone-encrypt-minimaxm27" if OS.linux? && !Hardware::CPU.arm?
  end

  test do
    assert_match "rclone-encrypt-minimaxm27", shell_output("#{bin}/rclone-encrypt-minimaxm27 --help")
  end
end
"@

Set-Content -Path $formulaPath -Value $formula -NoNewline
Write-Host "Wrote $formulaPath for version $Version"