class RcloneEncryptMinimaxm27 < Formula
  desc "CLI tool to encrypt and decrypt files using rclone encryption defaults"
  homepage "https://github.com/llm-supermarket-org/rclone-encrypt-minimaxm27"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket-org/rclone-encrypt-minimaxm27/releases/download/v1.0.0/rclone-encrypt-minimaxm27-darwin-arm64.tar.gz"
      sha256 "PLACEHOLDER"
    else
      url "https://github.com/llm-supermarket-org/rclone-encrypt-minimaxm27/releases/download/v1.0.0/rclone-encrypt-minimaxm27-darwin-amd64.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket-org/rclone-encrypt-minimaxm27/releases/download/v1.0.0/rclone-encrypt-minimaxm27-linux-arm64.tar.gz"
      sha256 "PLACEHOLDER"
    else
      url "https://github.com/llm-supermarket-org/rclone-encrypt-minimaxm27/releases/download/v1.0.0/rclone-encrypt-minimaxm27-linux-amd64.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  def install
    bin.install "rclone-encrypt-minimaxm27-darwin-arm64" => "rclone-encrypt-minimaxm27" if OS.mac? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-minimaxm27-darwin-amd64" => "rclone-encrypt-minimaxm27" if OS.mac? && !Hardware::CPU.arm?
    bin.install "rclone-encrypt-minimaxm27-linux-arm64" => "rclone-encrypt-minimaxm27" if OS.linux? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-minimaxm27-linux-amd64" => "rclone-encrypt-minimaxm27" if OS.linux? && !Hardware::CPU.arm?
  end

  test do
    assert_match "rclone-encrypt-minimaxm27", shell_output("#{bin}/rclone-encrypt-minimaxm27 --version")
  end
end