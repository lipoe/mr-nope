#!/usr/bin/env node
"use strict";

const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const { createWriteStream } = require("fs");

const SUPPORTED_PLATFORMS = {
  "linux-x64": "mr-nope-linux-x64",
  "darwin-x64": "mr-nope-darwin-x64",
  "darwin-arm64": "mr-nope-darwin-arm64",
  "win32-x64": "mr-nope-win32-x64.exe",
};

const REPO = "lipoe/mr-nope";

function getPlatformKey() {
  const platform = process.platform;
  const arch = process.arch;
  return `${platform}-${arch}`;
}

function getVersion() {
  const packageJson = JSON.parse(
    fs.readFileSync(path.join(__dirname, "package.json"), "utf8")
  );
  return packageJson.version;
}

function getDownloadUrl(version, binaryName) {
  return `https://github.com/${REPO}/releases/download/v${version}/${binaryName}`;
}

function followRedirects(url, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) {
      return reject(new Error("Too many redirects"));
    }

    const client = url.startsWith("https://") ? https : http;

    client
      .get(url, { headers: { "User-Agent": "mr-nope-installer" } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          resolve(followRedirects(res.headers.location, maxRedirects - 1));
        } else if (res.statusCode === 200) {
          resolve(res);
        } else {
          reject(
            new Error(
              `Failed to download: HTTP ${res.statusCode} from ${url}`
            )
          );
        }
      })
      .on("error", reject);
  });
}

function downloadFile(url, destPath) {
  return new Promise(async (resolve, reject) => {
    try {
      const res = await followRedirects(url);
      const fileStream = createWriteStream(destPath);

      res.pipe(fileStream);

      fileStream.on("finish", () => {
        fileStream.close();
        resolve();
      });

      fileStream.on("error", (err) => {
        fs.unlink(destPath, () => {});
        reject(err);
      });

      res.on("error", (err) => {
        fs.unlink(destPath, () => {});
        reject(err);
      });
    } catch (err) {
      reject(err);
    }
  });
}

async function main() {
  const platformKey = getPlatformKey();
  const binaryName = SUPPORTED_PLATFORMS[platformKey];

  if (!binaryName) {
    const supported = Object.keys(SUPPORTED_PLATFORMS).join(", ");
    console.error(
      `Error: Unsupported platform "${platformKey}".\n` +
        `mr-nope supports the following platforms: ${supported}\n` +
        `Please visit https://github.com/${REPO}/releases for manual installation.`
    );
    process.exit(1);
  }

  const version = getVersion();
  const url = getDownloadUrl(version, binaryName);
  const binDir = path.join(__dirname, "bin");
  const destPath = path.join(binDir, binaryName);

  // Ensure bin directory exists
  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }

  // Skip download if binary already exists
  if (fs.existsSync(destPath)) {
    console.log(`mr-nope binary already exists at ${destPath}`);
    return;
  }

  console.log(`Downloading mr-nope v${version} for ${platformKey}...`);
  console.log(`  URL: ${url}`);

  try {
    await downloadFile(url, destPath);

    // Make binary executable on Unix platforms
    if (process.platform !== "win32") {
      fs.chmodSync(destPath, 0o755);
    }

    console.log(`Successfully installed mr-nope binary to ${destPath}`);
  } catch (error) {
    // Clean up partial download
    if (fs.existsSync(destPath)) {
      fs.unlinkSync(destPath);
    }

    console.error(
      `Error: Failed to download mr-nope binary for ${platformKey}.\n` +
        `  URL: ${url}\n` +
        `  Reason: ${error.message}\n\n` +
        `Possible causes:\n` +
        `  - No internet connection\n` +
        `  - The release v${version} may not exist yet\n` +
        `  - GitHub may be temporarily unavailable\n\n` +
        `You can manually download the binary from:\n` +
        `  https://github.com/${REPO}/releases`
    );
    process.exit(1);
  }
}

main();
