#!/usr/bin/env node
"use strict";

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const SUPPORTED_PLATFORMS = {
  "linux-x64": "mr-nope-linux-x64",
  "darwin-x64": "mr-nope-darwin-x64",
  "darwin-arm64": "mr-nope-darwin-arm64",
  "win32-x64": "mr-nope-win32-x64.exe",
};

function getPlatformKey() {
  const platform = process.platform;
  const arch = process.arch;
  return `${platform}-${arch}`;
}

function getBinaryName(platformKey) {
  return SUPPORTED_PLATFORMS[platformKey] || null;
}

function getBinaryPath() {
  const platformKey = getPlatformKey();
  const binaryName = getBinaryName(platformKey);

  if (!binaryName) {
    const supported = Object.keys(SUPPORTED_PLATFORMS).join(", ");
    console.error(
      `Error: Unsupported platform "${platformKey}".\n` +
        `mr-nope supports the following platforms: ${supported}\n` +
        `Please visit https://github.com/mr-nope/mr-nope/releases for manual installation.`
    );
    process.exit(1);
  }

  return path.join(__dirname, binaryName);
}

function main() {
  const binaryPath = getBinaryPath();

  if (!fs.existsSync(binaryPath)) {
    console.error(
      `Error: mr-nope binary not found at "${binaryPath}".\n` +
        `The binary may not have been downloaded during installation.\n` +
        `Try reinstalling with: npm install @mr-nope/cli\n` +
        `Or run the postinstall script manually: node install.js`
    );
    process.exit(1);
  }

  const args = process.argv.slice(2);

  try {
    const result = execFileSync(binaryPath, args, {
      stdio: "inherit",
      env: process.env,
    });
  } catch (error) {
    if (error.status !== null) {
      process.exit(error.status);
    }
    console.error(`Error: Failed to execute mr-nope binary: ${error.message}`);
    process.exit(1);
  }
}

main();
