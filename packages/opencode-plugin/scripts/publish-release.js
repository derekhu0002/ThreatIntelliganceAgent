import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(__dirname, "..");
const packageJsonPath = path.join(packageRoot, "package.json");
const packageLockPath = path.join(packageRoot, "package-lock.json");

function usage() {
  console.error([
    "Usage:",
    "  npm run release -- <patch|minor|major|x.y.z> [--tag latest] [--otp 123456] [--dry-run]",
    "",
    "Examples:",
    "  npm run release -- patch",
    "  npm run release -- 0.2.0 --tag beta",
    "  npm run release:dry-run -- minor",
  ].join("\n"));
}

function run(command, args, options = {}) {
  let executable = command;
  let commandArgs = args;
  if (process.platform === "win32" && command === "npm") {
    executable = process.env.ComSpec || "cmd.exe";
    commandArgs = ["/d", "/s", "/c", ["npm", ...args].map(quoteWindowsCmdArg).join(" ")];
  }

  console.log(`> ${[command, ...args].join(" ")}`);
  const result = spawnSync(executable, commandArgs, {
    cwd: packageRoot,
    stdio: "inherit",
    ...options,
  });

  if (result.error) {
    console.error(result.error.message);
    process.exit(1);
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function quoteWindowsCmdArg(arg) {
  if (/^[a-zA-Z0-9_./:=@-]+$/.test(arg)) {
    return arg;
  }
  return `"${arg.replace(/(\\*)"/g, '$1$1\\"').replace(/\\+$/g, "$&$&")}"`;
}

function parseArgs(argv) {
  const options = {
    bump: null,
    dryRun: false,
    tag: "latest",
    access: "public",
    otp: null,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--dry-run") {
      options.dryRun = true;
    } else if (arg === "--tag") {
      options.tag = argv[++i];
    } else if (arg === "--access") {
      options.access = argv[++i];
    } else if (arg === "--otp") {
      options.otp = argv[++i];
    } else if (arg.startsWith("--")) {
      throw new Error(`Unknown argument: ${arg}`);
    } else if (!options.bump) {
      options.bump = arg;
    } else {
      throw new Error(`Unexpected argument: ${arg}`);
    }
  }

  if (!options.bump) {
    throw new Error("Missing version bump argument.");
  }
  if (!options.tag) {
    throw new Error("--tag requires a value.");
  }
  if (!options.access) {
    throw new Error("--access requires a value.");
  }

  return options;
}

function parseVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(version);
  if (!match) {
    throw new Error(`Invalid semver version: ${version}`);
  }
  return match.slice(1, 4).map(Number);
}

function nextVersion(current, bump) {
  if (/^\d+\.\d+\.\d+(?:[-+].*)?$/.test(bump)) {
    return bump;
  }

  const [major, minor, patch] = parseVersion(current);
  if (bump === "major") {
    return `${major + 1}.0.0`;
  }
  if (bump === "minor") {
    return `${major}.${minor + 1}.0`;
  }
  if (bump === "patch") {
    return `${major}.${minor}.${patch + 1}`;
  }

  throw new Error(`Invalid bump value: ${bump}`);
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function updateVersions(version) {
  const packageJson = readJson(packageJsonPath);
  packageJson.version = version;
  writeJson(packageJsonPath, packageJson);

  if (existsSync(packageLockPath)) {
    const packageLock = readJson(packageLockPath);
    packageLock.version = version;
    if (packageLock.packages?.[""]) {
      packageLock.packages[""].version = version;
    }
    writeJson(packageLockPath, packageLock);
  }
}

function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    usage();
    process.exit(1);
  }

  const packageJson = readJson(packageJsonPath);
  const version = nextVersion(packageJson.version, options.bump);
  const originalPackageJson = readFileSync(packageJsonPath, "utf8");
  const originalPackageLock = existsSync(packageLockPath) ? readFileSync(packageLockPath, "utf8") : null;
  console.log(`Releasing ${packageJson.name} ${packageJson.version} -> ${version}`);

  try {
    updateVersions(version);

    run(process.execPath, ["scripts/verify-plugin.js"]);
    run(process.execPath, ["scripts/sync-assets.js"]);
    run("npm", ["pack", "--dry-run"]);

    const publishArgs = ["publish", "--access", options.access, "--tag", options.tag];
    if (options.otp) {
      publishArgs.push("--otp", options.otp);
    }
    if (options.dryRun) {
      publishArgs.push("--dry-run");
    }

    run("npm", publishArgs);
  } finally {
    run(process.execPath, ["scripts/clean-assets.js"]);
    if (options.dryRun) {
      writeFileSync(packageJsonPath, originalPackageJson, "utf8");
      if (originalPackageLock !== null) {
        writeFileSync(packageLockPath, originalPackageLock, "utf8");
      }
    }
  }

  if (options.dryRun) {
    console.log(`Dry run complete for ${packageJson.name}@${version}.`);
  } else {
    console.log(`Published ${packageJson.name}@${version}.`);
  }
}

main();
