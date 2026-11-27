import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const SCRIPT = readFileSync(
  join(__dirname, "../../scripts/scrub-security-leakage.sh"),
  "utf8",
);
const ACCOUNT = ["987654", "320198"].join("");
const DEVELOPER_PATH = ["", "Users", "scrub-fixture", "project"].join("/");

function runFixture(source: string, generated: boolean): ReturnType<typeof spawnSync> {
  const root = mkdtempSync(join(tmpdir(), "security-scrub-archive-"));
  try {
    mkdirSync(join(root, "scripts"), { recursive: true });
    writeFileSync(join(root, "scripts/scrub-security-leakage.sh"), SCRIPT);
    mkdirSync(join(root, "packages/source"), { recursive: true });
    writeFileSync(join(root, "packages/source/config.txt"), source);
    if (generated) {
      for (const directory of [
        "dist",
        "node_modules/dependency",
        "packages/nested/dist",
        "packages/nested/node_modules/dependency",
      ]) {
        mkdirSync(join(root, directory), { recursive: true });
        writeFileSync(
          join(root, directory, "generated.txt"),
          `${ACCOUNT}\n${DEVELOPER_PATH}\n`,
        );
      }
    }
    return spawnSync("bash", [join(root, "scripts/scrub-security-leakage.sh")], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        GIT_DIR: undefined,
        GIT_WORK_TREE: undefined,
        GIT_CEILING_DIRECTORIES: dirname(root),
        SCRUB_EXTRA_PATTERNS_FILE: join(root, ".fixture-empty-deny-list"),
      },
      timeout: 10_000,
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe("Security scrubber in a Git-free source archive", () => {
  it("prunes root and nested generated directories before testing file entries", () => {
    const result = runFixture("safe source\n", true);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("[OK]");
    expect(result.stderr).toBe("");
  });

  it("still rejects an AWS account ID in real nested source", () => {
    const result = runFixture(`${ACCOUNT}\n`, true);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain("Unexpected 12-digit AWS account IDs");
    expect(result.stdout).toContain(ACCOUNT);
  });

  it("still rejects a developer home path in real nested source", () => {
    const result = runFixture(`${DEVELOPER_PATH}\n`, true);
    expect(result.status).toBe(1);
    expect(result.stdout).toContain("packages/source/config.txt");
    expect(result.stdout).toContain("[LEAKAGE]");
  });
});
