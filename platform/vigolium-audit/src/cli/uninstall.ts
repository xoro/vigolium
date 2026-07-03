import chalk from "chalk";
import { uninstallHarness } from "../engine/harness.js";

export async function uninstallCommand(
  platform: string,
  opts: { json?: boolean } = {},
): Promise<void> {
  if (platform !== "claude" && platform !== "codex" && platform !== "copilot") {
    const msg = `platform must be "claude", "codex", or "copilot"`;
    if (opts.json) process.stdout.write(JSON.stringify({ ok: false, error: msg }) + "\n");
    else console.error(chalk.red(`error: ${msg}`));
    process.exit(2);
  }
  // No harness/plugin is ever installed for copilot (headless-only support;
  // see run.ts's -i gate), so there's nothing for this command to remove.
  if (platform === "copilot") {
    if (opts.json) process.stdout.write(JSON.stringify({ ok: true, platform, removed: [] }) + "\n");
    else console.log(`[vigolium-audit] nothing to remove for copilot (no harness is ever installed)`);
    process.exit(0);
  }
  try {
    const { removed } = await uninstallHarness(platform);
    if (opts.json) {
      process.stdout.write(JSON.stringify({ ok: true, platform, removed }) + "\n");
    } else if (removed.length === 0) {
      console.log(`[vigolium-audit] nothing to remove for ${platform}`);
    } else {
      console.log(chalk.green(`[vigolium-audit] removed ${removed.length} item(s):`));
      for (const r of removed) console.log(`  - ${r}`);
    }
    process.exit(0);
  } catch (err) {
    if (opts.json) {
      process.stdout.write(JSON.stringify({ ok: false, error: (err as Error).message }) + "\n");
    } else {
      console.error(chalk.red(`[vigolium-audit] uninstall failed: ${(err as Error).message}`));
    }
    process.exit(1);
  }
}
