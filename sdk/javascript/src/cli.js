#!/usr/bin/env node
import { OutisCloudClient } from './client.js';
import { applyPlan, planDesiredState } from './reconcile.js';
import { readFile } from 'node:fs/promises';

function usage() {
  console.error('Usage: outiscloud <operationId> [--params JSON] [--query JSON] [--body JSON]');
  console.error('       outiscloud reconcile <desired-state.json> [--yes] [--prune]');
  process.exitCode = 2;
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === '--help' || command === '-h') {
    usage();
    process.exitCode = 0;
    return;
  }
  const client = new OutisCloudClient({
    baseUrl: process.env.OUTISCLOUD_API_URL,
    token: process.env.OUTISCLOUD_API_TOKEN,
  });
  if (command === 'reconcile') {
    const [file, ...flags] = args;
    if (!file || flags.some((flag) => !['--yes', '--prune'].includes(flag))) return usage();
    const desired = JSON.parse(await readFile(file, 'utf8'));
    desired.prune = flags.includes('--prune');
    const plan = await planDesiredState(client, desired);
    const result = flags.includes('--yes')
      ? await applyPlan(client, plan, { dryRun: false, allowDestructive: flags.includes('--prune') })
      : { dryRun: true, actions: plan };
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  if (!command) return usage();
  const values = {};
  for (let i = 0; i < args.length; i += 1) {
    const key = args[i];
    if (!['--params', '--query', '--body'].includes(key) || !args[i + 1]) return usage();
    try {
      values[key.slice(2)] = JSON.parse(args[++i]);
    } catch (error) {
      throw new TypeError(`invalid JSON for ${key}: ${error.message}`);
    }
  }
}

main().catch((error) => {
  console.error(JSON.stringify({ error: error.message, code: error.code, status: error.status }));
  process.exitCode = 1;
});
