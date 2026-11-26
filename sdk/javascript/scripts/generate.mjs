import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const source = path.join(root, 'crates/control_api/openapi-paths.json');
const output = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/generated.js');
const document = JSON.parse(await readFile(source, 'utf8'));
const operations = [];
for (const [route, methods] of Object.entries(document.paths)) {
  for (const [method, operation] of Object.entries(methods)) {
    operations.push({
      id: operation.operationId,
      method: method.toUpperCase(),
      path: route,
      hasBody: Boolean(operation.requestBody),
    });
  }
}
operations.sort((a, b) => a.id.localeCompare(b.id));
await writeFile(output, `// Generated from crates/control_api/openapi-paths.json by scripts/generate.mjs.\nexport const operations = ${JSON.stringify(operations, null, 2)};\n`);
console.log(`generated ${operations.length} API operations`);
