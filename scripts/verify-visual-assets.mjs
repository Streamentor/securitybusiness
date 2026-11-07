import assert from "node:assert/strict";
import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  productAssets,
  guideCoverAssets,
} from "../src/components/visuals/assets.ts";
import { guides } from "../src/lib/guides.ts";

// Offline asset contract: missing files, incorrect intrinsic dimensions and
// oversize exports must fail before a broken image or layout shift ships.
function verify(src, dimensions, budget) {
  assert.match(src, /^\/images\/[a-z0-9/-]+\.webp$/);
  const file = fileURLToPath(new URL(`../public${src}`, import.meta.url));
  assert.ok(statSync(file).size < budget, `${src}: byte budget exceeded`);
  const bytes = readFileSync(file);
  assert.equal(bytes.toString("ascii", 0, 4), "RIFF");
  assert.equal(bytes.toString("ascii", 8, 12), "WEBP");
  const format = bytes.toString("ascii", 12, 16);
  let width, height;
  if (format === "VP8X") {
    width = bytes.readUIntLE(24, 3) + 1;
    height = bytes.readUIntLE(27, 3) + 1;
  } else if (format === "VP8 ") {
    width = bytes.readUInt16LE(26) & 0x3fff;
    height = bytes.readUInt16LE(28) & 0x3fff;
  } else if (format === "VP8L") {
    const bits = bytes.readUInt32LE(21);
    width = (bits & 0x3fff) + 1;
    height = ((bits >>> 14) & 0x3fff) + 1;
  } else assert.fail(`${src}: unsupported WebP header`);
  assert.deepEqual(
    { width, height },
    dimensions,
    `${src}: intrinsic size mismatch`,
  );
}

for (const asset of Object.values(productAssets)) {
  assert.ok(asset.alt.length > 30 && asset.caption.length > 20);
  verify(asset.src, { width: asset.width, height: asset.height }, 120_000);
  if (asset.mobile)
    verify(
      asset.mobile.src,
      { width: asset.mobile.width, height: asset.mobile.height },
      120_000,
    );
}
assert.equal(Object.keys(productAssets).length, 7);
for (const guide of guides) {
  if (!guide.cover) continue;
  assert.ok(
    guideCoverAssets[guide.cover],
    `${guide.slug}: missing cover metadata`,
  );
  verify(guide.cover, guideCoverAssets[guide.cover], 90_000);
}
verify(
  "/images/art/vibe-coding-building.webp",
  { width: 1200, height: 1200 },
  140_000,
);
console.log(
  "verify-visual-assets: all product crops, covers, dimensions and byte budgets pass",
);
