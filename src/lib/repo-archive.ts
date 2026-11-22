import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream } from "node:stream/web";
import { createGunzip } from "node:zlib";
import { extract } from "tar-stream";

const ARCHIVE_COMPRESSED_BYTES = 600_000_000;
const ARCHIVE_EXPANDED_BYTES = 750_000_000;
export const REPO_SOURCE_BYTES = 112_000_000;
export const REPO_FILE_BYTES = 360_000;
export const REPO_LOCKFILE_BYTES = 5_000_000;

export class ArchiveLimitError extends Error {}

function byteLimit(limit: number) {
  let bytes = 0;
  return new Transform({
    transform(chunk: Buffer, _, done) {
      bytes += chunk.byteLength;
      if (bytes > limit) done(new ArchiveLimitError("Repository archive exceeded its size limit."));
      else done(null, chunk);
    },
  });
}

/** Parse GitHub's tar.gz stream without extracting files or following links. */
export async function readRepoArchive(
  body: ReadableStream<Uint8Array>,
  selected: ReadonlyMap<string, number>,
  signal: AbortSignal,
) {
  const parser = extract();
  const files: Array<{ path: string; content: string; bytes: number }> = [];
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const seen = new Set<string>();
  let retainedBytes = 0;
  parser.on("entry", (header, entry, next) => {
    const separator = header.name.indexOf("/");
    const path = separator > 0 ? header.name.slice(separator + 1) : "";
    const size = header.size ?? 0;
    const perFileLimit = selected.get(path);
    const collect = header.type === "file" && perFileLimit !== undefined && size <= perFileLimit
      && size >= 0 && retainedBytes + size <= REPO_SOURCE_BYTES && !seen.has(path);

    const buffer = collect ? Buffer.allocUnsafe(size) : null;
    let written = 0;
    entry.on("error", next);
    entry.on("data", (chunk) => {
      if (!buffer) return;
      if (!(chunk instanceof Uint8Array)) {
        parser.destroy(new Error("Invalid archive byte stream."));
        return;
      }
      if (written + chunk.byteLength > size) {
        parser.destroy(new Error("Invalid archive entry length."));
        return;
      }
      buffer.set(chunk, written);
      written += chunk.byteLength;
    });
    entry.on("end", () => {
      if (buffer && written === size && !buffer.includes(0)) {
        try {
          const content = decoder.decode(buffer);
          if (!content.startsWith("version https://git-lfs.github.com/spec/v1\n")) {
            files.push({ path, content, bytes: size });
            seen.add(path);
            retainedBytes += size;
          }
        } catch { /* Invalid UTF-8 is not an eligible text file. */ }
      }
      next();
    });
  });

  let endedEarly = false;
  try {
    await pipeline(
      Readable.fromWeb(body), byteLimit(ARCHIVE_COMPRESSED_BYTES), createGunzip(),
      byteLimit(ARCHIVE_EXPANDED_BYTES), parser, { signal },
    );
  } catch (error) {
    if (!(error instanceof ArchiveLimitError) && !signal.aborted) throw error;
    endedEarly = true;
  }
  return { files, endedEarly };
}
