import { pack } from "tar-stream";
import { createGzip } from "node:zlib";
import { Readable } from "node:stream";

export function fixtureArchive(files) {
  const tar = pack();
  const output = tar.pipe(createGzip());
  for (const { path, content } of files) tar.entry({ name: "fixture-repository/" + path }, content);
  tar.finalize();
  return new Response(Readable.toWeb(output));
}
