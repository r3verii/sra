# Skill — audit/file-boundary (v0)

This file defines the contract for the Claude skill that consumes a
single `PACKET-NNN.md` under
`.audit/04-packets-sensors/audit-file-boundary/` and produces a
structured investigation report.

The skill is invoked **once per packet**.

## Inputs

- **The single packet you are given** in this invocation. Do not
  search for, list, open, or investigate any other packet.
- **The target repository**, reachable from the current working
  directory.

## Tools allowed

- `Read`, `Grep`, `Glob` only.

## Tools FORBIDDEN

- `Write`, `Edit`, `NotebookEdit`, `Bash`, `PowerShell`, any network
  tool.

## What the skill does

File-boundary audit asks four core questions:

1. **Path traversal**: when external input becomes part of a filesystem
   path, is the resulting path contained inside an intended root?
2. **Archive extraction**: when extracting zip/tar archives, is each
   entry's destination path verified to stay inside the extraction
   root (zip-slip), and are archive bombs bounded (size, ratio)?
3. **Upload validation**: when accepting uploads, are size, type
   (extension AND content), and destination path bounded?
4. **Static-file serving**: what's the configured root? Are dotfiles,
   symlinks, and out-of-root paths blocked?

Hits are categorised by `expected_role`:

- `file_read_sink`, `file_write_sink`, `file_io_sink` — generic
  file I/O
- `path_construction` — `path.join`, `os.path.join`, `filepath.Join`,
  `Paths.get`, etc.
- `file_download_sink` — `res.sendFile`, `send_file`, `ServeFile`
- `static_serve` — `express.static`, `StaticFiles`, `http.FileServer`
- `upload_handler` — multer, busboy, multipart, MultipartFile
- `archive_extract` — zip/tar extraction APIs
- `lfi_sink` — PHP include/require (local file inclusion)

For each packet:

1. **Read the packet**. Group hits by `expected_role` and identify the
   files that contain them.

2. **For each `path_construction` hit**, find its callers (use Grep):
   - Is any of the arguments derived from an HTTP request, CLI flag,
     environment variable, or other external input?
   - If yes, is the resulting path then containment-checked (e.g.
     `path.startsWith(rootDir)`, `realpath` comparison, `..` rejection)?
   - **Findings to look for**: input concatenated into a path with no
     containment check before file I/O.

3. **For each `file_read_sink` / `file_write_sink` hit**, follow the
   path argument backward to its origin. Same questions as above.
   - **Findings to look for**: arbitrary file read / write controlled
     by request data.

4. **For each `archive_extract` hit**, open the file and read the
   surrounding extraction loop. Look for:
   - Does the code call `..` / symlink / absolute-path rejection
     before writing each extracted entry?
   - Is there a size limit per entry and per archive?
   - Is there a compression-ratio check (archive bomb)?
   - **Findings to look for**: extraction without containment check
     (zip-slip), missing size or ratio limits (archive bomb).

5. **For each `static_serve` hit**, find the registration call and
   read the configured options:
   - What is the `root` / `directory` argument?
   - Are dotfiles allowed by default? (Express: `dotfiles: 'allow'`?)
   - Does the framework follow symlinks?
   - Is there any user-controllable path component, or is it static?
   - **Findings to look for**: static serving of a directory broader
     than needed; symlink follow without check; dotfile access.

6. **For each `upload_handler` hit**, find the configuration:
   - What size limit is set?
   - What types are accepted (extension, MIME, magic bytes)?
   - Where does the file get stored?
   - Is the filename sanitised before becoming a path component?
   - **Findings to look for**: missing size limit, accept-all type
     filter, attacker-controllable destination filename.

7. **For each `lfi_sink` hit** (PHP): if a `require` / `include`
   argument is input-derived, that is almost always exploitable.
   - **Findings to look for**: any include with non-constant argument.

8. **Cross-check with tests**: glob for test files that exercise the
   boundary. If a test exercises path-traversal payloads
   (`%2e%2e%2f`, `..\\`, `..%2f`), the code is at least aware of the
   risk class.

9. **For each potential issue**:
   - Decide whether the sensor hit represents a real, reachable
     problem in this codebase.
   - Cite the **file:line** you verified.
   - State the smallest change that would close it.

10. **For each sensor hit you dismiss**:
    - Record why in one short sentence.

11. **For anything you could not determine** (cross-module path
    derivation, runtime configuration, deployment context), record
    it as a **limitation**.

## What the skill MUST NOT do

- Do not flag every file I/O. The job is to find INPUT-DERIVED
  unsafe path / size / type behaviour.
- Do not invent risks outside the packet's cluster.
- Do not extrapolate to other audit families (no input-validation
  schema concerns, no supply-chain, no memory-safety).
- Do not assume the framework's default config is what's running.
  Cite the actual options passed in this codebase.

## Output

Print the report to STDOUT, Markdown. No file writes.

Output structure:

    # PACKET-NNN — investigation report

    ## Summary
    <2-4 sentences>

    ## Confirmed issues (N)
    <For each: severity hint, file:line, input → sink chain, smallest fix>

    ## Dismissed sensor hits (M)
    <Bulleted list with one-sentence reason each>

    ## Limitations / what I could not determine (K)
    <Bulleted list with concrete sentences>

    ## Files read during investigation
    <Ranges + Grep / Glob queries>

## Failure modes the skill should report explicitly

- "All path-construction hits in this cluster operate on
  constant strings; no external input flows into the path."
- "Archive extraction uses `<library>` which enforces containment
  by default; the application code does not override this."
- "Static serving root is the project's `public/` directory; no
  symlinks present in this codebase; default config is reasonable."
- "Uploads are bounded to `<N>` MB and only `<types>` are accepted."
- "I could not determine the deployment-time `root` argument
  because it is set in a config file outside this cluster."

## Why this contract exists

File-boundary findings have a wide range — from "wrong static-file
serving root" (low) to "arbitrary path traversal in production"
(critical). The skill must distinguish: many `path.join` calls are
benign; the few that take external input without a containment
check are exploitable. The contract forces the skill to **read the
caller**, not just flag the sink.
