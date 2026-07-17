# secrets

Store a named secret once, reference it by name everywhere. `secrets` manages a small file under `~/.mcpvessel` where a value lives keyed by a name you choose. A provider endpoint's key (its `key_ref`) and an agent's `SECRETS` entry both resolve against this store by name, so you type a token in once and never again. Values are read from stdin, never the command line, so they stay out of your shell history and the process table.

```
mcpvessel secrets set NAME
mcpvessel secrets ls
mcpvessel secrets rm NAME
```

`secrets` has no flags of its own. It is a group of three subcommands: `set` writes a value, `ls` lists the names, `rm` deletes one. Each loads the same store, and `set` and `rm` write it back.

## The store

Secrets live in a single JSON file, a flat map of name to value:

- **Path.** `~/.mcpvessel/secrets.json`. If `VESSEL_HOME` is set, the file is `$VESSEL_HOME/secrets.json` instead.
- **Permissions.** The file is written `0600` (owner read/write only) and its directory is created `0700`. Every `set` and `rm` rewrites the whole file at those permissions.
- **Missing file is an empty store.** The first `set` creates the directory and the file; `ls` and `rm` on a fresh machine see nothing rather than erroring.
- **Malformed file fails closed.** If the JSON does not parse, `Load` returns an error instead of silently treating the store as empty, so a corrupted file cannot make every secret quietly vanish. Fix or remove the file to recover.

The in-memory store redacts itself: its `String`, `GoString`, and `json.Marshal` forms all print `[redacted]`, so a value cannot leak through a log line or a stray marshal. Persistence writes the underlying map directly, which is the only path that ever serializes real values.

## set

```
mcpvessel secrets set NAME
```

Stores one value under `NAME`, read from stdin. Takes exactly one argument, the name.

**How the value is read.** `set` prints `Value: ` to stderr, then reads the value with the same reader `login` uses for passwords:

- **On a terminal**, typing is hidden. Characters are read without echo, so the value never appears on screen. You type it and press enter.
- **When stdin is not a terminal** (a pipe or a redirected file), `set` reads one line and strips the trailing newline (`\r\n` or `\n`). This is the scripting path: `mcpvessel secrets set NAME < key.txt` or `printf %s "$TOKEN" | mcpvessel secrets set NAME`.

After reading, `set` prints a newline to stderr (to close the prompt line) and, on success, `Stored NAME` to stdout. Because the prompt and the newline go to stderr, capturing stdout in a script yields only the confirmation.

**Empty is rejected.** If the value comes back empty (you pressed enter at the prompt, or piped in nothing), `set` fails with `secret "NAME" is empty` and writes nothing. This is deliberate: an empty secret would otherwise satisfy a required input and defer the failure to run time, so `set` refuses it up front.

**Overwrite is silent.** `Set` replaces any existing value under the same name with no prompt and no diff. Re-running `set` on a name is how you rotate a key.

Only after a non-empty read does `set` load the store, set the value, and save. A read error or an empty value leaves the store untouched.

## ls

```
mcpvessel secrets ls
```

Prints the stored names, one per line, sorted. Takes no arguments.

`ls` prints **names only, never values**. There is no flag to reveal a value, and the store's `Names` method returns the keys alone. An empty store prints nothing and exits zero. Use `ls` to see what you have stored before a run, or to confirm a `set` landed.

## rm

```
mcpvessel secrets rm NAME
```

Deletes the secret named `NAME`. Takes exactly one argument.

`rm` loads the store and removes the name. If no secret by that name exists, it fails with `no secret named "NAME"` and writes nothing, so a typo does not silently succeed. On a real removal it saves the store and prints `Removed NAME`. There is no confirmation prompt and no undo; the value is gone once the file is rewritten.

## How secrets are consumed

A stored secret does nothing on its own. It is pulled in by name at the moment an agent runs or a provider is called.

**`--secret NAME` on run, build, and import.** These commands resolve a named secret and inject it into the cage. The lookup checks **your environment first, then the store**: if `NAME` is exported in your shell it wins, otherwise the value comes from `secrets.json`. If neither has it, the command fails closed with a message telling you to store it first (`mcpvessel secrets set NAME`) or export it. The value reaches the agent through the runtime's secret channel, never the command line or an image layer. See [import](import.md#inputs-a-server-needs-to-start) and [run](run.md) for the flag in context.

**Provider keys.** When a reasoning agent runs, the LLM gateway reads each configured provider's `key_ref` from this store. A provider whose `key_ref` is missing stops the boot with `provider "..." needs secret "...": run 'mcpvessel secrets set ...'`. This is the link between `mcpvessel config provider set` (which records a `key_ref` name) and the actual key value you store here.

**Agent `SECRETS` entries.** A Vesselfile `SECRETS NAME` line names a secret the agent needs at run time. It resolves against the same store by the same name.

In every case the resolution is by name and fails closed when the name is absent, so a run never starts with a silently missing credential.

## Examples

```sh
# Store a provider key, typing hidden on a terminal.
mcpvessel secrets set openai_key
# Value: (typed, not shown)

# Store from a file, no prompt, for scripts and CI.
mcpvessel secrets set github_token < token.txt

# Pipe a value straight in without a trailing newline.
printf %s "$SLACK_TOKEN" | mcpvessel secrets set slack_token

# See what is stored (names only).
mcpvessel secrets ls

# Rotate a key by storing over it.
mcpvessel secrets set openai_key < new-key.txt

# Delete one you no longer need.
mcpvessel secrets rm slack_token
```

## Notes

- The prompt (`Value: `) and the closing newline go to stderr, so `mcpvessel secrets set NAME > /dev/null` still shows the prompt, and a script capturing stdout gets only `Stored NAME`.
- Piping in a file with a trailing newline is fine: `set` strips one trailing `\r\n` or `\n`. A value with meaningful internal newlines cannot be stored through the piped path, which reads a single line.
- `ls` sorts names, so its order does not reflect when you stored each one.
- There is no bulk import here. To load many secrets for one run without storing them, `run` and `import` accept `--secret-file` (`NAME=VALUE` per line); `secrets set` handles one named value at a time for the persistent store.
- Editing `secrets.json` by hand works (it is a plain name-to-value JSON map), but keep it `0600`; the commands rewrite it at that mode on every change.
- A value stored empty is impossible: `set` rejects it. A name that resolves to a stored secret always has a non-empty value.

## See also

- [import](import.md): `--secret` grants a stored secret to a wrapped server at introspection time.
- [run](run.md): `--secret` and `--secret-file` inject secrets into a run, resolved from your environment or this store.
- [login](login.md): reads passwords with the same hidden-input reader `secrets set` uses.
- [Give it a brain](../README.md#give-it-a-brain): storing each provider key before running a reasoning agent.
