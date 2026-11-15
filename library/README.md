# Component library and scanner rules

- `components.json`: the blocks of the left rail. Each component has `base` EMB3D property IDs
  (PIDs) and questions; each answer adds PIDs. Custom blocks and imported libraries use the same
  format.
- `yocto-rules.json`: what `emb-tm scan` looks for in Yocto build outputs and how it answers
  each question.

## Scanner rules

Each entry in `components` is a candidate block: a `when` condition, a `type` from the component
library, a `name` (`${VAR}` and `${A|B}` take build variables), an optional `version` package regex,
and per question an ordered list of `{ "if": condition, "value": answer, "review": "note" }`. The
first entry whose condition is true wins; an entry without `if` is the fallback. `flows` connect
blocks by rule id.

| Condition | True when |
|---|---|
| `{ "var": "X", "set": true }`, `"eq"`, `"word"`, `"re"` | build variable X is set, equals, contains the word, matches |
| `{ "pkg": "regex" }` | an installed package (manifest) or SBOM component name matches |
| `{ "kconfig": "CONFIG_X", "eq": "y" }`, `"re"` | kernel `.config` value (`n` when not set) |
| `{ "uboot": "CONFIG_X", "eq": "y" }` | bootloader `.config` value |
| `{ "file": "/etc/a\|/etc/b.d/*", "re": "^…" }` | a rootfs file matches (multiline regex) |
| `{ "exists": "/path/*" }` | a rootfs path exists |
| `{ "any": [...] }`, `{ "all": [...] }`, `{ "not": … }`, `{ "always": true }` | combinations |

A condition whose input was not given is neither true nor false: it never selects an answer, and
the answer finally chosen is flagged for review, naming the missing input. Regular expressions are
[Rust's](https://docs.rs/regex/latest/regex/#syntax) (no look-around). After changing the rules,
run `make test` and regenerate the scan example (`examples/yocto-scan/`) with `emb-tm scan`.
