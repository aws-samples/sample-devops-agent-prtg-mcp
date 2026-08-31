# Diagrams

Rendered architecture diagrams used by the docs in the parent directory. Every diagram
is a pair: a [draw.io](https://www.drawio.com/) source (`<name>.drawio`) and the SVG
render (`<name>.svg`) committed beside it. Node icons are the official
[AWS Architecture Icons](https://aws.amazon.com/architecture/icons/), embedded in both
files so the source opens identically in draw.io with no shape library.

| Image | Used by | Shows |
|---|---|---|
| `architecture-end-to-end.svg` | [`../../README.md`](../../README.md), [`../architecture.md`](../architecture.md#the-loop) | **Both halves** - the full alarm → investigation → PRTG-query loop |
| `mcp-standard-nat.svg` | [`../../README.md`](../../README.md), [`../architecture.md`](../architecture.md#half-2---the-mcp-server) | `network.mode: nat` - NAT egress, SigV4, secret in this account |
| `mcp-fully-private.svg` | [`../deployment-matrix.md`](../deployment-matrix.md) Knob 1 | `network.mode: private` - no NAT, no IGW, interface endpoints |
| `mcp-cross-account-secret.svg` | Knob 3 | `secret.mode: external` - secret in a security account |
| `mcp-prtg-remote.svg` | Knob 4 | `prtg.reachability: remote` - PRTG across peering, TGW or VPN |
| `mcp-combined-multi-account.svg` | "Combinations outside the eighteen" | Four accounts plus the customer network |
| `fanout-role-assumption.svg` | Knob 5 | `targeting.mode: fanout` - the direction of cross-account role assumption |

A rendered diagram of the alarm pipeline on its own is still outstanding; the
end-to-end diagram covers it as one half of the loop.

---

## Before you add a diagram: the gate will not check the labels

> **`scripts/check-sanitisation.sh` has no pattern for bare IP addresses.** A real
> customer address in a tracked file passes the gate today.

Diagrams earn their SVG-plus-source convention, because they are where sensitive
values hide best:

- **A binary render is opaque to every text-based check.** A hostname or address baked
  into a PNG is invisible to CI, to review diffs, and to any secret scanner a consumer
  runs over the repo. The renders here are SVG precisely so every label is plain text
  that those checks can read - keep it that way.
- **The source and the render can drift.** The committed `.drawio` and the `.svg` are
  two files; a label fixed in one can survive in the other. Edit the source, mirror
  the render, and review them as a pair.

So, when adding or regenerating a diagram:

1. **Read every label in the rendered image by eye.** Node labels, sublabels, legends,
   the title, and anything in a footnote. Placeholders only: `10.x.x.x`, `203.0.113.7`
   ([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)), `111122223333`, `vpc-0123…`.
2. **Check the source too, separately**, and scrub it before committing it.
3. **Check the crop.** An export sized to a region rather than the full page can leave
   sensitive text just outside the frame - present in the source, absent from the
   image, and therefore easy to believe was never there.

## Regenerating

Edit `<name>.drawio` in draw.io, then mirror the change into `<name>.svg` - either
re-export (File → Export as → SVG) or edit the SVG directly; it is hand-readable.
Commit the pair together.

To eyeball a render locally without opening draw.io, any browser shows the SVG; for a
screenshot at exact size:

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless --disable-gpu --screenshot=out.png --window-size=<svg width>,<svg height> \
  --hide-scrollbars file:///absolute/path/to/diagram.svg
```

Keep filenames tied to the **knob value** the diagram illustrates, not to a scenario
number. The scenario numbering is a mapping this repo provides for people arriving
with a number in hand
([`../deployment-matrix.md`](../deployment-matrix.md#mapping-the-conventional-scenarios));
it is not the primary model.
