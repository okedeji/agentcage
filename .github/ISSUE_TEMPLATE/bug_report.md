---
name: Bug report
about: Something does not work the way it should
title: ""
labels: bug
assignees: ""
---

**What happened**
A clear description of the bug.

**What you expected**
What you thought would happen instead.

**Reproduction**
The commands, and the Vesselfile or bundle if relevant. A minimal case that
still shows the bug is worth a lot.

```sh
# commands here
```

**Environment**
- mcpvessel version (`mcpvessel --version`):
- OS and arch (e.g. macOS 15 arm64, Ubuntu 24.04 amd64):
- Runtime: bundled Lima VM (macOS) or host containerd (Linux):

**Logs**
Relevant output. `mcpvessel logs <run>` and the run id from `mcpvessel ps` help
for runtime issues. Redact any secrets first.
