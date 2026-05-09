# macOS support removal

## What we built

agentcage used Apple Virtualization.framework to run Firecracker on macOS. The architecture:

```
macOS (M3+, macOS 15+)
  └── Apple VZ Linux VM (orchestrator + all services)
        └── Firecracker via nested KVM (cage microVMs)
```

The macOS binary (`agentcage-darwin-arm64`) booted an Apple VZ Linux VM with nested virtualization enabled. Inside that VM, the orchestrator ran Firecracker using `/dev/kvm` to create cage microVMs. This required:

- A custom VM kernel (6.12) with KVM, virtio, and VirtioFS
- A VM rootfs (Alpine Linux) with an init script for VirtioFS mounting
- Asset downloading with SHA-256 checksum verification
- macOS code signing with the `com.apple.security.virtualization` entitlement
- TCP proxying from macOS to the VM for gRPC and PostgreSQL

## Why it didn't work

Apple Virtualization.framework's nested virtualization does not expose VHE (Virtualization Host Extensions) to the guest CPU. The Linux kernel inside the Apple VZ VM boots at EL2 but sees no VHE support in `ID_AA64MMFR1_EL1`, so it drops to EL1 and runs KVM in nVHE mode. The `kvm-arm.mode=nested` boot parameter is rejected because `is_kernel_in_hyp_mode()` returns false after the kernel drops from EL2.

In nVHE mode, KVM cannot provide the EL2 emulation that nested guests need. Firecracker can create VMs (`/dev/kvm` ioctls succeed, `InstanceStart` returns 204), but the guest kernel never executes. VCPUs start but produce zero output, zero boot markers, and zero vsock connections.

This was confirmed with both our custom kernel and Firecracker's official CI kernel (`vmlinux-6.1.155` from `s3://spec.ccfc.min/firecracker-ci/v1.14/aarch64/`). Neither produced any guest output.

## What we tried

1. **Serial console**: `console=ttyS0` with `CONFIG_SERIAL_8250=y` and `CONFIG_SERIAL_8250_CONSOLE=y` — zero output
2. **Earlycon**: `earlycon=uart,mmio,0x40002000` and `earlycon=ns16550a,mmio32,0x40002000` — zero output
3. **ARM64 kernel configs**: Added `CONFIG_SERIAL_OF_PLATFORM=y`, `CONFIG_SERIAL_EARLYCON=y`, `CONFIG_ARM_GIC_V3=y`, `CONFIG_ARM_PSCI_FW=y`, `CONFIG_IRQCHIP=y` — kernel didn't boot
4. **Boot args**: Removed `reboot=k` (ARM64 has no keyboard controller), added `console=hvc0` fallback — no change
5. **Persistent boot marker**: cage-init writes `/cage-boot.log` to the ext4 rootfs — file never created, confirming cage-init never ran
6. **Firecracker trace logging**: `--log-path` with `--level Trace` — VMM logs showed successful boot sequence but zero guest activity
7. **KVM nested mode**: `kvm-arm.mode=nested` in VM boot args — rejected by kernel (`WARNING: ... early_kvm_mode_cfg`, `Malformed early option 'kvm-arm.mode'`)
8. **dmesg diagnostics**: Confirmed `kvm [1]: Hyp nVHE mode initialized successfully` — KVM running in non-VHE mode

## Why we removed it

The macOS code added ~1,700 lines across 13 files, a CGO dependency (`github.com/Code-Hex/vz/v3`), two CI jobs (darwin build + VM asset build), and three build scripts. None of it produced a working cage. Maintaining dead code paths in a security-critical tool is a liability.

## Developing on macOS

The agentcage binary builds on macOS without CGO:

```bash
go build ./cmd/agentcage/
```

CLI commands that talk to a remote orchestrator work from any platform:

```bash
agentcage connect <linux-host>:9090
agentcage run --target example.com --agent discovery
agentcage logs cage <id>
agentcage assessments list
```

Only `agentcage init` and `agentcage stop` require Linux with `/dev/kvm`.
