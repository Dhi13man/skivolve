# Security Policy

Skivolve executes untrusted generated code and integrates with authenticated coding harnesses. Security reports are handled privately so a fix can be prepared before details become public.

## Supported Versions

| Version   | Supported |
| --------- | --------- |
| `0.7.x`   | Yes       |
| `<=0.6.x` | No        |

Only the latest patch release receives security fixes. A security fix may change a provider protocol lock, release authority, schema, corpus, or result contract when preserving the old behavior would remain unsafe.

## Reporting A Vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Dhi13man/skivolve/security/advisories/new). If GitHub private reporting is unavailable, email `dhiman.seal@hotmail.com` with the subject `Skivolve security report`.

Include the affected version or commit, threat model, reproduction steps, impact, and any suggested mitigation. Remove real credentials, private holdout content, access tokens, personal data, and unnecessary exploit payloads. You should receive acknowledgement within seven days and a status update within fourteen days. Timelines for remediation and coordinated disclosure depend on severity and affected release surfaces.

Do not open a public issue for a suspected vulnerability until the maintainer confirms disclosure is safe.

## Security Boundary

The project defends against untrusted prompts, fixture contents, candidate code, model responses, comparator output, path traversal, symlink substitution, source drift, accidental credential exposure, interrupted spend accounting, and ordinary provider-process escape attempts within its documented Linux isolation model. The Claude boundary assumes the digest-attested provider executable is trusted; its code-owned settings deny the controller's ephemeral OAuth file to built-in file tools and sandboxed Bash. Sandboxed commands deny network domains, and generation fails before dispatch unless the Linux helper that denies new Unix sockets is present, executable, digest-attested, and explicitly bound into the sandbox.

The project does not claim protection against a compromised kernel, malicious root, hostile same-UID processes outside the transient isolation unit, forged release JSON when the executing checkout is already compromised, provider-side account compromise, or reviewers who collude or leak private holdout content. Run sensitive holdouts on a dedicated trusted host with minimal credentials and no unrelated same-UID workloads. Set `kernel.dmesg_restrict=1` on evaluation hosts: sandbox units deny `syslog(2)` and `/dev/kmsg`, but a permissive host setting would still let candidate code read kernel logs through the nested `/proc/kmsg`.

## Credential Handling

Never commit `.env` files, provider credentials, diagnostic manifests containing host paths, live calibration evidence, private holdout plans, consumption records, or result directories. The Claude and Codex adapters validate narrowly scoped runtime bindings and deny direct credential access to generated code. Claude generation requires Claude Code 2.1.187 or newer and fails closed when its Bash sandbox or Unix-socket seccomp dependencies are unavailable. Changes to those bindings require security review.

## Disclosure And Credit

Security advisories will credit reporters who request attribution. The project will not publish private details or personal information without consent.
