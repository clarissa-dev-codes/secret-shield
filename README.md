# SecretShield

**Real-time secret detection and automated `.env` remediation for traditional developers and AI-assisted ("vibe") coders.**

---

## The Problem
With the rise of AI-assisted coding workflows, developers frequently paste API keys (`sk-proj-...`, `AKIA...`, `ghp_...`) directly into source files or forget to add `.env` files to `.gitignore`. Once committed, those credentials remain exposed in Git history even after the file is deleted.

## System Architecture
SecretShield uses a **shared-core monorepo architecture** to avoid duplicating detection logic across platforms:

* **`/core-engine` (Rust):** High-speed static analysis library combining compiled Regex rulesets, Shannon entropy scoring for high-randomness strings, and `libgit2` commit history traversal.
* **`/cli-wrapper` (Rust):** Standalone, zero-dependency CLI binary (`secret-shield`) that outputs standardized JSON diagnostics for editor integrations.
* **`/vscode-extension` (TypeScript):** Lightweight VS Code extension that invokes the native CLI binary on file save and renders inline squiggly diagnostics and quick-fix code actions.
* **`/vs-extension` (C# / VSIX):** Visual Studio extension integrating the scanning engine directly into the native Error List and editor adornments.
* **`/desktop-app` (Tauri v2 + React + TypeScript):** Cross-platform desktop dashboard for full-repository audits, Git history secret scrubbing, one-click `.env` refactoring, and license key management.

---

## Development Roadmap & Build Log

### Phase 1: Core Detection Engine & CLI (In Progress)
- [ ] Implement regex pattern matcher for major cloud & AI providers (OpenAI, AWS, GitHub, Stripe)
- [ ] Build Shannon entropy analyzer to catch custom/unrecognized high-entropy tokens
- [ ] Add `.gitignore` validation to alert when `.env` files are left untracked
- [ ] Compile cross-platform CLI binaries (Windows, macOS, Linux) with JSON output

### Phase 2: IDE Extensions (VS Code & Visual Studio)
- [ ] Build VS Code extension with `onDidSaveTextDocument` hooks and `DiagnosticCollection` markers
- [ ] Build Visual Studio (C# VSIX) extension wired to the native Error List
- [ ] Implement custom URI protocol (`secretshield://`) for one-click handoff to the Desktop App

### Phase 3: Cross-Platform Desktop App & Monetization
- [ ] Build Tauri v2 + React audit dashboard with repository health scoring
- [ ] Implement `git2` deep commit history scanner and automated redaction engine
- [ ] Integrate Lemon Squeezy license activation with OS Keychain offline grace caching

### Phase 4: CI/CD, Code Signing & Release
- [ ] Configure GitHub Actions matrix builds for automated multi-OS binary compilation
- [ ] Publish free extensions to the VS Code Marketplace and Visual Studio Marketplace
- [ ] Package and sign desktop installers (`.msi` / `.dmg`)

---

## Screenshots & Demos
*(Coming soon — Phase 1 CLI benchmark and Phase 2 VS Code inline warning previews will be posted here.)*
