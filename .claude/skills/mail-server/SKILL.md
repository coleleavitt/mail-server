```markdown
# mail-server Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill provides guidance for contributing to the `mail-server` Rust codebase. It covers coding conventions, commit and workflow patterns, and testing practices observed in the repository. The goal is to help new and existing contributors maintain consistency and quality when developing or fixing features in the project.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `mailHandler.rs`, `smtpClient.rs`

### Import Style
- Use **relative imports** within modules.
  - Example:
    ```rust
    mod utils;
    use crate::utils::parse_email;
    ```

### Export Style
- Use **named exports** for functions, structs, and modules.
  - Example:
    ```rust
    pub fn send_mail(...) { ... }
    pub struct MailServer { ... }
    ```

### Commit Patterns
- Commit messages are **freeform** but often start with prefixes like `mta` or `s3`.
- Example:
  ```
  mta: fix envelope parsing for multi-recipient messages
  s3: add support for multipart upload
  ```

## Workflows

### Bugfix or Feature Change with Changelog
**Trigger:** When fixing a bug or adding a small feature.  
**Command:** `/bugfix`

1. Edit one or more source files to implement the fix or feature.
   - Example:
     ```rust
     // crates/mailer/src/mailHandler.rs
     pub fn handle_incoming_mail(...) { ... }
     ```
2. Update `CHANGELOG.md` to document the change.
   - Example:
     ```markdown
     ## [Unreleased]
     - Fix: Corrected envelope parsing for multi-recipient messages
     ```

### Bugfix or Feature Change with Tests
**Trigger:** When fixing a bug or adding a feature and ensuring it is tested.  
**Command:** `/bugfix-with-test`

1. Edit one or more source files to implement the fix or feature.
2. Update or add relevant test files.
   - Example:
     ```rust
     // tests/src/mailHandler.test.rs
     #[test]
     fn test_multi_recipient_envelope() { ... }
     ```
3. Update `CHANGELOG.md` to document the change.

## Testing Patterns

- Test files follow the pattern `*.test.ts` (note: this may be a misconfiguration, as Rust typically uses `.rs`).
- Tests are typically placed under `tests/src/`.
- Example test file:
  ```rust
  // tests/src/mailHandler.test.rs
  #[test]
  fn test_mail_parsing() {
      // test implementation
  }
  ```
- Testing framework is **unknown**; use standard Rust testing conventions unless otherwise specified.

## Commands
| Command            | Purpose                                      |
|--------------------|----------------------------------------------|
| /bugfix            | Start a bugfix or small feature workflow     |
| /bugfix-with-test  | Bugfix/feature workflow with tests included  |
```
