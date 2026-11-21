## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `ruff check` is clean
- [ ] Tests pass: `cd tests && PYTHONWARNINGS=error::EncodingWarning python3 -X warn_default_encoding -m unittest discover -s . -p 'test_*.py'`
- [ ] New behaviour has a test; docs and `CHANGELOG.md` (Unreleased) are updated in the same change
- [ ] Works on Linux, macOS and Windows, or says where it cannot (CONTRIBUTING.md)
- [ ] Commits are signed
