# Contributing to ExamShield

## Branch naming

One branch per module, named after the module and owner:

```
module1-joylin
module2-nagaraj
module3-divya
module4-divya
module5-elisha
module6-elisha
```

## Workflow

1. Pull latest `main`:
   ```bash
   git checkout main
   git pull origin main
   ```

2. Create/switch to your module branch:
   ```bash
   git checkout -b module1-joylin
   ```

3. Implement your module's functions (replace `raise NotImplementedError` with real code). Keep function signatures unchanged unless discussed with the team — other modules import them directly.

4. Write at least one test per public function in `tests/test_module<N>.py`.

5. Run tests before committing:
   ```bash
   pytest tests/
   ```

6. Commit with a clear message:
   ```bash
   git add module1_board_prep/
   git commit -m "feat(module1): implement AES-GCM encrypt/decrypt"
   ```

7. Push and open a PR into `main`:
   ```bash
   git push origin module1-joylin
   ```
   Fill in the PR template — what was implemented, how it was tested.

8. Address review comments, then squash-merge once approved.

9. Delete your branch after merge.

## Commit message convention

```
feat(moduleN): short description       # new functionality
fix(moduleN): short description        # bug fix
test(moduleN): short description       # tests only
docs: short description                # README/docs only
chore: short description               # scaffolding, config, deps
```

## Rules

- Don't change another member's module files without discussing first — open an issue or ping them.
- Don't commit real private keys, certs, or secrets — `certs/` and `data/` contents are gitignored for this reason.
- Keep function signatures matching the architecture doc so `demo_flow.py` integration doesn't break.
- If you need to change a signature, flag it in the team channel before merging.
