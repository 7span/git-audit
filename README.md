# Daily Computer Safety Check

A quick check that looks for harmful software on your work computer. It only reads. It never changes or deletes anything.

## How to run it

1. Open the right app:
   - **Mac or Linux:** open the **Terminal** app.
   - **Windows:** open **Git Bash**. It comes with [Git for Windows](https://git-scm.com/download/win). Do not use PowerShell or Command Prompt.
2. Paste this line, then press Enter:

```
curl -fsSL https://raw.githubusercontent.com/7span/git-audit/v1.0.0/supply-chain-scanner.sh -o /tmp/scan.sh && bash /tmp/scan.sh
```

3. Wait a few minutes. The result appears on the screen.

Your Mac may ask to allow Terminal to open some folders. Click **Allow**.

## What the result means

Look at the last lines.

| You see | What to do |
|---|---|
| **ALL CLEAR** | Nothing. You are done for today. |
| **FINDING(S)** | Do not upload or push any work. Do not delete any files. Send the result to your security lead. |
| An error or nothing happens | Run the line again. If it still fails, ask for help. |

## Good to know

- Works on Mac, Linux and Windows (in Git Bash).
- On Windows, the check on VS Code tasks needs [Python 3](https://www.python.org/downloads/). Without it, that test is skipped.
- If the git history test says **git log failed** for a project folder, git did not trust that folder, so its history was not checked. If the folder is yours, run `git config --global --add safe.directory "<folder>"`, then run the check again.
- It needs an internet connection.
- Run it once every day.

## What it checks

The check runs 33 tests (35 on Mac). It looks for:

- Signs that harmful software already ran on your computer.
- Harmful code hidden inside your project files.
- Harmful code hidden in invisible characters, or in fake font and image files.
- VS Code tasks that secretly run code when you open a project.
- Git commits with odd dates, which can be a sign that harmful code was slipped into old history.
- Known harmful npm packages and accounts.
- Hidden programs that start by themselves, and changes to your SSH keys and git settings.
- Connections to servers used by attackers.

Each test shows one of these marks:

| Mark | Meaning |
|---|---|
| ✅ | Clean |
| ⚠️ | Looks unusual. It may be harmless, so check it. |
| 🔴 | Harmful software found. Follow the **FINDING(S)** steps above. |
| 👀 | For your information only. Look for anything you don't recognise. |

## Reading the git history result

The **Git history** test lists commits where the code was written more than one day before it was added to the branch. It is for your information only (👀). It never turns the result into **FINDING(S)**.

Every git commit has two dates:

- **Author date:** when the code was written.
- **Committer date:** when the code was added to the branch.

Example:

```
👀 ~/projects/my-app — 12 commit(s) with author/committer date skew > 24h
   a1b2c3d4e5f6  2026-07-25T23:22:51+05:30 -> 2026-07-31T13:01:07+05:30  (133.6h)  Jane Doe: Add chat room API
```

| Part | Meaning |
|---|---|
| `a1b2c3d4e5f6` | The commit ID |
| `2026-07-25 23:22` | Author date: when Jane wrote the change |
| `2026-07-31 13:01` | Committer date: when it was added to the branch |
| `(133.6h)` | The gap between the two dates: about 5.5 days |
| `Jane Doe: Add chat room API` | Who wrote it, and the commit message |

The list shows up to 10 commits per project. "... and N more" means there are more.

**Is it a problem?** Usually not. A gap appears when someone rebases, cherry-picks or merges older work. A clear sign of this is many commits with exactly the same committer date and time. That means they were all added in one go.

Attackers sometimes give their commit an old date, so it looks like old, trusted code. Check a commit by hand if:

- You don't recognise the author.
- The message doesn't match the work on the project.
- One commit has a very large gap, such as months or years.
- It changes files like `tailwind.config.js`, `postcss.config.js`, `next.config.js`, font files or `.vscode/tasks.json`.

To see what a commit changed, run this with your project folder and the commit ID:

```
git -C ~/projects/my-app show --stat a1b2c3d4e5f6
```

If the commit looks harmful, follow the **FINDING(S)** steps above.

## Versions

The version number is shown at the top of the result.

| Version | What changed |
|---|---|
| 1.3.0 | Added 5 tests, based on [Operation-PolinRider](https://github.com/richkazz/Operation-PolinRider): hidden loader code, invisible characters, fake font and image files, VS Code tasks that run by themselves, and git commits with odd dates. Also checks more attacker server addresses. |
| 1.2.0 | Added checks for more harmful npm packages and accounts, startup programs, injected SSH keys and hidden install code. |
