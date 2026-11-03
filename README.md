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
- If the result says **COULD NOT SCAN** for a project folder, git did not trust that folder. The result shows the line to run to allow it. Run that line only if the folder is yours, then run the check again.
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

## Versions

The version number is shown at the top of the result.

| Version | What changed |
|---|---|
| 1.3.0 | Added 5 tests, based on [Operation-PolinRider](https://github.com/richkazz/Operation-PolinRider): hidden loader code, invisible characters, fake font and image files, VS Code tasks that run by themselves, and git commits with odd dates. Also checks more attacker server addresses. |
| 1.2.0 | Added checks for more harmful npm packages and accounts, startup programs, injected SSH keys and hidden install code. |
