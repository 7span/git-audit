# Daily Computer Safety Check

A quick check that looks for harmful software on your work computer. It only reads. It never changes or deletes anything.

## How to run it

1. Open the **Terminal** app.
2. Paste this line, then press Enter:

```
curl -fsSL https://raw.githubusercontent.com/7span/git-audit/main/supply-chain-scanner.sh -o /tmp/scan.sh && bash /tmp/scan.sh
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

- Works on Mac and Linux.
- It needs an internet connection.
- Run it once every day.
