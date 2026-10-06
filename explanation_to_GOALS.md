# GOALS.md, explained as a story

## The house with one front door

Think of your computer as a house. om is the doorman at the front door.

Today the doorman decides by **where you stand**:

- Standing **inside the house** (localhost) or on the **private tunnel** (Tailscale)? Come in, see every room.
- Standing **on the street** (your Wi-Fi/LAN)? You may only enter the rooms marked "public".

This works, but it has a weakness: the doorman never asks *who you are*. Anyone who walks up the private tunnel sees every room. Anyone on the street sees the same lobby as everyone else. There is no way to say "Alice may see the photo room, Bob may not."

**The goal of GOALS.md:** make the doorman ask **who you are**, not where you stand.

---

## Four kinds of rooms

Every room (project/service) wears a sign saying the minimum it needs:

| Sign | Story version |
| :-- | :-- |
| **public** | The lobby. Anyone walks in. |
| **user** | A guest room. You must show your ID *and* be on the guest list. |
| **private** | A study. ID, guest list, *and* you must arrive in a trusted car (an enrolled device or your Tailscale device). |
| **admin** | The control room (it holds the keys to everything, like Portainer). Admins only, with a trusted car. |

If a sign is missing or misspelled, om treats the room as **private**. When in doubt, the door stays locked.

---

## How you prove who you are

- **Passkey** is your fingerprint or face on your phone or laptop. No password to steal; the secret never leaves your device.
- **Tailscale device** means "I know this device, I let it onto my private tunnel."
- **Device certificate (mTLS)** is a membership card installed on your device.
- **Token** is a key for programs (scripts, apps) that can't use a fingerprint.

The doorman checks these **on every single request**. Not just at the dashboard, but at every room's door. If the doorman's office (`om_auth`) is closed, the answer is **no**, never "let them through."

---

## The big picture, step by step

1. A visitor knocks.
2. The edge (Caddy, the outer door) removes any fake name tags the visitor wrote on themselves.
3. It asks `om_auth` (the guard with the guest list): "Who is this, and may they enter this room?"
4. `om_auth` looks at the proofs, finds the person, checks the guest list, and answers yes, "go log in", or no.
5. Only if yes does the request travel on, through the old internal router, to the room.

Old safeguards (separate networks, the secret token, the firewall) stay. The new guard is **one more layer**, not a replacement.

---

## Several front doors, never mixed up

The house gets one door per way in: **home, Tailscale, LAN, internet**. Each has its own number on the wall, so the doorman always knows which one you came through. This matters a lot: if you point an internet tunnel at the *home* door by mistake, strangers would walk into the private rooms. So `om doctor` checks for that mistake.

The internet door is the most careful: it never serves the private study or control room, even to people on the guest list. Those need Tailscale.

---

## Why one domain name?

A passkey is tied to a **web address**. A passkey made on `archlinux.local` will not work on `mymachine.ts.net`. That would make "works the same everywhere" a lie.

So the plan: rent one cheap domain (`om.example.com`, ~$10-15/year) and put every way in under it (`lan.om.example.com`, `ts.om.example.com`, ...). One passkey then works everywhere, and one free certificate covers everything. Without a domain, om still works as today, but remote login to `user`/`private` rooms is limited.

---

## Staying logged in, safely

You log in at one special page. Each project gets its own small "visitor pass" valid **only for that project's address**. So a hacked project can't steal your pass and use it at the others. Passes expire when idle, expire after a long time anyway, and can be revoked in one click. Dangerous actions (adding users, changing grants) ask for your fingerprint again.

---

## Getting people in

- **The first admin:** whoever has the keys to the actual machine, by running one command in the terminal. If every admin loses their passkey, the same command is the emergency way back in.
- **A new person:** the admin creates a one-time invite link that expires. The person opens it and their device makes the passkey. om stores only the public half (like a lock, never the key).
- **A lost phone:** the admin revokes it, and it stops working on the very next request. Then a new invite.

---

## What gets stored

One small file (SQLite) holding: users, passkeys, devices, who may enter which room, invites, sessions, tokens, and an **audit log** (who did what, when). It is kept inside the guard's own container, so nothing else can tamper with it.

---

## The honest limits

- Python's built-in tools can't check passkey signatures, so om needs a small piece of its own code for that (verify only, well tested).
- Signing device certificates needs a helper container.
- Some home routers block "public names pointing at private addresses". `om doctor` will detect it and print the fix.
- If you tunnel through Cloudflare, they see the traffic and device certificates can't work. So those rooms stay on Tailscale.

---

## The order of the work

0. Give each door its own number (nothing changes for you).
1. Add the guard and passkeys.
2. Add room signs and guest lists.
3. Add the domain, certificates, and the internet door.
4. Recognize Tailscale devices.
5. Device certificates (optional).
6. Tokens for programs; retire the old password login.

Each step works on its own and keeps everything that works today working.

---

## Four questions left for you

1. For `private` rooms over Tailscale: is the Tailscale device enough, or also a passkey?
2. On your own laptop, should "I'm at the keyboard" automatically mean admin?
3. Domain: free deSEC name, or your own domain on Cloudflare (DNS only)?
4. Is the device certificate step worth building, given passkeys + Tailscale?
