# GOALS.md, explained as a story

## What om is

git keeps the history of what your project **is**. om runs what your project **uses**: its services, their addresses, and who may reach them. Like git, it stays small and doesn't care what's inside: no special cases, just a few simple ideas.

For access, there are only four ideas: **a door, keys, signs, and a diary**.

---

## 1. The door

The house has **one door: a WireGuard tunnel**. It doesn't answer anyone without a key, so to a stranger the house looks like a blank wall. At home, in a café or on mobile data, everyone uses the same door and the same rules.

You choose what the door is made of, like git lets you choose ssh or https:
- **om's own WireGuard** (default): free, nothing to sign up for, om holds every key.
- **A VPN you already use** (Tailscale, Headscale, NetBird, ZeroTier…): om just uses its tunnel, after checking that every device on it is truly identified. Even if that VPN company slipped in a strange device, it could only see the look-only household rooms, because everything else needs a fingerprint.

Whatever the door, everything behind it works exactly the same.

There's also the computer's own keyboard (the console). Sitting there is a *place*, not a pass: it never lets anyone in on its own.

## 2. The keys

- **Device key:** every phone or laptop has its own, proving which device is knocking.
- **Passkey:** your fingerprint or face, proving it's really you.
- **Two admin hardware keys:** one you carry, one backup in a separate safe place. They are never kept next to the computer. **The same key signs everything:** your code, approved updates and every change to who may enter.

No passwords, no invite links, nothing to steal from an email.

## 3. The signs (written in the project, like code)

Every room carries signs that say what it needs:

- **Who may enter:**
  - *shared*: anyone in the household with a device.
  - *user*: device, fingerprint, and your name on the list.
  - *private*: the same, with a fingerprint that lives on that one device and was checked just now.
- **Can it change things?** File managers, editors and terminals can.
- **May it talk to the internet?** No, unless allowed.

Two rules can never be bent: **a room that can change things is never open to everyone, and never talks to the internet.** A room with no sign gets the strictest one.

## 4. The diary (like git's history)

Who is in the household, which devices they own, and which rooms they may enter is written in a **diary**, and the diary simply **is a git repository**. Every page is a commit signed with your admin hardware key, so you can read it with the same tools as your code.

- Nobody can forge a page, not even someone who takes over the computer.
- Tearing out pages is noticed, because each new page is also announced to your phone.
- Losing one admin key: the other one fixes it. Losing both: the diary starts over, and everyone joins again. A thief never inherits anything.

---

## om works like git, everywhere

git remembers every version of your code. om does the same for **what is running**:

- **The recipe** (which services, which settings) lives in git, like any code.
- **A shopping list with exact barcodes** (the lock) says precisely which version of every program runs, so nobody can swap a program behind your back.
- **A diary of deployments** says what ran on this computer and when.
- **The guest diary** (above) says who may enter.

Running something means "check out this signed version": the same version always gives the same result on any computer. Going back is just checking out an older version (your data stays as it is).

The commands feel like git: `om status` (is what runs what you approved?), `om diff` (what would change?), `om log` (what ran, when?), `om checkout` (go back), `om fsck` (is everything intact?).

**Updates never install themselves.** om looks for new versions and prepares them as a proposal, like a pull request. You look at what changes, approve and sign it, and only then does it run. If the new version fails its health check, om goes back to the previous one by itself.

---

## How a visit works

1. A device comes through the door; the doorman sees its key.
2. He throws away any fake name tags.
3. The guard reads the diary: "This device is Alice's. Has she shown her fingerprint? Is she on this room's list?"
4. Yes → in. No → refused. If the guard can't tell → refused.

Changes to the diary happen only at the console, by typing a command (like `om user add`) and touching the admin key. There's no admin web page at all, so there's nothing on the web to attack.

## Collaborators

Collaborators never touch your computer. They work in git, and their changes only run after you review and sign them.

## Moving over without locking anyone out

The new door opens next to the old ones first. Every device that uses om today gets its key, and `om doctor` lists anyone who would be locked out. Only when that list is empty are the old doors closed.

## Fix first

Before building the door, om fixes today's weak spots: a strict browser policy for the dashboard, a "look-only" key to the containers for the dashboard, refusing dangerous container settings, deploying only signed commits, and no internet for containers by default. om also moves into its own user account on your everyday computer, so a bad website can't reach it.

## Promises `om doctor` checks

- Every door except the tunnel is closed, and the tunnel stays silent to strangers.
- No room can be reached without the guard saying yes.
- Fake name tags never get through.
- A removed device is refused on its next knock.
- The control room is never reachable through the tunnel.
- Containers can't reach your computer, each other, or the internet (unless allowed).
- The diary is intact from its first page to its last.

## Every worry, and its answer

| Worry | Answer |
| :-- | :-- |
| A stranger | The door doesn't answer; there's nothing to find. |
| A stolen, unlocked phone | Only look-only household rooms. |
| A hacked phone | Only its owner's rooms while logged in; never the control room; writers can't send anything out. |
| A collaborator | Git only, your signature only. |
| Someone misusing a room that can change things | Never open to everyone; you choose each person. |
| A bad program in a container | Boxed in: no internet, no other rooms, no access to your computer. |
| A bad website in your browser | om lives in a separate user account. |
| Someone who takes over the computer | Can't forge the diary; tearing pages shows up on your phone. |
| A stolen computer | Encrypted; keys elsewhere; the keyboard alone is never admin. |
| Lost admin keys | Backup key, or a clean restart, never a takeover. |
| A bug somewhere | Fail closed, tested, auto-updated; layered, so one bug alone opens nothing. |
