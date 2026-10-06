# GOALS.md, explained simply

## The idea in one sentence

git keeps the history of what your project **is**; om runs what your project **uses**, and decides who may reach it, with one simple rule that never has to change.

## The one rule

```
someone knocks → through the door → om collects proofs → checks the room's rule → in or out
```

1. **The door.** There is only one way in: a private tunnel (WireGuard by default, or a VPN you already use). It doesn't answer anyone without a key, so to strangers your computer looks like a blank wall. Your own keyboard is a second, local door.
2. **Proofs.** When someone comes in, om notes what it knows for sure: *which device*, *whose device*, *did they show a fingerprint (passkey)*, *was it just now*, *is it someone at the keyboard*, *did they touch the admin key*.
3. **The room's rule.** Every service says which proofs it needs, in one line of its settings:
   `om.require: device,passkey,grant`. Handy shortcuts exist (*shared*, *user*, *private*), but they're just names for common combinations. A room that says nothing gets the strictest rule.
4. **Signed history.** Everything that changes what runs or who gets in is a git commit signed with your hardware key: your code, every update, every person and device you add. Nothing unsigned does anything.
5. **Laws nobody can switch off:**
   - If om isn't sure, the answer is no.
   - A room that can change things never talks to the internet.
   - Containers stay in their own box: no access to your computer, other projects, or the internet unless allowed.
   - Admin only at your keyboard, with your hardware key.
   - No secrets in settings; private keys never leave their device.

## Why it won't need rebuilding

Future ideas just plug in:
- **A different VPN?** A new kind of door.
- **A new way to log in?** A new kind of proof.
- **A new access combination?** A new line in a room's rule.

The rule itself stays the same, just as git's core has stayed the same while everything around it grew.

## Your keys

- **Device key:** in each phone or laptop, added by scanning a QR code at your keyboard.
- **Passkey:** your fingerprint or face.
- **Two admin hardware keys:** one you carry, one backup in a safe place, never next to the computer. They sign everything. Lose one, the other replaces it; lose both, you start fresh, and a thief never inherits anything.

## Updates

om never updates itself silently. It prepares new versions as a proposal, you look at what changes (`om diff`), sign it, and only then does it run. If it breaks, om goes back by itself.

## Moving over

The new door opens next to the old ones first. Every device you use today gets its key; `om doctor` shows anyone who would be locked out; only then are the old doors closed.

## What's left

Someone would need your enrolled device **and** your fingerprint, or your locked, encrypted computer **and** your hardware key. Everything else is closed, and `om doctor` keeps proving it.
