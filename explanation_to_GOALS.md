# GOALS.md, explained as a story

## What om is for

om is your **workshop**: it runs your projects and services and lets you and a few trusted people (family, friends you work with) use them. Strangers walking in to look around isn't its job. When a project is ready for the world, you ship it somewhere built for that.

So the new plan asks a simple question: if only trusted people should ever get in, why have more than one door?

---

## Today: a house with open doors

Right now the doorman decides by **where you stand**:

- Inside the house (localhost) or in the Tailscale tunnel: you see every room.
- On the Wi-Fi: you see the "public" rooms.

The web doors (ports 80/443) are open on the home network, and the house even shouts its name (`archlinux.local`) so everyone knows it's there.

---

## The new house: one hidden door

- **One door only: a WireGuard tunnel.** The house has no other open door. The tunnel door is special: it **doesn't answer** anyone who doesn't already have a key. Someone scanning for doors sees a blank wall.
- **Your key is your identity.** Each phone or laptop gets its own key, belonging to one person. With the key, the house knows exactly *who* is coming, and the key can't be faked.
- **Same door everywhere.** At home, in a café or on mobile data, you use the same tunnel and see the same rooms.
- **The house stays quiet.** It stops announcing its name, doesn't answer pings, and changes its network "face" (MAC address).

---

## The rooms

| Room sign | Who gets in |
| :-- | :-- |
| **shared** | Anyone in the household with a key (e.g. movies, search). |
| **user** | Guest list **and** a fingerprint/face check (passkey), so a stolen, unlocked phone isn't enough. |
| **private** | Same, but the passkey must live on that one device (not synced to a cloud account) and be checked fresh. |
| **admin** | Only by sitting at the computer itself and touching the admin hardware key. |

If a room has no sign, it's treated as **private**. People only ever see the rooms they may enter; the others aren't even listed.

---

## The control room is only reachable in person

Adding people, adding devices, changing guest lists, and Portainer (the master control panel) can **only** be done at the computer's own keyboard, with a touch on the admin's hardware key, which you carry with you (never left next to the computer). There's no way to do it over the tunnel, so there's no "admin phone" that could be hacked or found.

To add a family member's phone, you open the console, it shows a **QR code**, and the phone scans it. That's it: no links sent around, no passwords.

Lose a phone? Remove it at the console, and it's locked out instantly.

---

## The guards behind the door

1. A visitor comes through the tunnel; the doorman (Caddy) sees which key they used.
2. He removes any fake name tags.
3. He asks the guard (`om_auth`): "This key belongs to Alice. May she enter *this* room?"
4. Yes → in (for user/private rooms, after a fingerprint check). No → refused.
5. Inside, the old internal router still makes sure rooms can't sneak into each other.

---

## The address (free)

Fingerprint checks (passkeys) need a proper web address with a certificate. You get a **free name from deSEC**. Its only public record points to an address that **exists only inside the tunnel**, so it tells nobody where your house is. The certificate is free too (Let's Encrypt) and renews itself.

---

## Fixing today's weak spots first

Before any of the new door work:
- A strict browser policy for the dashboard, so project names can't hide scripts.
- The dashboard only gets a "look" key to the containers; Portainer is off until you need it, and only at the console.
- om refuses dangerous container settings and unsigned updates.
- Containers can't reach the internet unless you allow it.
- om moves into its **own locked apartment** (a separate user account), so a bad website in your everyday browser can't reach it.

---

## Protecting the one thing left: the computer itself

- Disk encryption with a PIN: a stolen computer is a brick.
- Secure Boot and a firmware password.
- Two admin hardware keys: one you carry, one backup in a separate safe place. Neither is ever kept with the computer.
- Sitting at the keyboard alone is never enough to become admin: recovery needs one of the two keys. If both are lost, the only option is wiping all users and devices and starting over, so a thief who takes the computer gets an empty system.
- Every important event is copied to your phone instantly, so nobody can quietly erase it.

---

## The order of the work

First **check** that the tunnel works the same on every system and that the doorman sees the real key behind each visitor.

- **A1–A6:** fix today's weak spots (above).
1. Move om into its own user account.
2. Build the tunnel door; close the web doors on the home network; QR enrollment.
3. Add the guard: guest lists, room signs, the console-only control room, alerts.
4. Free address + certificate + fingerprint checks for user and private rooms.
5. Make the house quiet, and add all the automatic checks to `om doctor`.

---

## Where that leaves us

To get in, someone needs your **enrolled device**, and for anything beyond shared rooms **your fingerprint too**. To change anything, they need to be **physically at your locked, encrypted computer with one of your hardware keys**, which are never kept with it. Nothing else is open. What remains is an unknown bug in the software itself, which updates keep short-lived.
