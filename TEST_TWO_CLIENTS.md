# Alice and Bob in two terminals

Install and build the project using [README.md](README.md). The current `chat`
uses separate encrypted profiles, remote pairing and the upstream ratchet. The
terminals can run on different computers; passwords do not have to match.
This is an experimental application without an independent audit.

## Start a conversation

1. In Bob's terminal, open the project directory and run `./chat Bob`. Choose his
   own password. Wait for Tor to connect, then enter `/address`.
2. Copy the entire generated command beginning `/add Bob PMS2:`. This is a one-time
   invitation for this contact. Give it to Alice through a trusted channel.
3. In Alice's terminal, run `./chat Alice` and choose her own password. Paste the
   entire `/add Bob PMS2:…` command and press Enter. If you have only the token,
   use `/add PMS2:…`; a complete JSON export can also follow `/add`.
4. Bob enters `/accept`.
5. Both enter `/verify`. Compare the entire fingerprint in person or through
   another independently authenticated channel. Only if it matches, both enter
   `/yes`. If it differs, enter `/no` and check the invitation's origin.
6. Alice types `Hello Bob!` and presses Enter. Bob sees it and can reply directly.
   Quotation marks, apostrophes and Unicode text are supported.

You do not need to copy internal contact IDs or put the fingerprint into a command.
The interface explains which acceptance or verification step is still missing.
On restart, a single existing contact is selected automatically. Reusing a consumed
invitation is unnecessary: the established conversation remains stored.

**Every command starts with `/`.** Text without a slash is a message to the selected
recipient. Invitation markers and long Base32 fragments are blocked from messages
and direct you to `/add`. Unknown slash commands are never sent as messages.

| Command | Purpose |
| --- | --- |
| `/help` | Show the pairing, verification and messaging steps. |
| `/address` | Create a fresh one-time invitation. |
| `/add NAME INVITATION` | Add a separate contact. |
| `/requests` | Show incoming connection requests. |
| `/accept [NAME]` | Accept a request. |
| `/verify [NAME]` | Display the complete contact fingerprint. |
| `/yes`, `/no` | Confirm or decline the currently displayed verification/deletion prompt. |
| `/chat`, `/contacts` | Show the numbered saved-contact list. |
| `/chat NUMBER`, `/chat NAME` | Select the recipient shown in the prompt. |
| `/send NAME TEXT` | Send explicitly to a named contact. |
| `/history [NAME]` | Show conversation history. |
| `/del [NAME]` | Request contact deletion, followed by `/yes` to confirm. |
| `/status` | Show the network and selected-contact state. |
| `/quit` | Exit safely. |

Use a displayed number or explicit ID if names are ambiguous. Menu numbers refer
to the last displayed list; a new incoming request cannot silently renumber it.
The scripting form `/verify ID --confirm FINGERPRINT` is also available.

`server_accepted` means the router accepted ciphertext. `recipient_received` means
the recipient's application authenticated and processed it. Neither means a human
read the message.

## Offline delivery

1. Bob enters `/quit` and exits completely.
2. Alice sends a message and waits for server acceptance.
3. Bob runs `./chat Bob` again and unlocks his profile. The queued message arrives.

Alice must be online to receive Bob's encrypted receipt; otherwise it waits in
her queue. Delivery depends on router availability, quotas and retention.

## Add Charlie and select the recipient

1. Charlie runs `./chat Charlie` and enters `/address`.
2. Alice pastes the entire generated `/add Charlie PMS2:…` command into her chat.
3. Charlie enters `/accept`. Alice and Charlie both enter `/verify`, compare the
   fingerprint independently, then enter `/yes` only if it matches.
4. Alice enters `/chat` and sees Bob and Charlie in a numbered list.
5. `/chat 2` selects the second contact; `/chat Bob` selects Bob by name.

The prompt shows the selected recipient, for example `Alice → Charlie>`. Each
contact has independent keys, queues and conversation history.

## Delete a contact and start over

In Alice's terminal enter `/del Charlie`, then `/yes`. In Charlie's terminal enter
`/del Alice`, then `/yes`. `/no` cancels. You can also use `/del NUMBER` from the
last displayed menu or `/del` for the selected contact.

Deletion retires that contact's local history, conversation/prekeys, pending sends
and delivery/replay records, stops its receiver and deletes your own incoming SMP
queue. Other contacts and the profile remain intact. Deleting the selected contact
does not silently select a different recipient.

Charlie then generates a fresh `/address`. Alice imports the newly generated
`/add Charlie …` command. Repeat acceptance, fingerprint comparison and `/yes`.
New contact keys and queues are created, with an empty history for this conversation.

`/contacts --all` also lists unused invitations; remove one with `/del NUMBER`.
If remote deletion fails, local conversation state is already retired. A visible
pending-deletion record retains encrypted queue credentials for completing DEL.
Retry `/del NAME` or the displayed ID, including after restart; already confirmed
retirement does not require a second ordinary deletion confirmation.

`/del NAME --local` followed by a fresh `/yes` explicitly discards the remaining
local credentials without contacting the server. The remote queue remains and
this client loses the credentials needed to delete it. Network failure never
selects this alternative automatically. AUTH is reported as unconfirmed, not as
proof of server deletion. Neither option erases peer copies, old backups or
guarantees physical erasure on SSDs or in Python memory.

## What the invitation contains

Each `/address` creates a new queue and fresh contact identity, address, classical
prekeys and ML-KEM key. The router assigns random queue IDs. The invitation carries
the router address/pin, sender queue ID, public keys, cryptographic suite, expiry
and signature. It contains no vault password, private keys or receiver credentials.

Its compressed Base32 representation fits alphanumeric QR capacity up to 40-L;
QR rendering is not implemented. It expires after seven days and is for one contact.
Do not publish it as an unrestricted public address: its first holder can claim
the connection. A self-signature authenticates the invitation's consistency,
not the human identity of its sender.

Remote pairing means both devices generate their own private keys and exchange
only public invitations. They need no shared password or same-computer setup.
Fingerprints bind the resulting connection to the person you independently verify.

## Networking and remaining limits

Ordinary launches use **TOR**. Each profile can run its own installed Tor process;
the single-line progress bar waits for 100% before SMP connections begin. Failure
does not create a direct connection. An older DIRECT profile switches to TOR on
normal login, but earlier direct connections cannot be retroactively hidden.

For an existing proxy use `./chat Alice --tor-proxy-port 9050`. That explicit proxy
setting persists and is never silently replaced. `--network DIRECT` is an explicit
diagnostic option exposing your IP to the router. Restart an old running process
with `/quit` before using updated code.

Profiles live in `~/.local/share/private-messenger/secure-profiles/`. The old
same-computer static-Box demo is separate under `terminal-demo/` and `./chat-legacy`;
it does not gain PFS/PCS/PQ protection retroactively.

The bundled default-router creation password is public server configuration,
not a profile secret; chat does not fetch the operator's website at runtime.
For another router use `/servers URI --basic-auth-file PATH` as documented in
[server selection](SERVER_SELECTION.md).

Initial establishment uses X25519 + ML-KEM-1024, followed by Double/Triple Ratchet
and ongoing SPQR ML-KEM-768. Initial ML-KEM-768 compatibility is not provided.
Tor does not defeat global correlation, and a server's country alone guarantees
no privacy. See [SECURITY.md](SECURITY.md) for the precise PFS/PCS, endpoint,
storage, authentication and release-integrity limits.
