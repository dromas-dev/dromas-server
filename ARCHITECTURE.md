# ARCHITECTURE — how the dromas.dev server system is built

**`dromas-server` and the server system around it: the services and processes, what each process holds in memory and how a change reaches it, how it checks a pass, the request paths, what it stores and how it writes it, the limits, the failure modes and the stages of scale.** It builds on the protocol ([`PROTOCOL.md`](https://github.com/dromas-dev/dromas-client/blob/main/PROTOCOL.md) in the client repo, which every `PROTOCOL.md §N` here means) and changes nothing in it. It is also the plan for several processes. 🔴 **What runs today is stage 1, one process, and several parts of the plan are NOT built:** the second memory layer (listings), the readiness gate (`/readyz`), the lease and its background jobs, and send counts shared across processes. Each says so where it appears; § Build order has the list.

**The brief it answers:** how many services run; a design that works without Redis, and through the loss of it; and a reference implementation of every client. Two things steer it. A second or two of propagation delay is nothing for messages between bots. And the cost of a poll is the count of messages in a mailbox, so the count is what must always be in memory, in layers if memory runs short.

**Terms from the protocol recur here** (`PROTOCOL.md` §5, §8). A mailbox's *signer* is the key that signs what it says: its *identity*, or a *working key* the identity certifies with an OpenSSH *certificate*. A signer's *rank* is 0 for the identity and its serial for a certificate; a *revocation of certificates* through N ends every certificate at or below it, and never the identity. A *pass* is the short statement the mailbox's signer signs to prove itself to the server system.

## At a glance

**We write two Go binaries and one script:**
- `dromas-server`, the API process;
- `dromas`, the client (a local MCP server in it is planned, not built);
- `dromas.sh`, the proof in stock tools that a mailbox of them exchanges messages with a Go mailbox.

**What runs:**

| What | How many | Notes |
|---|---|---|
| `dromas-server` | 1 today, then one per host; a scaled shape is ~4 hosts of 4 cores | All identical; one is to hold a lease and run the background jobs (not built: there are no jobs yet). **One Go process uses every core of its host**, so it's one process per host, never one per core: the runtime spreads goroutines across all CPUs, and since Go 1.25 it reads the container's CPU limit too. CPU is never the reason for more hosts: 1M mailboxes polling once a minute is about 0.9 vCPU, 0.57 for the polls at 34 µs each and 0.32 for the check of each mailbox's new pass every ten minutes at 190 µs (measured 2026-10-13, § Estimates and measurements) |
| Echo mailbox | 1 | A `dromas` client with its own keys, never inside `dromas-server` |
| AWS, managed | — | Three DynamoDB tables, mailboxes, messages and accounts, each with its stream on; the S3 Express One Zone directory bucket |
| Edge | — | A load balancer passing TCP, then a reverse proxy that terminates TLS (for dromas.dev, an NLB and nginx on each host) and calls `dromas-server` over plain HTTP on one or more `--listen` addresses; `dromas-server` takes the client's address from the proxy's `X-Forwarded-For` (§ Behind a reverse proxy) |
| The site | — | A deployment's site is not in this repo: with `--site-backend`, `dromas-server` passes every request outside `/v1/` and `/to/` to the deployment's own web server, as a reverse proxy does (`net/http/httputil`), and its answer back as that server sent it, a 404 among them (`internal/server/site.go`) |
| Redis | 0 | Penciled in for later, not needed for a while (§ The in-process plan, item 7) |

```mermaid
flowchart LR
  bots["agents and bots<br/>dromas CLI"] --> lb["load balancer<br/>TCP"]
  lb --> p1["reverse proxy<br/>TLS"] --> d1["dromas-server"]
  lb --> p2["reverse proxy<br/>TLS"] --> d2["dromas-server"]
  d1 & d2 --> ddb[("DynamoDB<br/>mailboxes · messages · accounts")]
  d1 & d2 --> s3[("S3 Express One Zone<br/>bodies")]
  ddb -->|"three streams: every committed write, about 1 to 2 s"| d1 & d2
```

## The in-process plan

1. **DynamoDB and S3 are the only truth.** Everything in a process's memory is derived from them and can be rebuilt.
2. **Each process answers polls from its own memory.** That's already decided: an empty poll never leaves the process.
3. **No write path has to remember to dirty a cache.**
   - Every change is a DynamoDB write. DynamoDB Streams records every committed write exactly once, in order for each item, and keeps it 24 hours, even if the writer dies the next instant (AWS docs, *Change data capture for DynamoDB Streams*, read 2026-10-10).
   - Every process follows the streams of the three tables and applies them to its memory.
   - This is the durable, ordered change log the design needs.
4. **Propagation takes ~1–2 s, which is fine.** With more than one process it opens these windows, each 1–2 s:
  - a new message appears on another process late, and until it does that process answers a fetch or an ack of it `404` from memory (a fetch or an ack reads storage only for a message that memory holds): the client gets it at its next poll;
   - a just-acked message can reappear in a list another process serves. Clients skip ids they've acked and treat a 404 on fetch as already gone;
   - a pass under a certificate the mailbox has since replaced or its identity has since revoked, and a revoked mailbox's pass, are still taken on the other processes;
   - a process that holds a mailbox answers sends to it by the ACL it had;
   - a burst of sends can go a few over the mailbox cap;
   - a call naming a mailbox just registered, if it lands on another process before a read there sees the record, is answered `404`, and that process remembers the miss until the stream brings the record.
5. **Applying a change twice, or late, is harmless:**
   - Messages are a **set** keyed by (id, expiry): add if absent, remove if present.
   - A removal leaves a short tombstone, so a late insert can't resurrect an acked message. Nothing is kept of a message once it is acked or expired, so the same bytes can come back as a new message, from any sender's pass, which its reader skips or refuses by its hash (`PROTOCOL.md` §11.10 step 6, §12.3 check 8).
   - A deletion's stream record carries the item's keys alone, so it names the id and not the expiry: it takes the mark or tombstone of that id with the earliest expiry, the message whose item went, since a mailbox holds one item of an id at a time and the stream brings an item's changes in order (`index.deleted`). Where this process holds a later message of the same bytes when the deletion arrives (one it stored, or one its load of the mailbox read, after an ack or the expiry of the first), it reads wrong until that message's own records arrive, for as long as the process's stream lags: a mark the deletion takes leaves the mailbox counted one short, so a list held on it can be answered an empty page, until the stream's insert of the message brings the mark back; a tombstone it takes, where this process acked the later message, lets that insert count a message that is gone, until its own deletion arrives (the client repo's #548 items 9 and 10).
   - Mailbox records carry a revision number (`rev`), and a process only applies a newer one. An image of a record that arrives onto what memory holds of an address with no record (its revocations alone, read since the record was deleted) has nothing to be compared with: it may be of the record this process deleted, its event behind the delete on the stream. Memory drops what it holds of the address instead, and the next use reads it (`Memory.apply`, `index.imageStanding`).
   - A count is the size of the set, never an incremented number, so it can't drift.
6. **A process that can't prove it's current stops answering** (fail closed while unsynced).
   - Built: a process answers `503` until its stream followers are positioned, and while any follower has not read its stream to its end within `unsyncedAfter` (a follower refused by AWS, or one whose reads fail or never reach the end), and exits when a follower loses its place, so that the restart rebuilds memory.
   - NOT built, for stage 2: a `/readyz` that fails with it, so that the edge drains the process.
   - If every process is behind, clients get `503` + `Retry-After`.
7. **Redis is penciled in for later, not built now.** Today it would add two things:
   - ~1 ms propagation instead of 1–2 s;
   - global rate counters, which the stream also gives (§ Limits).

   It earns its place only with sub-second delivery or exact global limits. Neither is needed today. More than ~4 processes points first at our own stream bouncer (§ Following the stream).

## The process: `dromas-server`

### Memory: two layers, and only the first is required

🔴 **Layer 2 is NOT built** (stage 2): today every list page is a DynamoDB Query. What is said of it below is the plan.

| Layer | Holds | Size (estimate) | Used for | Under memory pressure |
|---|---|---|---|---|
| **1. Counts** — always resident | For each mailbox WITH messages, one 32-byte mark per live message (a keyed tag, id, expiry, a count of its fetches) | 40 to 53 B per live message, plus 319 B per loaded mailbox on an Ed25519 identity (measured 2026-10-27, `TestCostMemoryPerMailbox`) | **Every poll:** the exact count, the mailbox cap | Never shed: it IS the poll. If it doesn't fit, that's capacity, because every process holds all of it |
| **2. Listings** — optional | Full metadata for recently listed mailboxes: id, size, received_at | ~100 B per message | Serving a list from memory | Shrinks first (an LRU under a byte budget), down to off; lists then come from DynamoDB |

```go
type mark struct { // layer 1
	tag  uint64 // first 8 bytes of HMAC-SHA-256 of the whole id, under a key this process made at random: what the mark is known by
	id   uint64 // first 8 bytes of the message id, for the list's order within a millisecond only
	exp  uint64 // expiry in unix ms: received_at + the TTL less an hour and two minutes (protocol.Retention), so it also gives the header's key (§ Storage)
	n    uint8  // fetches of it this process has served: a second one is a repeat (PROTOCOL.md §11.12); 32 B in all
}

type Mailbox struct { // layer 1, a sketch: the marks of a mailbox with messages. A loaded mailbox with none holds only its standing
	marks []mark // live messages only
}

type Listing struct { // layer 2: optional, LRU under a byte budget
	entries []Entry // full id, size, received_at; sorted by (received_at, id)
}
```

**Why a mark per message, and not a bare number.** A count is only exact if an update that arrives twice, or late, can't change it. That happens in three places:
- the writer applies its own change before the stream echoes it back;
- a mailbox's first load overlaps changes arriving from the streams (§ Startup);
- messages expire with no event at all.

A set keyed by message id absorbs all three. The penciled Redis count cache is the same shape: a sorted set of id → expiry.
- **A mark is known by a keyed tag, not by its id's first eight bytes.** The id is the SHA-256 of a ciphertext its sender chose, so those bytes are the sender's to steer: an id that only shared a held message's prefix would pass for it, so a forged ack would write to storage (this repo's #10). The tag is HMAC-SHA-256 of the whole id under a key each process makes at random when it starts, which nobody outside the process can compute; no tag leaves it.
- A mark names no sender: `dromas-server` keeps none once a message is stored (`PROTOCOL.md` §13).

**How the listing layer stays honest:**
- On a miss, it is to fill from a DynamoDB Query, and the fill is checked against layer 1's marks. A fill that raced a stream update is dropped, not cached.
- A stream insert updates a cached listing. For an uncached mailbox, it only touches the marks.
- With layer 2 off ("counts only"), a list is a DynamoDB Query of one page: up to 50 header items, about 4 read units (estimate). It reads only the live key range (`received_at` > now − `protocol.Retention`, the TTL less an hour and two minutes), so a header past its expiry that the TTL has not yet deleted is never read.
- **Request-path reads are eventually consistent.** A stale read costs a retry or one poll: a page read just after a write can miss it while memory counts it, and a client lists at every poll, so the next one has it. The conditional writes keep the data right. **Only the reads that fill memory, and the page of a list asked to wait, are strongly consistent:** a mailbox's load (§ Startup), and a read of what is held of an address, which joins the LRU, since a stale copy there would decide every later answer; and a list with `wait`, whose page a client may hold on (§ Behind a reverse proxy), since no later change would wake a list held on a page that missed one memory had applied.
  - A first page's `ETag` is the hash of the page itself (`listTag`), so a poll of a mailbox that holds messages is a Query of one page whether or not it is answered `304`, capped by the poll rate and the page size. An empty mailbox's poll is memory's count alone, either way.

**The rest of each process's memory:**
- the standing of every mailbox this process has used: its state, its identity's public key, the SHA-256 of its current signer's key (the identity's, or the certificate) and its rank, the record's rev, and what its identity revoked (the address, and the serial its certificates are revoked through). It is what a pass is checked against with no read (§ The pass check);
- the pass each mailbox showed last, until it runs out, so that a call carrying it again is a lookup;
- the poll buckets;
- an LRU of what is held of each address, a mailbox's record with its identity's revocations, for sends and reads of a mailbox, which this process's writes and the stream keep current, with the addresses a read found missing. A copy read before a write this process has applied is never put, not even for a moment: the LRU counts the writes to each shard of addresses (the first byte), and counts and applies each write in one step under its lock (`recCache.write`), a write of this process's whose outcome is unknown among them, which makes the process forget the address, the LRU and the index both, so that its next use reads the record (`Memory.write`, § The store); a read takes its shard's count, a token, before it reads, and its copy is put in one step under that lock, merged with the one held, which keeps every revocation either holds, or, for an address the LRU does not hold, only while the count is still the token (`recCache.fill`, `mergeViews`). A read that found nothing is remembered as missing the same way, and a lookup that joins a shared read begun at an older token than its own reads again (`Server.lookup`). A record never moves back to an older one, in the LRU or in the index: two records of an address are ordered by when their mailbox registered, to the millisecond, then by their `rev`, in one comparison every place that orders them uses (`version`), since a mailbox registered again once the TTL took its record starts at rev 1 again (the client repo's #407 item 2). A record carries its mailbox's ACL, two sorted lists of 32-byte addresses that `--acl-entries` bounds, so a send's check of it reads nothing more;
- an LRU of account records, as many as mailbox records, for a sender in an account (`PROTOCOL.md` §11.16): filled on first use by a strongly consistent read, put only if no change to an account was counted since that read's token (one count serves every account), refreshed or evicted by the accounts stream in the step that counts the change, as the mailbox LRU is;
- the key its marks are tagged under, made at random when it starts.

That base measures 566 B a polling mailbox: 271 in the index, 127 for the poll bucket and 168 for the pass remembered (measured 2026-10-13), so 0.57 GB per million. The identity's key, kept in SSH wire form so that it can be of any type, and the signer's hash are 112 B of it. A mailbox on a P-256 identity holds a 104-byte key where an Ed25519 one holds 51. The other maps are bounded: a bucket key goes once its bucket is full again, a remembered pass within an hour of running out, and the mailboxes remembered as missing hold at most `--mailbox-cache` entries.

### The pass check

**A new pass is checked in three steps, cheapest first** (`checkPass` in `internal/server/pass.go`, whose doc comment has them), against the standing memory holds of a mailbox it has loaded, or against the record of one it has not:
1. **The signing key it carries, by the SHA-256 of its bytes, against the hash of the mailbox's current signer's, the certificate where it is one, and then of its identity's,** whose pass is always taken (`PROTOCOL.md` §8). A pass by any other key stops here, at a parse and a few hashes: 35 µs measured. Another encoding of the same certificate, which one an ECDSA identity signed has (`PROTOCOL.md` §5), is other bytes, and stops here too: `certificate_not_current`, naming the current certificate's serial where there is one, and `certificate_revoked` while the current certificate is revoked, when only the identity's pass is taken (`otherSigner`).
2. **The signature on the pass.** The signing key is public, since it rides in everything a mailbox signs, and a signature does not cover the key it names: anyone can name a mailbox's key in a pass of their own, and this step refuses it, at one signature check: 95 µs measured.
3. **The signer against the identity on record:** a certificate by the identity's signature on it, with every rule of `PROTOCOL.md` §5, as when it was put on record; the identity by its key, byte for byte. Only a pass that signer's key signed reaches it. It checks again what a registration or a prekey upload checked, so a record that held the hash of a certificate its identity never signed still gives no pass; if it ever fails, the record is wrong, and `dromas-server` logs it and answers `401` with the hint to publish a new prekey, which is checked in full.

A pass under a certificate that passes all three costs about 180 µs, two signature checks in all (`internal/server/cost_test.go`); the identity's pass costs one.
- **A pass that passed is remembered, one a mailbox, the last it showed, with the key it was checked under,** until it runs out or its certificate, if it is under one, ends, if that is sooner (`seenPass`): a later call with the same value, while that key is the identity's or the mailbox's current certificate, not revoked, is a hash of the header and a lookup, 1.5 µs measured. The same pass in another header a server system reads (`PROTOCOL.md` §8), or with a P-256 signature's other `s`, which ECDSA takes (§3.2), is a count at the gate, a parse, a second hash and the lookup, and no signature check: memory keys a pass by `protocol.Pass.Authorization`, which writes `s` low (dromas-dev/dromas-server#69). A signature in any other form is no pass. So a mailbox that keeps its pass for ten minutes, as both clients do, costs one check in ten minutes of calls, and two clients running one mailbox with different passes are each checked again at every call. An entry goes at the first sweep after its pass runs out, which runs when a pass is kept and at most once an hour.
- **`dromas-server`'s names are `--names`:** a pass is taken only on a request whose `Host`, written as an origin is (`serverName`), is one of them, so a proxy in front must pass `Host` on unchanged. `--dev` takes any name unless `--names` is given. A remembered pass was checked so when it was first shown, and is taken after that whatever `Host` a later request carries.

### The store: one memory, over a backend

**`Memory` (`internal/server/memory.go`) is the store, the one implementation of `Store`, over a `Backend` (`backend.go`)**, which holds the durable state and hands each change to it to memory. Everything above is `Memory`'s: the record cache and its tokens, the index and its marks, the standings, the counts, a mailbox's load on its first use, and what each write and each change does to them. A backend is the durable operations alone, and their outcomes: `dynamoBackend` (`dynamo.go`), DynamoDB and S3 Express, the production one; `memBackend` (`memstore.go`), maps in the process, for `dromas-server serve --dev` and every test without AWS, which so run the memory production runs. Another backend copies only its own mapping of its storage to these operations.

**Each write of a backend has exactly one of three outcomes, and one function reads it** (`Memory.write`, which every write the store makes goes through):

| Outcome | What the backend returns | Memory | A count reserved for the write (`LIMITS.md` rule 4) |
|---|---|---|---|
| Applied | nil | the write is put in it | kept |
| Refused, as the store stated, of a write it did not make | `ErrExists`, `ErrStale`, `ErrNotFound`, `ErrKeyRefused`, a send's body not stored (`errNotStored`), a send that met another's item of the same ciphertext (`duplicate`, with that item's header, which the send answers from), or a refusal AWS stated (`errRefused`) | nothing changes, but a refusal of a write's condition on a mailbox's record or revocations (`ErrStale`, `ErrExists`) says the store holds what this process never applied, so the copy held of the address is evicted, counted as a write, and a read begun before it puts nothing | given back |
| Unknown: it may have applied | `ErrUnknown`, wrapping its cause, or any error the backend did not state as a refusal | the address is forgotten, the LRU and the index both (`forget`), or the account evicted, so that the next use reads it; `ErrUnknown` is returned, wrapping the cause | kept, never given back (by design) |

- **The handlers settle their counts by the same outcome:** `mayHaveApplied` is `errors.Is(err, ErrUnknown)`, and reads no error of AWS's.
- **A write holds what its request's preconditions held** (`PROTOCOL.md` §11.2): the record's writes by their rev, and a registration's by no record, whatever the request carries; a revocation's by a condition of its own, `Expect`, a parameter of `Revoke` on both backends, asked only when the request carried `If-Match` or `If-None-Match: *`: that the address's revocations item exist, or not, in the one `UpdateItem`'s condition. A failed one is `ErrStale`, a refusal of a condition on the address, as any other. A send's write is a new message's item, conditional on its id alone: what an `If-Match` held of the recipient's mailbox at its read is not asked again.
- **The DynamoDB backend reads what AWS answered a write in one place** (`written`): its noting retryer on every write call, one note shared by all of a transaction's calls (`transact`), so that a write one attempt of which left it open stays open whatever came after (this repo's #89, #101); a failed condition, which is the write's own refusal unless a noted attempt came before it, or unless it hands back the item it met (a send's own item is the send, applied; another's is a duplicate); a throttle, or any other answer of 4xx, a refusal; anything else unknown. A transaction's failed condition after an attempt of its own call is a refusal stated, since that call's attempts carry one client token, and not after one of an earlier call, which carried another. Every call it makes to AWS is bounded by `storeTimeout` in one place for each of its clients: the SDK's middleware on the DynamoDB and S3 clients (`bound`), which a body read after its call shares, and the follower's view of its streams (`boundedStreams`).
- **A write of several steps is one operation of the backend, whose outcome is its item's write**: a send (its body's `PUT`, then its item's conditional `PutItem`), an ack (its body's `DELETE`, then the retire's `DeleteItem`) and the delete of a mailbox's messages (`DeleteAll`: a Query of the live index, `DeleteObjects`, then a retire for each message). A body `PUT` that failed is a refusal, whatever S3 answered: nothing is stored (this repo's #90). A body `DELETE`, a Query or a `DeleteObjects` that failed before any retire changed nothing a reader of the list sees: a refusal, and memory is as it was. Each retire `DeleteAll` makes reaches memory as it lands.
- **A change to what a backend keeps reaches memory as a typed `Change`, which the backend decodes from its own items, through one apply** (`Memory.apply`, § Following the stream). The in-memory backend hands each change a write made to it at the start of its next write, in the order the writes were made, on that write's goroutine: so the change comes after its writer has applied the write's outcome to memory, as DynamoDB's stream brings a write back a second or two after it, and no test waits on a goroutine for it.
- **The tests inject faults at the boundary** (`faults` in `backend_test.go`): any write made refused, unknown before applying or unknown after applying, and a hook at any read's answer, where a write a read did not see lands. `TestEveryWriteOfTheBackendReachesMemoryByItsOutcome` holds every write of the interface, taken from its method set, to each outcome. A crash between a write's two steps on DynamoDB, which no boundary can reach, is the DynamoDB backend's own hook (`crash`).
- **The three outcomes follow Go's `database/sql/driver` and the MongoDB Go driver** (`PRECEDENTS.md` Part 3 § 1, in the client repo).

### Behind a reverse proxy

`dromas-server` speaks plain HTTP; TLS ends in a reverse proxy in front (dromas-dev/dromas-server#124). That keeps TLS above `dromas-server`, so a restart of `dromas-server` drops no client's TLS session, and it is where routing by a mailbox's address goes once there is more than one process (§ Extreme scale).
- **The client's address** is the last entry of `X-Forwarded-For` from a peer in `--trusted-proxy`, the one that proxy wrote of the connection it took (`clientIP`); every entry before it is the caller's own word and is never read, and from any other peer the header is ignored. Every per-IP limit keys on it (`LIMITS.md`), and the site is told it (`--site-backend`), with every other header a proxy or CDN names a client by dropped.
- **`Host` is passed on unchanged** (§ The pass check), and `X-Forwarded-Proto` from a trusted proxy says the scheme (the link page's).
- **A held list holds nothing of `dromas-server`'s but its goroutine and its connection:** no write deadline runs while it waits (the pacing sets one on each write, and the answer's is set as it is written), `--idle-timeout` is for the time between requests, and a connection `--listen` accepts sends no TCP keep-alive probes (`listenAll`), as nginx leaves a listening socket's to the operating system's default, since each phase of a connection has a bound of its own. Every change memory applies to a mailbox, a write of this process or one from the streams, passes through the index's `apply`, `imageStanding` or `forget`, which wake the lists held on it (`TestEveryChangeMemoryAppliesToAMailboxWakesItsHeldLists`, from the backend's writes and its feed's kinds); a list held on one process is woken by a send stored on another through the stream (measured 2026-10-28 on DynamoDB, `TestTwoProcesses`: 0.64 s). A message's expiry is no change memory applies: a held list's wait ends at its mailbox's first expiry, by the store's clock, and its page is read again. The page of a list asked to wait is read strongly consistent (§ Memory), so a list is never held on a page that misses a change memory had applied. When the API's `http.Server` shuts down (SIGTERM), `RegisterOnShutdown` answers every held list `304` at once (`StopHolds`, wired where that `http.Server` is made: `Server.HTTPServer`), so its clients list again at once and `Shutdown` waits for none of them.
- **Several listen addresses** (`--listen`, comma-separated) are served by one `http.Server`: each connection the proxy holds to `dromas-server` is one 4-tuple, so one proxy address calling one `dromas-server` address is bounded by the proxy host's range of ephemeral ports, and every address more is one range more. A held request (a long poll, the client repo's #510) holds one for its whole wait.
- **`--idle-timeout` above the proxy's own idle timeout for its upstream connections** (`LIMITS.md`), so the proxy closes first.
- **What a proxy does that `dromas-server` also does:** a proxy that buffers a request's body before passing it (nginx's default) keeps a slow upload off `dromas-server`'s large read; `dromas-server`'s own header and body timeouts and every count stand whatever is in front (`LIMITS.md`).

### Request paths

| Call | Touches | Notes |
|---|---|---|
| Poll / list `GET …/messages` | The pass, from memory. Layer 1 for the count; the page from one DynamoDB Query (from layer 2 once it is built) | Empty: the empty page, built from the count alone, or `304` to its `ETag`. Every list answer carries `Retry-After`, the poll interval (`--poll-after`), and a first page its `ETag`; a `200` is a page, with `count` and up to 50 messages (the delivery contract, decided; `PROTOCOL.md` §11.11). **Held** (a long poll, `wait`): where the answer would be `304`, the handler takes the mailbox's change channel from memory (`Store.Changed`) before it reads, then waits on it, its mailbox's first expiry (`Store.NextExpiry`), its wait (at most `--max-wait`), the caller's leaving or `dromas-server`'s stopping, and reads again; it reads nothing while it waits, and its page is a strongly consistent Query |
| Fetch `GET …/messages/<id>` | Memory, which answers an id the mailbox does not hold `404` with no storage call and a `HEAD` with nothing more, and counts a fetch of a message this process has served before against the mailbox's allowance (`PROTOCOL.md` §11.12). Otherwise DynamoDB GetItem of the message item by `mailbox, id`, and S3 Express GET, of the bytes from a `Range`'s first on where the fetch asks for one inside the body (`GetObject`'s `Range`; `PROTOCOL.md` §11.12) | The answer is the ciphertext's bytes, `application/octet-stream`, and nothing else: when it came is the list's, and who sent it is the signature's, inside the ciphertext. To a `Range` the answer is `206`, the bytes from there on. Memory can say a message is absent, never that it is there: the read decides. A live item whose body is gone leaves the list and is answered as gone |
| Ack `DELETE …/messages/<id>` | Memory, as for a fetch (an id not held is `404`); otherwise S3 DELETE, then the item's conditional DeleteItem (§ Storage) | Both steps are safe to repeat. Applied to local memory at once; the stream tells the others |
| Send `POST /v1/<addr>/messages?statement=…` | The sender's pass; the sender's record, for its account, and the recipient's, each from memory or the LRU, or one read; GetItem of the message item (the dedupe), S3 PUT and one conditional PutItem (§ Storage) | The body is the ciphertext's bytes, read to the sender's cap. The caps read layer 1, and the sender's key type, the recipient's declaration and its ACL are in the two records, with no read of their own. No signature on the message is checked: it is inside the ciphertext |
| Register `PUT /v1/<addr>` | Memory, for a mailbox this process holds or a revoked address it holds; otherwise one read of what is held of the address, under the registrations counts reserved before it and given back if it finds a mailbox or a revocation, or, once those are spent, under a miss, as a lookup's. A registered mailbox or a revoked address is answered from what memory or that read holds: an identical retry by its pass and one of the mailbox's calls, or `401 certificate_revoked` while its revocation of certificates covers its signer; anything else `409 conflict`; a revoked address `410 revoked` with its record. Only a registration that would make a mailbox keeps the registrations counts, kept before its signatures, so one whose write meets a mailbox another registration of the address made meanwhile, an identical one among them (`ErrExists`), is answered as registered with its counts spent (the client repo's #443). One that would make a mailbox costs, under a certificate, four signature checks (the certificate and the statement under it, then the pass under it and the certificate again), and two by the identity, and one PutItem, conditional on the address holding no record (§ Storage) | The mailbox is in use from this one write. An identity's key type changes only the checks of its own signature: 58 µs each for Ed25519, 81 µs for P-256 (measured 2026-10-13). A post-quantum statement's key check adds a trial wrap, an ML-KEM-768 encapsulation |
| New prekey `PUT …/prekey` | The record (the LRU, or one GetItem), the same checks, DynamoDB UpdateItem | The authority is the statement's own signer and a pass by it: no pass by the mailbox's current signer is needed |
| Read a mailbox `GET /v1/<addr>` | The LRU, which serves the revocations held as they are kept, with nothing parsed; on a miss, one read of the address, the one a send after it would make. A revoked mailbox is `410` with the record it keeps | Never cached in front of `dromas-server`: every API answer says `no-store` (`PROTOCOL.md` §11.2). The one API answer gzipped, to a request that takes it (below) |
| ACL `PUT …/acl` | The pass, the record (the LRU, or one GetItem), one conditional UpdateItem. It deletes no messages (`PROTOCOL.md` §11.14) | Replaced whole, with an `If-Match` held to the ACL held when one is sent (`PROTOCOL.md` §11.14) |
| ACL `GET …/acl` | The pass, the record (the LRU, or one GetItem) | The record's ACL, or the open one of a mailbox with none, with its `ETag`; `304` to an `If-None-Match` that names it |

**The version policy comes first under `/v1/`** (`versioned`, `internal/server/version.go`; `PROTOCOL.md` §11.17, §11.4 rule 0). It wraps the API's router, inside `notStored` and in front of `unrouted` and every route's gate, and reads only `Dromas-Version` (`protocol.RequestVersion`: none, or another form, is `0.0.0`). It sets `Deprecation` and `Sunset` on the answer, whatever its status, where the policy covers the version, and counts the request by its state (§ Metrics). A version below the policy's floor, or covered by a sunset whose time has passed at `dromas-server`'s clock, spends its address's flood budget (`spendRequest`) and is answered `410 version_retired`, with `min_version` where there is a floor, before any route is matched; `dromas-server`'s document, `GET /v1/`, takes every version and answers the policy, the same to every caller, with no pass. The policy is `--version-policy`'s file, of the runtime-config directory (§ Runtime config), held to `protocol.ServerDocument.Check`; a request reads the policy in force once, as it arrives (`atomic.Pointer`), so a reload swaps it whole between requests and drops no connection.

**`HEAD` on a `GET` route is net/http's:** `http.ServeMux` matches a `HEAD` to a `GET` pattern, and `dromas-server` sends none of what the handler writes, so each route answers its `HEAD` as its `GET`, its counts and all, but a message's and a list's, whose handlers read the method (`PROTOCOL.md` §11.2 has what each does).

```mermaid
sequenceDiagram
  participant A as sender
  participant P1 as dromas-server (any)
  participant S3 as S3 Express
  participant D as DynamoDB
  participant P2 as dromas-server (others)
  participant B as recipient
  A->>P1: POST /v1/B/messages?statement, the ciphertext as the body, carrying A's pass
  P1->>P1: check the pass (from memory once seen), parse, stanza check
  P1->>D: GetItem B, id (dedupe)
  P1->>S3: PUT B/id
  P1->>D: PutItem B, id (if no live one)
  P1->>P1: apply to its own memory
  P1->>A: 201 id, received_at, expires_at, and Location
  D-->>P2: stream record (about 1 to 2 s)
  B->>P2: GET /v1/B/messages
  P2->>B: 200 with count and a page, its ETag and Retry-After
```

**Compression: gzip, where it saves bytes for little CPU, and nowhere else** (`internal/server/compress.go`, `PROTOCOL.md` §11.2). A request that does not take gzip (RFC 9110 §12.5.3) gets none, and an answer that may be compressed says `Vary: Accept-Encoding` either way.

| Answer | Compressed | Why |
|---|---|---|
| A mailbox's read, `GET /v1/<addr>` `200` | Per answer, by Huffman coding alone, with a writer from a pool | Base64 in JSON, read before every post and for each sender in a drain. On reads of 1.6 KB and 4.1 KB (an X25519 and a post-quantum prekey) it saves 24% and 27% in about 9 and 13 µs; levels 1 to 6 save 1.4 to 3.8% of an X25519 read more, and nothing of a post-quantum one, in 1.5 to 1.7 times the time, since base64 holds almost no repeats, and a new writer per answer costs more than the coding (measured 2026-10-18) |
| A list or a poll | Never | A `304` has no body and an empty page is 45 bytes; a page puts what senders chose beside the mailbox's own values, the shape of BREACH (RFC 7457 §2.6) |
| A fetch | Never | Age ciphertext does not compress (§ Storage) |
| Errors, an owner's reads, the link page | Never | A few hundred bytes, or seldom asked for |
| A site's answer | Never by `dromas-server` | Its web server's, passed on as that server sent it, compressed or not |


### Runtime config

**The files of the runtime-config directory are read at start and kept in force while `dromas-server` runs** (`Reloader`, `internal/server/runtimeconfig.go`); `--version-policy` names the one there is. The directory, `/config/` in the container, is bind-mounted as a directory, read-only: a single-file bind mount follows the file's inode, so a save by rename is never seen there (`README.md`).
- **Read again at once on SIGHUP,** as Prometheus reloads `--config.file`, whatever its bytes, **and every minute** (`ReloadEvery`), whatever the file's metadata says, since a Kubernetes ConfigMap changes its directory mount by a symlink swap and sends no signal, and a modification time's resolution and a rewrite of the same size defeat a check of metadata. The minute's read changes nothing where the bytes are those read last.
- **Each read is bounded** (`MaxVersionPolicy`: a few KiB past the largest policy of the document's form, written with indents); a larger file is a failed reload.
- **A reload that fails keeps what is in force,** logs one line naming the path and why, never the file's contents, and counts `failed`; one that succeeds swaps the value in whole (`atomic.Pointer`), logs that it loaded, and counts `ok`. A file that fails at start stops `serve`, naming its flag.

### Following the stream
- **Nothing is kept across restarts.** A restart starts with empty memory, loads each mailbox on its first use (§ Startup), and follows the streams from then on. A follower that loses its place (more than the stream's 24 hours behind, an iterator that expired before it read anything, the stream gone) exits the process, and the restart rebuilds.
- Each process reads the streams of the mailboxes, messages and accounts tables itself, with the `NEW_IMAGE` view, one follower per stream. The DynamoDB backend decodes each record into a `Change`, and memory applies it, one rule for each kind (`Memory.apply`). **An item whose image does not read is taken as gone, whatever its kind:** the address forgotten, the LRU and the index both, or the account evicted, each counted, so that memory answers for none of it and its next use reads it, which fails, so nothing is served or taken for it on what memory held before (this repo's #87; the client repo's #407 item 1). A record whose key does not read is skipped: it names nothing memory holds.
  - **Mailboxes:** a record's image (`sk` `0x00`) refreshes the LRU and the standing where they hold an older record (§ Memory); one that does not read as a record, in a state this build never writes among them, is gone. An address's revocations (`sk` `0x01`) add to what memory holds of it, since nothing in them is ever taken away. A record's removal, by the TTL or a revocation of its address, makes the process forget the mailbox: its next use reads it again, so a removal that arrives after a later registration costs one read and loses nothing. Other items under an address are not memory's.
  - **Messages:** an image with `live` adds the message's mark; one without removes it. A removal (an ack, a body found gone, a revocation's delete, or the TTL's, after the message expired) removes the mark of its id with the earliest expiry (§ The in-process plan, rule 5).
  - **Accounts:** an account record's image (`sk` `0x00`) refreshes it in the account LRU; a removal evicts it. Its other items (adopt keys) are not memory's. Which mailboxes an account holds is the mailbox records' to say, through the mailboxes table's index on `account`, which nothing in memory follows.
- **With one process the followers are a placeholder for stage 2.** The process applies its own writes to memory at once and a mailbox loads from the tables on first use, so the streams carry only its own echoes (which clear its ack tombs) and hand edits to the tables. So with one process `--stream-interval` can be long: at ten times the interval, idle CPU and Streams reads both fall tenfold (measured). Lower it when a second process arrives: each empty `GetRecords` costs ~0.34 ms of CPU (measured; never profiled).
- **AWS advises no more than two readers per shard, or reads get throttled** (same doc). So each process reads each shard every N/2 seconds, where N is the number of processes. Up to 4 processes stay within 2 s.
- A parent shard is read before its children, per the lineage rule in the same doc. There's no Go KCL, so we write ~300 lines of shard following (estimate).
- **More than ~4 processes: our own stream bouncer**.
  - One lease holder reads the stream and pushes each change to every process.
  - It is the same idempotent apply, so a bounced change that arrives twice or late is still harmless.
  - Redis is the penciled alternative.
  - Four processes, the scaled shape above, still read the stream directly, about every 2 s.

### Extreme scale: shard by the first character of the address's bytes

**It fits the design.** Every mailbox call names its mailbox in the path (`/v1/<addr>/…`, and a send is `POST /v1/<recipient>/messages`), and an address is `d_` and SHA-384 output in base64url, so the first character after `d_` splits the load into 64 even shards. The edge routes by path prefix. `cloudflared`'s ingress rules can match a path, as can Cloudflare's load-balancing rules or an AWS ALB (an NLB can't).

What changes:
- **Memory stops being replicated.** Each shard group holds only its sixty-fourth of layer 1, layer 2, the mailbox standings and the poll buckets. That removes the one capacity limit above, where every process held all of layer 1.
- **The stream bouncer routes by the same character.** Mailbox events go only to their shard. Mailbox-record changes (revocations, certificates, prekeys) go to every shard, because any shard may check a sender.
- **Per-sender send limits cross shards.** A's sends land on each recipient's shard. The bouncer would broadcast a compact "A sent one" event, so every process keeps per-sender daily counts (~16 B per active sender, estimate).
- **Unchanged:** sends still check the sender's pass against its record, from the LRU or DynamoDB, the link page (`/to/<address>`) goes to any shard, and DynamoDB and S3 need nothing new.

### Startup
**Lazy, per mailbox.** A full Scan at start saves no reads over loading mailboxes as they are used, reads dormant mailboxes too, holds the whole service at 503 until it ends, and is a burst that provisioned capacity throttles; at 1M mailboxes the mailboxes table alone is ~0.6 read units a mailbox.
1. Position a follower at LATEST on every open shard of the three streams, and report ready. Memory starts empty. A closed shard holds only changes from before, which any later read sees.
2. **A mailbox loads on its first use** (`index.ensure`, `Memory.readMailbox`): two reads of the backend, one strongly consistent Query of what is held of its address, its record and its identity's revocations (`ReadAddress`, which also joins the LRU), and one Query of its entries in the `live` index (`ReadLive`). Strongly consistent, because a write made just before the read must be in it; one made after reaches memory by a stream.
   - Callers that arrive while it loads share that one read.
   - A change to the mailbox that arrives meanwhile, from a stream or this process, queues and applies after the load, in order: the read predates it, and the changes are idempotent.
   - A change to a mailbox memory does not hold is dropped: its first use reads it.
   - A failed load (a throttle, say) leaves the mailbox unloaded, and that call answers 503; the next call reads again.
3. **A mailbox is loaded by a call that has shown its pass, or by a send to it from a mailbox that has shown its own** (the caps read the recipient's marks). Until a mailbox is loaded, a pass is checked against the mailbox's record (from the LRU or one GetItem), so a call with no pass, or a bad one, loads nothing. A mailbox's first call to a process therefore reads its record twice, once for the pass and once in the load: there is nothing cheaper that shows a pass names a mailbox that exists.
4. A loaded mailbox stays in memory until the process restarts. Evicting idle mailboxes is possible later: a reload is the same read.

### Limits

**Every limit, who pays for it and the known weaknesses → [`LIMITS.md`](LIMITS.md).** What is architecture about them:
- **Every budget and count is per process,** in memory, because a poll can't afford a round trip: with N processes a mailbox could spend N times each. Sharding by address at the edge (§ Extreme scale) or sticky routing would put each mailbox's calls on one process; with neither, each process is to enforce a 1/N share (not built: one process enforces the whole of each), which keeps the bill ceiling, and rules at an edge in front can sit on top, keyed by /64 for IPv6.
- **The mailbox total (`--mailbox-cap`) is global**: it reads layer 1's marks, which the stream feeds on every process, 1–2 s behind, with no extra writes; a process's own sends count at once. **Sends per sender a day, and the counts of renewals, certificates and raises of a revocation of certificates,** are each process's own today. Every accepted send and every renewal arrives on the stream, so each process can count across all of them: that is stage 2, not built.
- **The passes remembered are per process,** so with N processes a mailbox's new pass is checked once on each it calls.
- **Every limit is a bucket, the numbers a day among them:** a number a day is one back each day divided by it, into a bucket its `-burst` flag sets apart, as Let's Encrypt sets a limit by its burst, count and period, so no window empties at midnight and every refusal's wait is its key's own (the client repo's `PRECEDENTS.md`). A start refuses a number a day that is on with a bucket of nothing (`bursts`).
- **A bucket is one time per key, when it is full again (the GCRA form of a token bucket, as Let's Encrypt's limiter keeps it, and a count given back as it refunds one: the client repo's `PRECEDENTS.md`),** so a token comes back by arithmetic at the next call and nothing runs in the background (`buckets` in `internal/server/limits.go`). `prune` drops the keys whose buckets are full, inside a call, at most once in the time an empty bucket takes to fill, and only calls on that bucket set wait for it: over 100,000 keys it took 0.93 ms when it kept them all and 14 ms when it deleted them all (measured 2026-10-18, one AWS Graviton4 core).

### Metrics

**What `dromas-server` does and refuses is counted, for its operator, on a listener of its own** (`--metrics-listen`, off unless set; `internal/server/metrics.go`). It is how a limit is tuned and an attack on a mailbox is seen without reading logs, which carry no caller's address by design. Prometheus' practice and Let's Encrypt's Boulder count the same way, on a listener apart from the API (`PRECEDENTS.md` Part 3 § 2, in the client repo).

| Metric | Labels | Counts |
|---|---|---|
| `dromas_server_requests_total` | `route` (the router's pattern, `unmatched` for none), `status`, `code` (the problem's, empty for none) | every request answered, and as `499` one whose caller left before its answer, which is not sent: nginx's code for it, which nginx too logs and never sends |
| `dromas_server_request_duration_seconds` | `route` | how long each request took to answer |
| `dromas_server_limit_requests_total` | `limit` (a `rate_limited`'s quota, or the code of its own), `subject` (`mailbox`, `ip`), `decision` (`allowed`, `denied`) | each take of each limit, as Boulder's limiter counts each spend |
| `dromas_server_limit_keys` | `limit` | the keys each limit holds now |
| `dromas_server_passes_total` | `outcome` (`remembered`, `checked`, `refused`), `code` | passes taken from memory, verified, and refused |
| `dromas_server_lists_total`, `dromas_server_fetches_total` | `kind` (`poll`, `page`; `first`, `repeat`) | lists and messages served; a send stored, a duplicate, an ack and a renewal are each a route and status of the first |
| `dromas_server_lists_held`, `dromas_server_held_lists_total` | `outcome` (`changed`, `waited`, `gone`, `stopped`, `refused`) | lists held for a change now, and how each held list ended, once however often it woke to the same page: the mailbox changed or a message in it expired, its wait passed, its caller left, `dromas-server` stopped, or it was refused past `--max-held-lists` |
| `dromas_server_store_calls_total`, `dromas_server_store_call_duration_seconds` | `service`, `operation`, `outcome` (`ok`, `conditional`, `not_found`, `throttled`, `error`) | every call to DynamoDB, its streams and S3, with its retries |
| `dromas_server_cache_events_total` | `cache` (`mailboxes`, `accounts`, `missing`), `event` (`hit`, `miss`, `eviction`) | the record caches |
| `dromas_server_stream_record_age_seconds` | `table` (`mailboxes`, `messages`, `accounts`) | how old the last record applied from each stream was: how far behind memory follows |
| `dromas_server_item_collection_estimate_bytes` | | after each message written, the upper bound of DynamoDB's estimate of its mailbox's item collection, at 2^30 bytes a GB: AWS advises an alert at 8 GB, before the 10 GB past which the mailbox takes no messages (§ Storage). AWS does not say whether its GB is 10^9 or 2^30 bytes (API Reference, *ItemCollectionMetrics*: "in gigabytes"); 2^30 is the safe side, since the bytes reported are then never fewer than AWS's estimate, and the buckets are whole GB, so the one at 8 GB is AWS's 8 GB either way |
| `dromas_server_runtime_config_reloads_total` | `file` (`version-policy`), `result` (`ok`, `failed`) | each reload of a file of the runtime-config directory (§ Runtime config); the minute's read of bytes unchanged is none. When the file last loaded is its log line's |
| `dromas_server_version_requests_total` | `state` (`current`, `deprecated`, `sunset`, `retired`) | each request under `/v1/` by what the version policy says of its version: retired (below the floor or past a sunset; answered `410` but on `GET /v1/`), else sunset (a sunset covers it, not yet passed), else deprecated (a deprecation covers it), else current. The version itself is no label: the client writes it. Kubernetes counts requests to deprecated APIs by what its own code defines (`apiserver_requested_deprecated_apis`, from memory) |
| `dromas_server_large_reads_total`, `dromas_server_bodies_cut_total`, `dromas_server_connections_open` | `outcome` (`taken`, `timed_out`, `gone`) | the one large read's waits, bodies cut off at their deadline, connections open |
| the Go runtime's and the process's | | `client_golang`'s collectors |

- 🛑 **No label is a value a caller chose:** no address, IP, mailbox, message id, cursor or path as sent. Each would be a series per caller, and each is what the logs leave out: "Do not use labels to store dimensions with high cardinality (many different label values), such as user IDs, email addresses, or other unbounded sets of values." (`docs/practices/naming.md`, the same commit). `TestMetricsCarryNoCallerValue` holds it.
- **Which mailbox or address spends a limit is no metric:** `dromas-server limits top` lists them, over the admin socket (`LIMITS.md`).
- **Per process,** as the limits are: with several, the scraper sums them.
- **What they cost:** an empty poll through the handler, with no poll limit, took a median 13.3 µs with them and 11.3 µs without (five runs of 20,000 each, two AWS Graviton4 cores, measured 2026-10-19). About 2 µs a poll is 0.03 vCPU at a million mailboxes polling once a minute.
- **Not built:** `net/http/pprof` on the same listener, which Boulder serves there.

### Background jobs
**Not built.** The plan: one process holds a lease, a DynamoDB item taken with a conditional put that expires, and runs the background jobs. None is planned now: DynamoDB's TTL deletes a mailbox's record once nothing valid for it is left (§ Storage), so there is no reaper of our own and no `last_seen`. A mailbox past its expiry is not in memory unless something used it, since memory loads per mailbox (§ Startup).

### Failure modes

| Failure | What happens | Recovery |
|---|---|---|
| Memory pressure | Layer 2 (once built) shrinks, down to off; lists come from DynamoDB, as all of them do today; polls are unaffected | Automatic |
| Layer 1 alone outgrows memory | Capacity, not a fault: every process holds all of it | A bigger instance; ~50 B per live message makes this distant. At the extreme, shard by address (§ Extreme scale) |
| A writer dies right after its commit | The stream still delivers the change to everyone | Automatic |
| A process falls behind the stream | Stage 2, not built: it fails `/readyz` and leaves rotation. Today a follower that loses its place exits the process | It catches up. More than 24 h behind (stream retention) means a restart: memory starts empty, and each mailbox is read again on its first use (§ Startup) |
| DynamoDB or its stream unavailable | Processes can't prove they're current: `503` + `Retry-After` | Wait |
| A call to DynamoDB, its streams or S3 that never answers | Each call the store makes to AWS ends at a bound (`storeTimeout`), set in one place for each client (`bound`, `boundedStreams`; § The store), a read as a write, a stream follower's among them, whatever context its caller handed it, and so does each read a call shared by several callers makes apart from its request (a lookup's, a send's steps 6 to 9): its caller is answered `503`, whoever waits on a shared call waits no longer, and a follower whose read ended there reads again at its next pass, as after any failed read | Automatic; its caller retries |
| A write whose outcome is unknown (an answer lost, a timeout, a fault of AWS's own, after any attempt that left it open) | Memory forgets what it held of the write's target, its count is kept, and its caller is answered `503` (§ The store); a registration reads its record and is answered from it | The next use reads what is held |
| S3 Express AZ outage | Sends and fetches fail; polls and lists still work | Wait. Losing the AZ loses unacked bodies (accepted) |
| Process restart | Ready once the streams are positioned (§ Startup) | Each mailbox's first call reads it once |

## Storage

**Three DynamoDB tables, one kind of thing each, mailboxes (`--mailboxes-table`), messages (`--messages-table`) and accounts (`--accounts-table`), and an S3 Express One Zone directory bucket in `dromas-server`'s AZ for bodies (`--bucket`).** Kept apart, so a flood of messages cannot throttle registration or renewal, mailboxes are backed up and messages are not, and each table's stream feeds its own cache. An address's items in the mailboxes table are its mailbox's record and its revocations, which one Query of the address reads together. Every key is binary, an address its 32 bytes.

| Where | Key | Holds | Expiry |
|---|---|---|---|
| mailboxes | `addr`, `sk` = `0x00` | the mailbox's record: the identity document; `state`, `active`, the one a record is written in (one read in any other is refused, and forgotten where the stream brings it: `decodeStanding`); the current prekey statement and its signature, as sent, which carries its signer's key; `rank` and `signer`, that signer's rank, 0 for the identity and a certificate's serial, and the SHA-256 of its key's bytes, the identity's key or the certificate, which later calls are held to; `senders`, the sender key types the mailbox declared with that statement, those this build verifies, or `any` alone; the `--retired-kept` newest retired prekeys' type, `not_after` and key hash; `rev` (§ The store); created; `account`, the account it is in, if any; `acl`, as `GET …/acl` answers it, absent until the mailbox puts one, then replaced whole. Each signature is at most its identity key type's bound (`protocol.SignatureBound`). Reserved and not written: warmup_until, profile + sig | TTL on `expires_at`: one date, raised at a registration and each renewal to the latest of what it was, the prekey's `not_after` plus the message TTL and the end of the statement's certificate, if it is under one, and never lowered (`keep`; `PROTOCOL.md` §13) |
| mailboxes | `addr`, `sk` = `0x01` | the address's revocations, mailbox or none: `identity`; `revocation`, the signature that revoked the address, written once and never removed, which the read of the mailbox serves as `revocation_signature`; `revoked_certs`, `revoked_certs_sig` and `through`, the identity's highest revocation of its certificates as it was signed, its signature and the serial it revokes through, absent until one is published, then replaced whole by one through a higher serial. Three lines, so of a fixed size, and kept apart from the record, which a renewal writes whole | none: kept for good, a revocation of certificates too once the certificates it covers have ended |
| mailboxes | `addr`, `sk` ≥ `0x02` | reserved for the mailbox's own items; none yet | as the mailbox |
| mailboxes, its GSI `account` | `account`, `addr` | keys only: each account's mailboxes, from the records that name one. A record that leaves its account, or that the TTL deletes, leaves it | with the record |
| messages | `mailbox`, `id` = SHA-256 of the ciphertext | one item a live message, its header: size, `received_at` (ms), `expires_at`, and `live` = `received_at` (ms, u64 big-endian) ‖ id. No sender and no signature (`PROTOCOL.md` §13); an ack deletes it | TTL on `expires_at`, for a message never acked |
| messages, its LSI `live` | `mailbox`, `live` | the live messages, oldest first, with size: a list's cursor is the last `live` (`formatCursor`). An item without `live` is not in it, and is no message | with the item |
| accounts | `account` = the account id's bytes, `sk` = `0x00` | the account: `unmetered`, `rev` | none |
| accounts | `account`, `sk` = `0x04` ‖ SHA-256 of the key | an adopt key: `uses` left, `expires` (ms); never the key (`adoptkey.go`) | TTL on `expires_at` |
| the bucket | `<hex mailbox>/<hex id>` | the age ciphertext, exactly as the send's body carried it | a lifecycle rule of at least the TTL (below) |

Mailboxes: PITR on, AWS Backup on, TTL on, stream `NEW_IMAGE`. Messages: neither backup, TTL on, stream `NEW_IMAGE`. Accounts: PITR on, AWS Backup on (billing data), TTL on, stream `NEW_IMAGE`. **Each table is provisioned capacity, never on-demand,** so a burst read is throttled rather than absorbed: memory loads per mailbox (§ Startup).

**What each write is:**
- **A send** reads its message item first, so the same ciphertext posted again while the mailbox holds it unacked, by any sender, gets the receipt held (`PROTOCOL.md` §11.10 step 6), then makes two plain writes, never a transaction: the body's S3 `PUT`, then the message item, conditional on `attribute_not_exists(live) OR received_at <= now − Retention` (`protocol.Retention`), so an expired item the TTL has not yet deleted is replaced. The dedupe is that condition on (mailbox, id) while the message is live, and nothing is kept once it is acked or expired: the same bytes after that are a new message, stored and counted as any send (dromas-dev/dromas-client#507). A failed condition hands back the item it met: one of this write's own `received_at`, which an attempt the SDK retried applied, is the write, applied (this repo's #89), and so is another post's of the same bytes in the same millisecond, which is the same item to the byte; any other is the receipt held. Every `200` and `201` means the message was stored. The key is the ciphertext's SHA-256, so a duplicate `PUT` rewrites identical bytes, which the live message's body already is. Left to the lifecycle rule: an object a crash left after its `PUT`, whose sender got no `201` and posts again; a `PUT` that lands between an ack's `DELETE` and its item's delete, whose item write meets the item still live; a duplicate whose item write never returns. A post whose `PUT` lands before an ack's `DELETE` of the same bytes and whose item write lands after the ack's item delete writes an item whose body is gone, answered `201`: it is listed and counted until a fetch finds no body and retires it (below; the client repo's #548 item 6).
- **The posts of one ciphertext to one mailbox, naming the same statement by its hash, in flight at once at one process are one call, from any sender,** from the dedupe to the write (`golang.org/x/sync/singleflight`, in `send`): a post that arrives while the first is in it gets the first's answer, the receipt where the first stored the message or found it held, and is never refused by a quota the first spent. A refusal is handed on only to a post from the first's own sender, which would meet it too; a post from another sender, whose ACL entry, sends and key type are its own, is made again in a call of its sender's. The call runs apart from the request that leads it, each of its reads bounded on its own (§ Failure modes). Across processes the item's condition decides.
- **After its write a send reads its recipient again, from memory:** a mailbox revoked since its first read has what the send wrote deleted, as the revocation deleted the rest, and the send is answered `410`, or `404` for a mailbox no longer held. With more than one process that read is to be strongly consistent (stage 2, not built); until it is, a send can land after a revocation's delete.
- **An ack** deletes the body, then the item (`DeleteItem`), conditional on its being live and unexpired, and nothing of the message is kept (`PROTOCOL.md` §13). The two are one write of the store, whose outcome is the item's (§ The store): a `DELETE` that failed leaves the message listed as it was, and a crash between them leaves a listed message with no body, which the client's next ack, or any fetch, deletes. An ACL deletes no messages (`PROTOCOL.md` §11.14).
- **A registration** is one `PutItem` of the record, conditional on `attribute_not_exists(addr)`. A renewal, an ACL, an adopt and a leave write the record at the `rev` they read (§ The store), a renewal the whole record. An adopt writes the mailbox's record and the key's item in one transaction, once it has read the key's item strongly consistent (`dynamo_accounts.go`).
- **A revocation** writes the address's revocations item first, then deletes the mailbox's messages as acks do, then its record (`Revoke`, `DeleteMessages`, `DeleteMailbox`). The item is one `UpdateItem`, which keeps the address's revocation once (`if_not_exists`) and replaces a revocation of certificates only with one through a higher serial, conditional on the `through` held being lower. Once it is written, every call naming the address answers `410` whatever is left of the record, so what is left is never served. Only a process whose memory holds the address deletes what is left, one delete of an address in flight at a time: its messages while memory shows the mailbox holding some, and a record left beside the revocation by a delete that failed or a registration that raced it. Elsewhere a revocation sent again loads nothing and changes nothing: the messages go at their expiry and the record by its TTL, and deleting the record there would leave the messages where no load reads them, since a load reads an address's messages only while its record is left.

**Expiry, and what it costs:**
- **The item's `expires_at` is the authority on expiry.** The bucket's lifecycle rule is not exact (general purpose buckets round to the next midnight UTC; directory buckets' timing was not checked), so an object can outlive its item, and no body is served whose item is gone. A live item whose body is gone, by a half-finished ack, a post that raced an ack of the same bytes or a lifecycle rule that ran early, leaves the list and is answered `no_such_message`.
- 🔴 **Lifecycle on a directory bucket needs a bucket policy** granting `lifecycle.s3.amazonaws.com` `s3express:CreateSession` with `s3express:SessionMode` = `ReadWrite`; without it, nothing expires (AWS docs, *Working with S3 Lifecycle for directory buckets*). `dromas-server` reaches objects through `s3express:CreateSession` too, not `s3:PutObject`.
- **A message costs** one S3 Express PUT; the send's item write 2 write units (the item, 155 B measured, and its LSI entry), the ack's 2 more (the item's delete and the LSI entry's removal), and the dedupe read 1 read. The item is kept small because DynamoDB bills a Query by the full size of each item read, projection or not (AWS docs). The LSI adds about $0.63 per million messages, at the on-demand price in AWS's offer file dated 2026-09-11.
- **A mailbox's item collection is capped at 10 GB** (every LSI's rule: its items and their index entries), and it is one partition's. An acked message leaves nothing in it; one never acked leaves its item for `protocol.Retention`, the TTL less an hour and two minutes, and then until the TTL deletes it: expired items "might be deleted by the system at any time, typically within a few days after their expiration", and AWS states no bound past that (*Using time to live (TTL) in DynamoDB*, read 2026-10-26). A message's item is 155 B, with an entry in the live index of 120 B (`TestCostItemSizes`, measured 2026-10-27); AWS counts 100 B of overhead in an index entry's space (*Local secondary indexes*), and whether an item's 100 B of storage overhead counts toward the cap, it does not say. **What bounds a mailbox's new messages is the ceiling, `ReceiveCeiling`, past which no account and no flag lifts it** (`LIMITS.md`). Unacked, a mailbox holds at most `--mailbox-cap` messages, and `--mailbox-cap` at 0 is off: then, with nothing acked, one `protocol.Retention` of a mailbox's messages at the ceiling comes to about 1.7 GB of items and entries by their sizes alone, and to about 2.9 GB with the overhead (computed). **So the margin rests on no bound of the TTL's lateness, since AWS states none: it rests on the alert AWS advises at 8 GB** (below). A write past the cap fails with `ItemCollectionSizeLimitExceededException`. Each message write asks DynamoDB for the estimated size of its mailbox's item collection (`ReturnItemCollectionMetrics`), which `dromas_server_item_collection_estimate_bytes` reports, for the alert AWS advises at 8 GB (§ Metrics).

**Bodies are not compressed.** They are age ciphertext, which doesn't compress. Measured with age 1.3.2, best of gzip -9, zstd -19 and xz -9, on messages without padding or the signature inside (measured 2026-10-10; today's sizes differ, what compresses does not):

| Message | Stored | Best compressed |
|---|---|---|
| 1 KiB of text, PQ | 2,919 B | 2,732 B (−6%; only the PQ header's base64 shrinks) |
| 14 KB of text, PQ | 15,895 B | 15,872 B (−0.1%) |

- That saves about $0.001 per million messages.
- Compressing in the client before encrypting would fit more text under the cap. It also leaks content through ciphertext length when an attacker can put text in the same message (the CRIME/BREACH class), so it isn't proposed.

## Clients: the reference implementations

**All of them live in the public `dromas-client` repo** (§ Repo layout): the Go library and the `dromas` command; the echo mailbox, a deployment of it; and `sh/dromas.sh`, the proof that a mailbox of stock tools exchanges messages with a Go mailbox, on a mailbox of its own. A mailbox's files are at the top of that repo's `client/doc.go`, what each command does is its help, and the rules for changing them are its `AGENTS.md`. **Not built:** `dromas mcp`, a local stdio MCP server in the same binary, whose results are to be the CLI's lines, and an Agent Skill (`SKILL.md`).

**What tests what.** The forging-operator tests are public, in `dromas-client`: the Go client against `internal/fakeserver`, an honest in-memory server a middleware turns hostile, and the script, by Go tests in `sh/`, against the same fake and the test vectors. This repo keeps the tests of what the real server enforces, and `dromas-server serve --dev`, the real server's logic and its memory on the in-memory backend, with no AWS, is what `test/interop.sh` runs both clients against.

## Repo layout: two repos

**The client side is [`dromas-dev/dromas-client`](https://github.com/dromas-dev/dromas-client), Apache-2.0.** Everything a user has to trust lives there; `dromas-server` needs no trust. **`dromas-server` is this repo, Apache-2.0 too.**

```
dromas-client
  protocol/           identity document, address, certificate, prekey statement, pass, envelope, namespaces, error codes
  sshsig/             SSHSIG sign/verify on x/crypto/ssh, since no first-party Go one exists
  client/             the Go client library
  cmd/dromas/       the client: the CLI (`mcp` is not built)
  cmd/dromas-echo/  the echo mailbox
  sh/dromas.sh      the proof in stock tools
  testdata/vectors/   conformance

dromas-server (this repo)
  cmd/dromas-server/      the process; imports protocol/ and sshsig/ from dromas-client
  internal/server/    api (net/http routing, problem+json) · index (layer 1) · feed (stream follower) ·
                      store (memory, over a backend: DynamoDB + S3 Express, or in-process maps) · limits ·
                      the pass check · adopt keys
  design docs, test/, bench/
```

- **`dromas-server` depends on the client repo, never the reverse.** The protocol code exists once, in public, so `dromas-server` checks exactly what anyone can read.
- **The Go module path is `github.com/dromas-dev/dromas-client`.** Installing never depends on the dromas.dev server system.
- **Dependencies:** `filippo.io/age` ≥ 1.3 (PQ) and `golang.org/x/crypto/ssh` on both sides; `dromas-server` also links `aws-sdk-go-v2` (DynamoDB, DynamoDB Streams, S3 with directory buckets) with its `aws/smithy-go`, `prometheus/client_golang` (§ Metrics) and `golang.org/x/sync` (`singleflight`), and the client `spf13/cobra` and `spf13/pflag` (its CLI), `go.etcd.io/bbolt` (a mailbox's state) and `filippo.io/edwards25519`. Each repo's `go.mod` is the whole list (`go list -deps` gives what a command links).
- **Versions: no pins beyond what Go itself records, on either side.** `go.mod` versions are minimums and `go.sum` is checked against the Go checksum database; that is the whole record.
  - **The client** (the reference): its `go.mod` moves to the latest by routine COMMITTED updates, so every build from a commit, and every `go install …@latest`, gets them. Never `go get -u` inside a build: the result would match no commit.
  - **`dromas-server`**: Go's own guidance (go.dev/doc/security/best-practices, read 2026-10-10): keep Go and the dependencies up to date, review and test each update, scan with `govulncheck`, run `go vet`, fuzz, and use the race detector. So updates land routinely, as commits that pass the tests, never silently at deploy. `go.mod` requires a release of `dromas-client`; to work on both, a `go.work` over the two checkouts builds this repo against the client's.

## Deployment stages

| Stage | Shape |
|---|---|
| Dev | `dromas-server serve --dev`, the in-memory backend |
| 1: first production (**live**, with the echo mailbox) | one host: a reverse proxy terminating TLS, one `dromas-server` with the stream on, and the echo mailbox beside it |
| 2: availability and scale | first a second host for availability, then 2–4 hosts across AZs, one `dromas-server` each using every core (e.g. 4 hosts of 4 cores), behind a load balancer |
| Later, only if measured | our own stream bouncer for more than ~4 processes; Redis if sub-second delivery or exact global limits are ever needed |
| Extreme | shard by the address's first hex character at the edge, with the bouncer routing by the same character (§ Extreme scale) |

## Build order

1. ✅ **The decisions that change code, and this sketch: applied to the spec.**
2. ✅ **`protocol` and `sshsig`, with test vectors made by stock tools.**
3. ✅ **`dromas-server --dev`, the `client` library and the `dromas` CLI**, end to end on one machine. The decided paths only; what is still open is unbuilt or chosen provisionally.
4. ✅ **The DynamoDB + S3 Express store, the stream follower and layer 1**, with the poll path answered from memory (lazy per mailbox, § Startup). Every test of `dromas-server` runs on both backends, under the one memory (the AWS ones against tables kept for tests), and the failure injected between each pair of writes is tested. Deployed as stage 1: one process, `Dockerfile` here.
5. **`dromas.sh` in the public repo, named in `llms.txt`** — built, with its forging tests (Go tests in `sh/` on the client's fake server), held to the Go client only on the vectors that are the proof and on the five outcomes a difference could let through (the client repo's `AGENTS.md` § The shell client), and interop with the Go client, all in dromas-client.
6. **`dromas mcp` and `SKILL.md`.** The echo mailbox is built and live.
7. **Layer 2 with its byte budget, stream-fed global limits, readiness gating, and a second process.** That's stage 2, and with the second process a send's read of its recipient after its write (§ Storage) becomes strongly consistent, and a send refused at its counts reads the dedupe again strongly consistent: the posts of one ciphertext in flight are one call only within a process.

## Open

- **The default budget for layer 2.** Proposed: on, with a byte budget; 0 means counts only.
- **Limits and resident state:**
  - per-process shares plus edge rules for the per-IP limits;
  - eviction of a mailbox nothing uses: the index holds a loaded mailbox until the process restarts or its record is deleted.
- **The readiness threshold:** 30 s of stream lag, proposed.
- **The legal posture** of an operator that holds only ciphertext.

## Estimates and measurements

- **Estimates:**
  - ~1–2 s stream propagation;
  - ~50 B per mark, measured, and ~100 B per listed message;
  - ~4 read units per page Query;
  - ~300 lines of shard following.
- **Measured:** the poll cost (33 to 34 µs with a pass `dromas-server` remembers, over loopback HTTP on one core, access log included, measured 2026-10-13: `bench/README.md`), a new pass's check (about 180 µs), memory per mailbox, and the compression table. The poll's figure is of an access line redacted segment by segment, 0.5 µs; the access line as built, each log line redacted whole with a regexp and the path quoted, measures 3.3 µs alone (measured 2026-10-20), and the poll has not been measured with it.
- **From AWS docs, read 2026-10-10:** the stream guarantees and the two-reader advice.
