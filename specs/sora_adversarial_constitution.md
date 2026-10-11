# SORA Adversarial Constitution

Status: design draft v0.4

Last revised: 2026-10-05

This document defines a self-contained game-theoretic frame for SORA as an
opt-in network state. It treats SORA as a set of games among self-interested
actors, not as a community that depends on moral appeals. Its purpose is to
make production safer and more profitable than capture.

The core thesis is:

> SORA makes building cheaper than capture.

SORA should not be designed for honest citizens only. It should be designed so
that selfish citizens, producers, auditors, experts, and capital providers find
it safer and more profitable to build within the system than to capture it.

## 0. Scope and Maturity

This constitution separates implemented behavior from target design and open
research. A mechanism must not be used as a security assumption before it is
implemented, tested, audited, and activated.

| Label | Meaning |
|---|---|
| Implemented | Present in the current SORA/Iroha runtime and covered by tests |
| Specified | Normative target defined here, but not necessarily implemented |
| Research | Promising mechanism whose security or implementation remains open |
| Rejected | Design that conflicts with this constitution |

Current maturity snapshot:

| Mechanism | Maturity |
|---|---|
| Attempt-local multibody Parliament reducer and certificates | Implemented |
| Future threshold-beacon, domain-separated citizen sortition | Implemented |
| XOR purchasing-power target and reserve balance sheet | Specified |
| Phoenix Capital Certificates | Specified |
| Producer Credit Facilities | Specified |
| Risk-tiered governance lanes | Specified |
| Anonymous on-chain jury ballots (public votes, unlinkable one-use authorization) | Specified |
| Epoch-seated SCCP standing pause panel (pause-only, public findings) | Specified |
| Receipt-free, coercion-resistant Parliament voting | Research |
| Equal signed clear Parliament ballots | Rejected |
| Privacy-preserving uniqueness credentials | Research |
| Prediction markets for governance outcomes | Research |
| Token-weighted Parliament voting | Rejected |
| Ballot custody or delayed opening (timed-OVN, Parliament TLE, threshold, trustee or coordinator decryption) | Rejected |
| Phoenix as XOR reserve collateral | Rejected |
| Unbacked XOR rewards or guaranteed Phoenix APY | Rejected |

Anonymous on-chain jury ballots are not the rejected equal signed clear
ballots. Both publish vote values. A signed clear ballot ties each vote to a
juror's account, giving bribers a public receipt for every juror and
retaliators a target list. An anonymous ballot is authorized only by a one-use
nullifier and a zero-knowledge membership proof and carries no account
identifier, so no published record links it to a seated juror beyond what the
public votes, counts, committee size, network metadata, and the juror's own
disclosures reveal. Neither is receipt-free. The
[ballot design](./parliament_private_ballot_design.md) is normative for the
binding-jury ballot.

The current governance implementation is described in
[`governance_pipeline.md`](./governance_pipeline.md). Where it differs from this
document, the implemented behavior is authoritative until a separately
reviewed upgrade is enacted. That rule does not keep retired mechanisms alive:
the timed-OVN and Parliament TLE ballot path still in source is scheduled for
removal, is not a fallback, and no mainnet binding decision may rely on it. Binding Policy and
Confirmation juries have no qualified ballot until the anonymous on-chain ballot
is implemented, tested, audited, and activated.

## 1. Constitutional Axioms

### 1.1 Cost Curves Over Purity

SORA does not assume corruption, collusion, bribery, Sybil farming, or rent
seeking can be eliminated. It assumes they will be attempted constantly.

The goal is to make every capture path:

- slower;
- more expensive;
- more visible;
- easier to challenge;
- easier to reverse;
- less profitable than production.

The target is not a pure system. The target is a hostile environment for
capture.

### 1.2 Productive Self-Interest

SORA does not ask people to be altruistic. It routes ambition, greed, status
seeking, security seeking, and capital accumulation into useful work:

- production;
- infrastructure;
- trade;
- auditing;
- expert analysis;
- liquidity and reserves;
- public works;
- temporary governance service.

The system should make the dominant strategy for ambitious actors to become
producers, builders, auditors, and temporary public servants, not permanent
rentiers.

### 1.3 No One Owns the Game Board

People can win games inside SORA. They can become rich, respected, influential,
and useful. They cannot turn wealth, expertise, tenure, family, early entry, or
temporary office into permanent sovereignty.

SORA should permit temporary earned advantage. It should reject permanent power.

## 2. Mandatory Design Test

Every grant, protocol upgrade, governance reform, treasury program, Phoenix
issuance rule, public-works proposal, or monetary-policy change must answer
three questions:

```text
1. Does this make production more attractive than extraction?
2. Does this make capture more expensive, slower, or easier to reverse?
3. Does this create permanent power, or only temporary earned advantage?
```

If the answers are weak, the proposal should be treated as a likely rent path.

A useful cultural warning label:

> A future rent path wearing nice clothes.

## 3. Core Assets and Power Separation

SORA separates money, risk capital, credit allocation, and governance. No
instrument may silently acquire rights from another layer.

### 3.1 XOR: Senior Money

XOR is the senior money and unit-of-account layer. It targets a governed SORA
purchasing-power unit derived from a transparent basket index.

The index specification must define:

- goods and services included;
- regional sampling and data providers;
- weights and quality adjustments;
- update cadence;
- outlier rejection and missing-data behavior;
- upper and lower intervention bands;
- delayed governance procedure for changing the basket.

No single oracle, market, ministry, or Parliament term may change the target.
Basket changes activate only after a review delay and must preserve a published
overlap calculation between the old and new indices. A constitutional basket
change requires proposal in one Parliament selection epoch and ratification by
an independently drawn later epoch.

When XOR trades above the upper band, the stabilization facility may issue and
sell XOR for eligible reserve assets. When XOR trades below the lower band, it
may spend liquid reserves to buy and retire XOR. Intervention size, price
limits, and per-period loss limits are fixed by policy before the market moves.

XOR does not promise unlimited appreciation. Any redemption facility, if one
exists, must state its eligible counterparties, price, capacity, queue, and
suspension rules explicitly. Stability must never be implied from an undefined
redemption promise.

XOR balances do not grant extra Parliament votes.

### 3.2 Phoenix: Subordinated Capital Certificates

Phoenix is not a second currency and not a perpetual farming token. Phoenix is
a family of term-dated, series-specific subordinated capital certificates, for
example `PHX-2032-A`.

A Phoenix series is created through a published offering with:

- a hard issuance cap;
- an entry price denominated in XOR or eligible external reserve assets;
- a defined term and final review date;
- an identified surplus source, payment priority, and fixed maximum share;
- a maximum cumulative payout multiple;
- no guaranteed principal redemption;
- no guaranteed payout or APY;
- no Parliament voting rights;
- explicit loss, transfer, and buyback rules.

Each series declares exactly one use of proceeds:

- **Stabilization series:** entry XOR is retired, reducing senior XOR
  liabilities; eligible external assets enter the declared reserve tier.
- **Producer-credit series:** entry XOR enters a segregated credit pool and is
  disbursed under that facility's mandate without increasing XOR supply;
  eligible external assets are converted or held under the published FX and
  custody policy.

The certificate is a claim on the series' defined future residual surplus, not
a receipt redeemable for the entry principal. A producer-credit series is
capitalized by the contributed assets, while its resulting producer loans are
valued separately under Tier 2 or Tier 3 haircuts. The Phoenix certificate
itself is never an asset of the system.

Phoenix may be transferable on a secondary market, but the protocol provides
no demand redemption before maturity. A secondary-market price decline must
not create an XOR reserve outflow.

Phoenix is never:

- counted as a reserve asset backing XOR;
- accepted as collateral for minting or borrowing XOR;
- cross-collateralized with the stabilization facility;
- convertible into governance power;
- paid from unrealized asset gains or new unbacked XOR issuance.

A Phoenix series receives value only through its stated share of realized
surplus. It can receive zero payout and expire worthless. This is the
first-loss property: Phoenix holders lose expected upside before XOR's monetary
rules are relaxed.

Optional treasury buybacks may occur only in the Green reserve regime, from
already distributable surplus, under precommitted auction rules.

An on-chain encumbrance registry records every outstanding claim on each
surplus source. A new series is invalid if its maximum claim would cause the
aggregate pledged share or payment priority to exceed the constitutional cap.
Governance cannot sell the same future revenue twice or dilute an existing
series through a later issuance.

### 3.3 Parliament

Parliament is the governance-service layer.

Design intent:

- equal-citizen sortition;
- temporary service;
- no permanent seats;
- no extra votes from extra XOR or Phoenix;
- authority-authenticated public findings for nonbinding public bodies;
- anonymous on-chain ballots for the binding Policy and Confirmation juries:
  each citizen registers a seat credential, fresh for each body and authorizing
  at most one ballot, on accepting a seat; the
  committee's credentials are frozen into a root before casting, and a ballot
  is a public vote, a nullifier, and a post-quantum zero-knowledge proof of
  membership bound to the network, proposal, attempt, body, and committee root;
- any relayer may submit a ballot; relaying confers no authority and cannot
  alter a proof-bound vote;
- vote values, exact counts, and the running tally are public; ballots contain
  no direct account identifier, and credential unlinkability depends on the
  qualified proof profile and remains limited by public information, auxiliary
  knowledge, credential disclosure, endpoint compromise, and network metadata
  (ballot design section 4);
- validators only produce blocks: in the ballot process they provide no secret
  custody, opening, or tally service; ordinary block execution verifies ballots,
  maintains public counts, and derives the result;
- no ballot custodian of any kind: the protocol neither requires nor
  distributes any voter's credential secret, or equivalent impersonation,
  opening, or recovery material, to a validator, trustee, juror, relayer,
  coordinator, or time-lock holder;
- anyone can recompute the tally and produce outcome evidence from finalized
  block data;
- no signed clear-ballot, manual-opening, or fallback electorate path;
- no claim that anonymous ballots are receipt-free or coercion-resistant: a
  juror who discloses their credential secret can prove or sell their vote;
  those stronger properties remain research and require a separately reviewed
  protocol change;
- challenge windows and delayed enactment for high-risk actions;
- accountability through bonds, clawbacks, public records, and later review.

Parliament power is borrowed. It is not owned.

## 4. XOR Balance Sheet and Reserve Regimes

SORA must distinguish liquidity from solvency. A productive loan can be sound
and still be unusable against a withdrawal today.

### 4.1 Balance-Sheet Classes

Liabilities include:

- circulating XOR;
- XOR that is immediately redeemable under an explicit facility;
- accrued but unpaid senior operating or settlement obligations;
- committed milestone disbursements not already held in segregated escrow.

Assets are classified by liquidity and risk:

| Tier | Assets | Maximum constitutional role |
|---|---|---|
| Tier 1 | Cash, short-duration FX reserves, and immediately realizable low-risk assets | Intervention and short-term outflows |
| Tier 2 | Short-dated diversified receivables with observable repayment | Limited liquidity buffer after haircut |
| Tier 3 | Productive loans, infrastructure claims, and long-duration investments | Solvency only, with severe haircuts |
| Excluded | XOR, Phoenix, governance reputation, unrealized protocol goodwill | Never counted as backing |

Each asset class requires a published valuation source, haircut, concentration
limit, maturity bucket, and liquidation assumption.

### 4.2 Coverage Tests

At minimum, the protocol calculates:

```text
liquidity_coverage =
  tier_1_liquid_value / stressed_short_term_net_outflows

solvency_coverage =
  total_haircut_asset_value / total_senior_xor_liabilities

realized_surplus =
  realized_fees
  + realized_seigniorage
  + cash_interest_and_realized_investment_income
  - operating_and_security_costs
  - realized_losses
  - expected_loss_provision
  - required_reserve_top_up
```

`realized_seigniorage` means issuance proceeds remaining only after the full
required backing for newly issued senior XOR and issuance costs are reserved.
Loan-principal repayment improves liquidity and replaces a receivable with
cash; it is not income and is not distributable surplus.

Unrealized Phoenix value, unrealized productive-asset appreciation, and
expected future fees are not distributable surplus.

### 4.3 Reserve Regimes

Regimes depend on both coverage tests, oracle health, and market liquidity.
They use hysteresis and minimum dwell periods so a single observation cannot
flip the state repeatedly.

| Regime | Entry condition | Phoenix | New producer credit | XOR stabilization |
|---|---|---|---|---|
| Green | Both coverage tests exceed policy buffers | Series payouts and buybacks may occur | Normal risk budgets | Two-sided operations |
| Yellow | A buffer is breached but minimum coverage remains | Payouts reduced or deferred | Tighter underwriting and lower caps | Reserve accumulation prioritized |
| Red | Minimum liquidity or solvency coverage is breached | No payouts or protocol buybacks | New commitments paused except protected completions | Tier 1 reserves defend XOR within loss limits |
| Black | Recovery plan triggered or senior impairment is plausible | Certificates may expire worthless; new recapitalization series may be offered | Only resolution funding | Emergency containment and governed recovery |

Already committed producer milestones must be prefunded into segregated escrow
before a pool enters Yellow or Red. The protocol must not promise a milestone
and later divert its cash to monetary defense.

No Phoenix payout occurs from unbacked issuance. If a reward is not funded by
realized surplus, it is inflation.

### 4.4 Cash-Flow Waterfall

Realized cash enters the following order:

1. Settlement finality and essential operating/security costs.
2. Contractually committed senior XOR obligations.
3. Expected-loss provisions and reserve-buffer restoration.
4. Prefunded producer milestones and approved restructurings.
5. Phoenix series payouts under their published terms.
6. New public investment and commons allocations.

Parliament may change future policy parameters, but it cannot reorder an
already issued series or retroactively subordinate senior claims.

## 5. Actor Model

SORA assumes actors are self-interested and often collusive. A rough heuristic
for group effectiveness is:

```text
effectiveness = people + 2 * energy + 4 * coordination
```

Coordination dominates. A small, disciplined group can beat a large passive
group. This heuristic is an alarm, not a security proof. Every use must define
the population, time window, and normalized scales for people, energy, and
coordination.

| Actor | Wants | Likely Strategy | Capture Risk | Productive Path |
|---|---|---|---|---|
| Early capital | upside, liquidity, status, exit options | lock capital if Phoenix upside is credible | convert capital into influence | fund reserves, liquidity, and production |
| Producers | credit, customers, imports, profit | seek subsidies and demand | fake output or lobby for protection | create goods, services, jobs, exports |
| Builders | mission, status, architecture influence | build core systems and narratives | become founder priesthood | create durable public infrastructure |
| Citizens | security, belonging, status, opportunity | hold XOR, serve when drawn | passive dividend rent seeking | temporary governance and public service |
| Auditors | fees, reputation, power | inspect grants, proposals, and fraud | extortion or shirking | adversarial truth discovery |
| Experts | status, accuracy rewards, influence | write briefs and forecasts | capture the information supply chain | bonded prediction and analysis |
| Phoenix holders | surplus, buybacks, upside | support growth if payouts credible | pressure short-term extraction | junior risk capital |
| Market makers | spreads, rules, liquidity | stabilize if rules are predictable | attack weak reserve rules | provide liquidity around target |
| Credit underwriters | fees, reputation, repeat mandates | select and monitor borrowers | approve cronies or hide losses | allocate capital within risk limits |
| Rent seekers | grants, titles, permanent claims | optimize metrics and committees | turn programs into entitlements | should face negative expected value |
| External speculators | profit from price movement | arbitrage, leverage, or short | profit from destabilization | reveal weak policy and provide liquidity |
| External states | compliance, control, taxes | tolerate, regulate, or attack | choke points and legal pressure | trade, lawful integration, public utility |

## 6. Threat Model and Security Limits

SORA distinguishes four attacker classes:

| Class | Objective | Primary response |
|---|---|---|
| Self-interested participant | Earn more within SORA | Incentive compatibility |
| Internal cartel | Capture grants, policy, or markets | Anti-collusion and defection mechanisms |
| Externally financed attacker | Profit from shorts, competitors, or side payments | Bounded authority, delays, and containment |
| Non-economic attacker | Disrupt for political, ideological, or military reasons | Byzantine safety, recovery, and redundancy |

Economic mechanisms can redirect the first class and raise costs for the
second. They cannot guarantee that attacks by the third or fourth class have
negative expected value because external payoffs are unobservable and may be
larger than SORA itself.

Therefore every high-risk authority must have:

- a maximum value and state-change scope per action;
- an enactment delay proportional to irreversible loss;
- independent monitoring and challenge paths;
- a tested rollback or containment procedure;
- automatic expiry for emergency authority;
- a published maximum irreversible loss if all incentives fail.

The constitutional objective is bounded damage and recovery, not a claim that
all attackers can be economically persuaded.

## 7. Core Games

### 7.1 Money Game

Players want stable savings, liquidity, and upside.

Desired equilibrium:

- XOR remains stable and useful;
- Phoenix absorbs risk and receives upside only from surplus;
- people who want safety hold XOR;
- people who want upside buy term-dated Phoenix certificates and accept loss
  risk.

Failure mode:

```text
XOR marketed as moonshot -> stabilization feels like betrayal -> holders revolt
```

Countermeasure:

```text
XOR = stable money
Phoenix = risky growth claim
```

### 7.2 Production Game

Players want capital, customers, and profit.

Desired equilibrium:

- producers earn XOR revenue and Phoenix upside by creating real goods and
  services;
- public funding follows delivered outcomes, not vanity metrics;
- fake activity has negative expected value.

Failure mode:

```text
subsidy metric becomes target -> wash activity and fake productivity
```

Countermeasure:

- sublinear subsidies;
- delayed vesting;
- clawbacks;
- diverse demand requirements;
- randomized audits;
- real third-party payments;
- export or import-substitution proofs where relevant.

### 7.3 Governance Game

Players want influence, status, and protection.

Desired equilibrium:

- governance is temporary service;
- citizens can rise into governance through sortition;
- wealth cannot buy sovereignty;
- public bodies publish authority-authenticated findings while binding juries
  cast attempt-bound anonymous on-chain ballots with public votes and a public
  tally;
- ballots contain no direct account identifier, and no custodian receives
  another voter's credential material; unlinkability is limited as stated in
  the ballot design section 4;
- the future research target prevents jurors from giving bribers transferable
  proof without adding a ballot custodian or weakening attempt binding.

Failure mode:

```text
capital -> governance capture -> extractive rents -> collapse of trust
visible running tally -> bribe only the final margin -> cheap capture
```

Countermeasure:

- Phoenix has no votes;
- equal-citizen sortition;
- no permanent seats;
- anonymous ballots with no ballot custodian and no validator role beyond block
  production;
- fixed casting deadlines and one immutable ballot per credential and attempt;
- receipt-free ballots after the research design is implemented and audited;
- challenge windows;
- bonded minority escalations;
- defection bounties.

### 7.4 Expert Game

Players want influence and reputation.

Desired equilibrium:

- experts compete to be accurate;
- jurors see adversarial briefs, not a single official narrative;
- experts gain reputation by being right under adversarial review.

Failure mode:

```text
experts become priesthood -> citizens rubber-stamp captured framing
```

Countermeasure:

- anyone may submit a brief under a bounded bond, with bond assistance for
  qualified capital-poor authors;
- factual briefs include calibrated probabilities and falsifiable predictions;
- normative arguments are labeled separately and are not scored as forecasts;
- red-team briefs are required for high-risk proposals;
- fraud and material misrepresentation can be challenged and slashed;
- forecast authors gain or lose calibration reputation under a proper scoring
  rule rather than being punished merely because an uncertain event occurred.

### 7.5 Identity Game

Players want eligibility and influence while remaining pseudonymous.

Desired equilibrium:

- anonymous citizens can enter and rise;
- instant Sybil capture is expensive;
- high-risk governance requires durable pseudonymous history and social risk.

Failure mode:

```text
AI agents and capital farm aged accounts until sortition capture becomes likely
```

Countermeasure:

- persistent pseudonyms;
- aged bonds;
- service history;
- reputation decay;
- no consecutive high-risk service;
- random duty timing;
- limited-liability slashed vouching;
- trust-cluster rate limits;
- independent entry paths and newcomer seats;
- optional privacy-preserving uniqueness credentials.

## 8. Anti-Collusion Mechanisms

### 8.1 Receipt-Free Voting

Anonymous voting is not enough. Bribers must be unable to verify compliance.

Anonymous on-chain ballots contain no direct account identifier, but they are
not receipt-free, and their unlinkability is limited by public information,
auxiliary knowledge, credential disclosure, endpoint compromise, and network
metadata. A juror who reveals their credential secret lets a briber
recompute the nullifier and read the matching public vote; a juror who hands
over the secret lets the briber cast the ballot. A public running tally also
lets a briber watch the aggregate effect.

Receipt-free voting is a research target, not current behavior. A candidate
design should provide MACI-like properties without MACI's decrypting
coordinator or any other ballot custodian:

- voters can change votes;
- later valid messages override earlier coerced messages;
- voters can rotate credentials;
- voters can present decoy keys or fake credentials;
- a coercer cannot tell which public vote, if any, is the voter's effective
  vote;
- vote windows allow recovery from coercion.

The goal:

> A juror can safely lie to a briber.

If a briber cannot verify the vote, bribery becomes harder to enforce.

Receipt-freeness does not solve endpoint compromise, physical coercion,
voluntary key or credential transfer, malware, or every form of screen sharing. Before
activation, the protocol requires an explicit coercion threat model, client
security review, recovery tests, and a stated residual-risk bound.

### 8.2 Whistleblower and Defection Bounties

Collusion is strongest when cartel members can trust each other. SORA should
make cartel trust unstable.

For bribery, fake productivity, auditor capture, expert capture, and Sybil
clusters, the first credible defector may receive a bounded reward after an
independent evidence process.

A bounty cannot be guaranteed to exceed unknown off-chain bribes or external
short positions. Its purpose is to destabilize internal cartels without
creating an unlimited treasury liability.

One possible bound is:

```text
verified_bounty = min(
  bounty_cap,
  seized_collateral + beta * independently_verified_loss_avoided
)
```

Funding sources may include:

- slashed briber bonds;
- slashed colluder bonds;
- fraud insurance fund;
- treasury security budget.

Claims require evidence that could not have been profitably manufactured by the
claimant. Self-created bribe offers, duplicate reports, and collusive bounty
farming are rejected or penalized. The first-report advantage, immunity terms,
appeal process, and maximum treasury contribution are fixed in advance.

### 8.3 Dark DAO Resistance

A Dark DAO is a trustless collusion contract that pays bribes and enforces
commitments through collateral. SORA cannot assume bribers are informal.

Countermeasures:

- anonymous ballots that contain no direct account identifier;
- research receipt-free voting, vote override, and credential rotation without
  a ballot custodian;
- bounded whistleblower bounties;
- delayed enactment;
- rollback and challenge paths;
- high penalties for exposed coordination.

The goal is to reduce enforceability and contain damage. SORA does not claim it
can make every Dark DAO negative-EV when attackers have unobservable external
capital or non-economic objectives. Anonymous ballots alone do not defeat a Dark
DAO that takes custody of jurors' credential secrets or requires casting inside
hardware it attests.

## 9. Producer Finance and Productive Funding

Retrospective rewards alone cannot finance producers who need inputs, payroll,
or equipment before output exists. SORA therefore uses Producer Credit
Facilities for recoverable finance and separate grant programs for public
goods whose value cannot be repaid directly.

### 9.1 Institutional Roles

| Role | Responsibility | Constraint |
|---|---|---|
| Parliament | Set facility mandate, risk budget, and concentration limits | Does not select individual borrowers |
| Facility manager | Execute the published mandate | Replaceable, bonded, and performance reviewed |
| Underwriter | Assess cash flow, counterparties, milestones, and collateral | Compensation vests over the credit life |
| Producer | Deliver output and repay under the contract | Contributes first-loss capital or a service bond |
| Senior capital provider | Fund low-risk portion of diversified pools | No governance rights from capital supplied |
| Phoenix series | Fund a defined junior risk tranche | Losses before senior pool or XOR reserves |
| Milestone attestor | Verify a narrow factual claim | Random assignment, bond, and challenge exposure |
| Auditor | Test underwriting, related parties, and evidence | Independent of approval and servicing |
| Servicer | Collect payments and execute restructurings | Cannot alter waterfall or forgive related parties alone |

Parliament governs the rules of credit allocation, not each loan. This avoids
turning routine financing into a political favor market.

### 9.2 Financing Products

Facilities may offer only products with specified evidence and resolution
paths:

| Product | Up-front use | Primary repayment source | Typical evidence |
|---|---|---|---|
| Purchase-order finance | Inputs for a committed order | Buyer payment | Buyer bond, order, delivery acceptance |
| Import finance | Foreign-currency equipment or materials | Sale of resulting output | Supplier invoice, shipment, customs or delivery proof |
| Invoice finance | Liquidity after delivery | Receivable collection | Accepted invoice and counterparty confirmation |
| Working-capital line | Inventory and payroll | Recurring operating cash flow | Sales history, inventory, payroll escrow |
| Milestone capex | Equipment and productive capacity | Project revenue | Independent milestones and asset inspection |
| Public-works contract | Shared infrastructure | Budgeted public payment | Reverse auction, completion evidence, maintenance bond |
| Public-good grant | Non-excludable benefit | No direct repayment | Retrospective impact review and capped staged grants |

### 9.3 Funding Stack and Loss Waterfall

Each credit pool publishes its capital structure. A default absorbs losses in
this order unless a proposal defines a stricter project-specific order:

1. Producer equity, retained payment, or performance bond.
2. Project-specific guarantor or buyer bond.
3. Project or facility Phoenix junior tranche.
4. Facility insurance and accumulated loss reserve.
5. Senior pool capital.
6. General treasury only under an explicit, pre-funded guarantee.

XOR monetary reserves do not automatically socialize producer-credit losses.
Any treasury guarantee is priced, capped, visible in solvency coverage, and
approved before origination.

Senior capital enters a ring-fenced facility through fixed-term facility notes,
not demand deposits. Those notes have claims only on the specified pool and any
explicit pre-funded guarantee. Neither senior facility notes nor Phoenix
certificates are redeemable against the XOR monetary reserve.

### 9.4 Staged Disbursement

Up-front finance should reach the productive bottleneck without becoming an
unrestricted withdrawal.

Preferred disbursement methods:

- direct payment to independently verified suppliers;
- payroll streaming from segregated escrow;
- shipping or customs escrow for imports;
- milestone tranches released after a challenge period;
- retained final payment until acceptance and warranty conditions are met.

Every approved milestone is prefunded before work begins. Attestors verify
narrow facts, not broad political judgments. Large milestones require several
independent evidence types and at least one randomly selected verifier.

### 9.5 Underwriting and Pricing

Underwriting considers:

- repayment source and downside cash-flow scenarios;
- producer contribution and prior repayment history;
- buyer, supplier, and guarantor independence;
- related-party and circular-payment risk;
- sector, geography, maturity, and counterparty concentration;
- oracle, legal-enforcement, custody, and physical-delivery risk;
- loss given default and time to recovery.

Interest, fees, collateral, and junior-capital requirements rise with expected
loss, correlation, evidence weakness, and illiquidity. Successful repayment
lowers future financing cost, creating upward mobility through performance
rather than inherited access.

Underwriter compensation is partly deferred until repayment. Underwriters lose
their deferred compensation or bond for fraud, hidden conflicts, or material
policy violations, not merely because a properly disclosed risk defaults.

### 9.6 Default and Restructuring

Default is expected in productive finance and must not be treated as proof of
fraud.

Each product defines:

- missed-payment and covenant thresholds;
- cure and grace periods;
- temporary payment reduction rules;
- restructuring authority and voting thresholds;
- collateral realization or replacement rights;
- producer appeal and independent review;
- final write-off and loss allocation.

Restructuring should preserve a viable producer when its continuation value
exceeds liquidation value. Fraud and asset diversion follow a separate
enforcement path with clawbacks and exclusion.

### 9.7 Portfolio Limits

Facilities enforce ex ante caps for:

- one producer or control cluster;
- one buyer, supplier, guarantor, or underwriter;
- one sector, geography, currency, and maturity bucket;
- unsecured and weak-evidence exposures;
- related-party transactions;
- total treasury-guaranteed loss.

Limits tighten automatically in Yellow and Red reserve regimes. Originators
cannot evade limits by splitting one economic exposure across pseudonyms.
Control-cluster findings are challengeable and privacy-preserving where
possible, but unresolved identity correlation receives the more conservative
capital treatment.

### 9.8 Grants, Subsidies, and Fake Activity

Grants supplement credit where repayment cannot capture the public benefit.
They do not replace working-capital finance.

Every subsidy formula asks:

```text
If a cartel fakes this metric with circular activity, does it lose money?
```

A base constraint is:

```text
subsidy <= independently_observed_value_signal * conservative_haircut
```

Use sublinear matching, delayed vesting, counterparty diversity, randomized
audits, and clawbacks. Do not subsidize raw transactions, signups, page views,
or self-reported activity.

Prefer repeat independent buyers, external revenue, delivery proofs, repayment
history, export receipts, import substitution, and maintained public
infrastructure. A negative-EV fake-activity test is necessary but not
sufficient: externally financed attackers may accept a loss, so each program
also has a hard maximum extraction and reversible payout schedule.

## 10. Auditing and Physical-World Evidence

Auditors are also self-interested actors. They may shirk, extort, collude, or
be captured.

Audit design should include:

- randomly assigned audit panels;
- second-opinion audits for large grants;
- auditor bonds;
- slashing for provable fraud;
- rewards for finding auditor corruption;
- public audit trails;
- producer appeal rights;
- rotation of audit pools;
- separation between approving auditors and investigating auditors.

Auditing should be an adversarial market, not a priesthood.

Real production cannot be proven by cryptography alone. Physical delivery,
asset ownership, legal claims, customs events, and buyer acceptance require
accountable off-chain institutions. Evidence should combine independent
sources such as suppliers, buyers, insurers, custodians, local inspectors, and
legal registries. No single attestor should both create and approve the same
claim.

Auditors are penalized for fraud, concealed conflicts, fabricated evidence, or
material policy violations. They are not automatically penalized because an
honestly assessed uncertain project later fails. This preserves incentives to
report uncertainty instead of hiding risk.

## 11. Risk-Tiered Governance

Applying the maximum process to every decision creates rational ignorance,
gridlock, and veto rents. SORA assigns each action to a risk lane before
substantive review.

| Lane | Scope | Process | Authority limit |
|---|---|---|---|
| Routine | Deterministic actions inside an existing mandate | Automatic or delegated execution with audit log | Cannot change policy or exceed mandate |
| Standard | Reversible parameter, facility, or budget changes | Bonded proposal, adversarial brief, ordinary Parliament gate, challenge window | Bounded value and rollback time |
| Constitutional | Monetary target, reserve waterfall, runtime, rights, or high irreversible loss | Full multibody Parliament, red teams, longer challenge, staged enactment | Explicit maximum irreversible loss |
| Emergency | Immediate containment of a live incident | Narrow temporary authority followed by mandatory review | Hard scope cap and automatic expiry |

The SCCP standing pause panel is an Emergency-lane body: pause-only,
epoch-seated, deciding by public findings, with automatic hold expiry (see the
[ballot design](./parliament_private_ballot_design.md) section 11).

The proposer must justify the selected lane. Underclassification is itself
challengeable. Routine and emergency authority cannot be chained to achieve a
constitutional change incrementally.

### 11.1 Constitutional Lifecycle

High-risk governance is delayed, staged, challengeable, and reversible where
possible.

An ideal lifecycle:

```text
proposal submitted
-> bonded expert briefs and red-team briefs
-> public comment and prediction market window
-> sortition roster commitment
-> future-beacon multibody sortition
-> public findings for public bodies
-> seated jurors register seat credentials; committee root frozen
-> anonymous on-chain ballots for binding juries, submitted by any relayer
-> public tally and outcome evidence from finalized block data
-> challenge window
-> canary or staged rollout
-> full enactment
-> retrospective review
-> clawback or rollback if needed
```

The binding-jury step publishes every vote value, the exact counts, and the
running tally. At most it hides which seated juror cast which ballot and
whether a given juror participated, within the limits stated in the ballot
design section 4. It is not receipt-free or coercion-resistant. A future
protocol may strengthen those properties only through an audited, explicitly
enacted change that preserves attempt binding, deterministic consensus
validation, block-production-only validators, the no-custodian rule, and the
absence of any signed clear-ballot or manual fallback.

For high-risk proposals, require:

- larger juries;
- multiple independent bodies;
- longer challenge windows;
- stronger expert red-team requirements;
- explicit rollback plan;
- an explicit maximum irreversible loss and containment plan.

## 12. Minority Delay Without Extortion

Minority escalation can protect against capture, but free delay becomes a
rent-seeking weapon.

Rules:

- minority delay requires a challenge bond;
- bond is refunded or rewarded if the challenge finds a real defect;
- bond is partially burned if frivolous;
- repeated bad-faith challengers lose escalation privileges for a period;
- critical emergency paths require higher thresholds and post-hoc review.

The goal is to make delay a truth-discovery tool, not a veto market.

### 12.1 First-Release Public Moderation Challenges

The authoritative SoraFS moderation ledger applies these deterministic rules:

- submission and resolution are separate windows, with exactly 24 hours of
  resolution grace after challenge submission closes;
- every challenge locks 150 units of the current governance voting asset in
  the configured governance bond-custody account, and the asset and custody
  destinations are snapshotted in the challenge record;
- one account may submit at most one challenge per case and duplicate evidence
  digests are rejected;
- an accepted challenge refunds the whole bond and vetoes the ballot;
- a rejected challenge sends 25% to the configured slash receiver, rounded
  toward zero at the voting asset's declared scale, and refunds the remainder;
  and
- an unresolved challenge may be expired permissionlessly after the grace,
  refunds the whole bond, and fails open. Finalization performs an idempotent
  sweep of any still-pending challenges before tallying.

These values are first-release protocol constants. Changing them requires a
new explicitly enacted schema/policy revision rather than interpreting old
records under new settings.

## 13. Phoenix Series Governance

Phoenix must attract early capital without creating a permanent rentier class.

Every series preserves the constraints in section 3.2. In addition:

- no Parliament votes;
- no continuous yield promise;
- reserve-gated payouts;
- no demand redemption or withdrawal queue;
- no cross-series claim on another series' allocation;
- no issuance that over-encumbers an already pledged surplus source;
- a published payout schedule that declines smoothly if the series uses
  time-weighted participation;
- maximum return multiples or buyout rights where appropriate;
- program-specific vintages for high-risk projects;
- transparent reserve regime and payout formula.

Series maturity ends future participation according to terms known at issuance.
Avoid a payout cliff immediately before maturity, which creates short-term
extraction pressure. Use smooth scheduled decline where appropriate:

```text
early Phoenix share high at launch
-> gradually declines as SORA matures
-> closes at its stated term or earlier maximum payout cap
```

## 14. Identity, Vouching, and Upward Mobility

Because SORA permits pseudonymity, identity cannot rely on real-world names.
The problem is Sybil resistance, not "false identity" in a legal-name sense.

Anonymous one-person-one-vote cannot be assumed without a scarce uniqueness
signal. Anonymous jury ballots do not change this: a seat credential
authorizes at most one ballot per sealed seat, not one per person.
SORA combines imperfect layers and treats unresolved correlation
conservatively:

- persistent pseudonymous citizen keys;
- aged citizenship bonds;
- service history;
- invitation-decline, public-finding absence, and misconduct records
  (binding-jury participation is never recorded per account);
- cooldowns after powerful service;
- limited-liability slashed vouching;
- cluster-level introduction limits;
- several independent trust paths for high-risk eligibility;
- expiring vouching edges and appeal rights;
- newcomer seats and bond assistance that do not give sponsors vote control;
- privacy-preserving uniqueness credentials where acceptable.

Vouching must be costly but bounded:

```text
vouch for citizen -> bond at risk
Sybil cluster proven -> direct vouchers may lose up to their published cap
```

There is no unbounded backward cascade. A sponsor cannot vote for, revoke,
direct, or hold the seat credential of the citizen it helped onboard. The design makes identity farming require
time, capital, and social-graph risk without converting established trust hubs
into hereditary gatekeepers.

## 15. Capture Path Register

| Capture Path | Attack | Countermeasure |
|---|---|---|
| Monetary run | Illiquid assets cannot meet XOR outflows | Separate liquidity and solvency tests, Tier 1 intervention reserve |
| Oracle capture | Basket or reserve valuations are manipulated | Multiple sources, delayed basket changes, outlier rules, loss caps |
| Phoenix reflexivity | Phoenix price collapse weakens XOR | Phoenix excluded from reserves and XOR collateral |
| Capital to governance | Phoenix holders buy policy | Phoenix has no votes, Parliament sortition, bounded authority |
| Expert capture | Captured experts frame choices | Bonded adversarial briefs and red teams |
| Vote bribery | Briber buys a vote | Anonymous ballots contain no direct account identifier, but a juror can prove a vote by revealing their credential secret; bounded bounties, delayed enactment; research receipt-free voting, decoy credentials, vote override |
| Key or credential sale | Briber buys a juror's private key or seat credential and casts or verifies the ballot | Body-scoped credentials authorizing at most one ballot each; research credential rotation, recovery, and decoy credentials; residual risk accepted |
| Dark DAO | Smart contract or attested hardware enforces collusion, including custody of jurors' seat credentials | Bounded bounties, research receipt-freeness, delayed enactment, damage caps |
| Tally steering | A visible running tally lets a briber buy only the final margin or trigger a bandwagon | Fixed casting deadline, no early close, one immutable ballot per credential, challenge window, delayed enactment, bounded bounties |
| Selective ballot censorship | Relayers or block proposers drop ballots by their visible vote | Any relayer may submit, resubmission until the deadline, casting windows sized past consecutive Byzantine leader slots, proposer rotation and observable finalized inclusion; no cryptographic evidence of deliberate censorship is claimed |
| Custodian creep | A reform adds a trustee, coordinator, time-lock, or validator key that can open or link ballots | No ballot custodian of any kind; validators only produce blocks; custody is Rejected in section 0 |
| Participation linkage | Submission metadata, fees, or rewards link a juror to a ballot | Signerless proof-authorized submission; no per-account voting rewards; network-metadata anonymity not claimed |
| External short attack | Attacker profits from system failure elsewhere | Authority caps, staged changes, circuit breakers, recovery |
| Sybil farming | AI agents farm citizenship | Aged bonds, limited vouching, service history, newcomer protections |
| Fake demand | Cartel circulates payments | Sublinear subsidies, haircuts, audits, clawbacks |
| Credit cronyism | Underwriters finance affiliates or hide losses | Deferred compensation, cluster limits, independent audits |
| Auditor capture | Auditors extort or shirk | Auditor bonds, second opinions, anti-auditor bounties |
| Minority extortion | Delays used as ransom | Bonded challenges and penalties for frivolous delay |
| Founder priesthood | Builders become permanent rulers | Term limits, open expert markets, no permanent seats |
| Vouching gatekeepers | Established trust hubs block entrants | Limited liability, multiple paths, expiry, appeals, newcomer seats |
| Hereditary rent | Early claims become tribute | Series caps, fixed terms, payout caps, no governance rights |

## 16. Quantitative Acceptance and Simulation

The three constitutional questions are necessary but easy to answer
rhetorically. Every material proposal therefore includes a reproducible
quantitative annex.

### 16.1 Economic Tests

- liquidity coverage before and after enactment;
- solvency coverage before and after enactment;
- stressed reserve outflow and intervention capacity;
- expected loss, unexpected-loss scenario, and loss waterfall;
- maximum exposure to one economic control cluster;
- maturity, currency, geography, and sector concentration;
- realized source of every proposed payout;
- maximum treasury and senior-XOR loss.

### 16.2 Governance Tests

- minimum internal capture budget under stated assumptions;
- externally financed and non-economic attacker scenario;
- time from malicious approval to detection and containment;
- maximum irreversible state change per action;
- expected participation cost and decision latency;
- number and independence of effective veto players;
- concentration and repeated overlap among bodies, experts, and auditors;
- ballot inference at the smallest admitted committee from public votes,
  counts, and committee size;
- relayer and proposer coalitions able to drop ballots by visible vote before
  the deadline;
- independent recomputation of the tally and outcome from finalized block data
  alone;
- per-ballot verification work and the cost of invalid-proof floods;
- confirmation that the protocol requires and distributes no voter's credential
  secret or recovery material to any other party.

### 16.3 Producer-Finance Tests

- median and tail time from application to first disbursement;
- producer cost of capital and required own contribution;
- expected default, recovery, and restructuring rates;
- senior and junior tranche loss under correlated defaults;
- subsidy leakage under circular-payment simulation;
- access rate for new producers versus established borrowers;
- percentage of funds paid directly to productive inputs.

### 16.4 Mandatory Adversarial Scenarios

At minimum, simulation covers:

- a rapid XOR run;
- correlated producer defaults;
- basket-oracle manipulation;
- Phoenix secondary-market collapse;
- a patient AI-assisted identity farm;
- expert and auditor cartels;
- a briber buying the final margin against a visible running tally;
- relayer or proposer censorship of ballots by visible vote;
- a Dark DAO collecting jurors' seat credentials;
- an attacker with a profitable external short;
- frivolous challenge flooding;
- a facility manager hiding losses through refinancing;
- failure of a major buyer, supplier, custodian, or reserve counterparty.

The proposal states model assumptions, parameter sources, uncertainty ranges,
and conditions that would falsify its safety case. Passing a model is not proof
of safety; unexplained sensitivity to small assumption changes blocks
enactment.

## 17. Proposal Template

Every formal SORA proposal should include this header.

```markdown
# Proposal Title

## Summary

What changes, who benefits, and what state transitions occur?

## Maturity and Governance Lane

- Mechanisms used: Implemented / Specified / Research
- Requested lane: Routine / Standard / Constitutional / Emergency
- Why a lower-risk lane is insufficient:
- Maximum authority and value affected:

## Production Over Extraction

Does this make production more attractive than extraction?

- Productive behavior rewarded:
- Extractive behavior made less profitable:
- Metrics that could be Goodharted:
- Fake-activity cost analysis:

## Capture Cost

Does this make capture more expensive, slower, or easier to reverse?

- Capture paths introduced:
- Capture paths closed:
- Challenge window:
- Reversal or rollback path:
- Minority escalation rules:
- Maximum irreversible loss:
- External short/non-economic attacker scenario:

## Temporary Advantage

Does this create permanent power, or only temporary earned advantage?

- New privileges created:
- Expiry, decay, or review:
- Governance rights affected:
- Wealth-to-power conversion risk:

## Actor Incentives

| Actor | Expected action | Benefit | Abuse path | Countermeasure |
|---|---|---|---|---|

## Expert Briefs and Forecasts

- Required expert briefs:
- Required red-team briefs:
- Falsifiable predictions:
- Bond amount:
- Slashing conditions:

## Reserve and Phoenix Impact

- Liquidity coverage before/after:
- Solvency coverage before/after:
- Realized source of distributions:
- Phoenix series affected and contractual basis:
- Reserve regime transition risk:
- Stress behavior:

## Producer Finance Impact

- Credit facility and product:
- Funding and loss waterfall:
- Up-front or milestone disbursement:
- Underwriter and related-party exposure:
- Default/restructuring path:
- Portfolio concentration impact:

## Audit and Clawback

- Audit plan:
- Randomized audit rate:
- Clawback conditions:
- Whistleblower bounty:

## Rollout

- Canary stage:
- Full activation condition:
- Rollback plan:
- Sunset or review date:

## Quantitative Annex

- Economic tests:
- Governance tests:
- Producer-finance tests:
- Adversarial simulations:
- Assumptions and falsification conditions:
```

## 18. Implementation Phases

### Phase 0: Doctrine

- Publish this constitution.
- Require the three-question design test for governance proposals.
- Keep the maturity matrix current and distinguish implemented guarantees from
  research targets.

### Phase 1: Monetary and Credit Specification

- Specify and test the basket index, intervention band, and oracle rules.
- Implement the XOR balance sheet, coverage tests, and reserve regimes.
- Define Phoenix series issuance, accounting, payout, and termination.
- Implement a limited producer-credit pilot with prefunded milestones, direct
  supplier payments, and explicit default resolution.
- Build reproducible stress and agent-based simulation harnesses.

### Phase 2: Governance and Credit Hardening

- Implement risk-tiered governance lanes and authority caps.
- Add bonded challenge windows and rollback rehearsals.
- Add bounded whistleblower bounties and evidence adjudication.
- Add limited-liability vouching, appeals, and newcomer access.
- Implement auditor bonds and second-opinion audits.
- Implement, audit, and activate anonymous on-chain jury ballots; remove
  timed-OVN and the Parliament TLE in the same change.

### Phase 3: Anti-Collusion Research and Pilot

- Specify, prototype, and audit receipt-free extensions of the anonymous
  ballot with no decrypting coordinator or other ballot custodian.
- Test vote override, credential rotation, client compromise, and coercion
  recovery.
- Pilot calibrated expert forecasts with bond assistance.
- Measure whether the mechanisms improve decisions without excluding
  capital-poor participants.

### Phase 4: Market-Based Governance Inputs

- Bonded expert market.
- Prediction markets for proposal outcomes.
- Retroactive public goods funding.
- Sublinear matching and anti-circularity scoring.
- Public capture-risk dashboards.

### Phase 5: Full Adversarial Network State

- Mature reserve regimes.
- Phoenix series accounting, encumbrance limits, maturity, and closure.
- High-risk proposal canaries.
- Automated challenge and rollback paths.
- Continuous adversarial simulation.

## 19. Non-Goals

SORA should not promise:

- perfect trustlessness;
- zero corruption;
- identity certainty under full anonymity;
- permanent passive income;
- a moonshot XOR price;
- technocratic rule by experts;
- permanent governance by founders, whales, or early citizens;
- proof that every externally financed or non-economic attack is negative-EV;
- cryptographic proof of every physical-world event.

SORA should promise a harder thing:

> Capture is never impossible, but production should usually be cheaper.

## 20. Glossary

**Capture**: Any strategy that converts temporary advantage, capital, expertise,
or office into persistent control over SORA rules or surplus.

**Phoenix Capital Certificate**: A term-dated, series-specific subordinated
claim on defined realized surplus. It has no guaranteed principal redemption,
is excluded from XOR reserves and collateral, and grants no governance rights.

**XOR**: Senior stable-money unit intended for savings, wages, trade, credit,
and contracts.

**Sortition**: Random selection of eligible citizens for temporary governance
service.

**Receipt-free voting**: Voting design where a voter cannot prove to a briber
how they voted, even by revealing their own credentials.

**Anonymous on-chain ballot**: A Parliament jury ballot whose vote is public.
It is authorized by a one-use nullifier and a post-quantum zero-knowledge proof
of membership in the frozen committee root and carries no account identifier;
public counts, small committees, network metadata, and the juror's own
disclosures can still reveal who cast it.

**Seat credential**: A credential that a citizen registers on accepting a jury
seat and alone holds. It is fresh for each body and authorizes at most one
ballot.

**Nullifier**: A value derived from a seat credential and the ballot context.
It prevents double voting without revealing the credential.

**Ballot custodian**: Any party to which the protocol gives another voter's
credential secret, or equivalent impersonation, opening, or recovery material.
The constitution permits none.

**Outcome evidence**: Evidence of a jury result that anyone can produce from
finalized block data.

**Dark DAO**: A trustless collusion contract that attempts to enforce bribery
or cartel commitments.

**Negative-EV subsidy**: A funding rule where fake activity costs more to
produce than the subsidy it can extract.

**Slashed vouching**: A web-of-trust mechanism where endorsers risk bonds when
endorsed accounts are later proven to be part of a Sybil or fraud cluster.

**Temporary earned advantage**: A benefit earned through useful contribution
that expires, decays, vests, or remains subject to review.

**Permanent power**: A durable control right over governance, issuance, public
funding, or rule changes that persists without continuous productive
justification.

**Producer Credit Facility**: A governed pool that finances eligible productive
activity under a mandate, capital structure, underwriting policy, milestone
process, portfolio limits, and default waterfall.

**Liquidity coverage**: Tier 1 liquid reserve value divided by stressed
short-term net outflows.

**Solvency coverage**: Haircut value of eligible assets divided by senior XOR
liabilities.

## 21. Final Principle

The constitutional posture is:

> Not a trustless utopia, but a hostile environment for capture.

Every implementation detail should be judged by whether it preserves that
posture.
