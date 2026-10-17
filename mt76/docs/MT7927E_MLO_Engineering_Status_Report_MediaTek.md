```
MT7927E / FILOGIC 380
Linux mt76 Multi-Link Operation (MLO)
Engineering Status and Reverse-Engineering Report

Prepared for MediaTek engineering review
Status date: 2 September 2026
Target: MediaTek MT7927E PCIe, 802.11be, 320 MHz, 2x2
Kernel test line: Linux 7.2.0-rc1-mt7927-monitor-v3
Primary experimental tree: mt7927-t2lm-emlsr-prototype

Classification: DEVELOPMENT / VALIDATION INCOMPLETE
```

## Executive Summary

The project goal is not merely to associate an MT7927E as an MLD. The target is a production-quality Linux mt76 implementation that can maintain exactly two usable links from a three-link MLD, select the best two links from 2.4, 5 and 6 GHz according to measured link quality, and replace one active member without reassociation while the surviving member remains usable.

The project has progressed beyond basic MLO association. All three two-link combinations have individually been demonstrated usable in the experimental driver: 0x3 (2.4+5 GHz), 0x5 (2.4+6 GHz), and 0x6 (5+6 GHz). The historically broken 5+6 GHz path was traced to an MT7927 firmware BSS band-context collision and repaired sufficiently to restore the 4-way handshake and data operation. ROC lifecycle and late-link PTK/GTK/IGTK/BMC reconciliation problems were also identified and repaired in the experimental branch.

The driver must NOT yet be described as 'MLO finally works.' Static two-link operation is substantially proven; the remaining release gate is robust live pair replacement plus automatic best-two selection under sustained three-link visibility. Automatic steering code exists and its score now includes both RSSI and PHY-rate quality, but real automatic cross-pair switching has not yet been demonstrated end-to-end in a stable valid_links=0x7 window.

|Capability|Current status|Engineering meaning|

|---|---|---|

|MLD negotiation / valid_links=0x7|PROVEN achievable|Three affiliated links can be negotiated.|

|0x3 = 2.4+5|PROVEN individually usable|Both member links have been TX-verified with traffic.|

|0x5 = 2.4+6|PROVEN individually usable|Both member links have been TX-verified with traffic.|

|0x6 = 5+6|PROVEN individually usable after fixes|Historical Windows+Linux failure no longer blocks static pair use.|

|Live remove/re-add lifecycle|SUBSTANTIAL FIXES PROVEN|ROC and key reconciliation fixes survive repeated cycles.|

|Automatic best-two steering|IMPLEMENTED, NOT END-TO-END PROVEN|RSSI + PHY-rate score, hysteresis and cooldown exist; real cross-pair selection remains validation work.|

|Production readiness|NOT YET|Test-only EHT override/debug controls and incomplete automatic-transition validation remain.|

## 1. Goal and Acceptance Criteria

The desired behavior is a two-active-link MT7927E MLO station operating against a three-link AP MLD. The station should preserve the best two links and dynamically replace the weaker member as conditions change.

```
Negotiated set:
    valid_links = 0x7       # link0 | link1 | link2

Required usable pairs:
    0x3 = link0 + link1     # 2.4 GHz + 5 GHz
    0x5 = link0 + link2     # 2.4 GHz + 6 GHz
    0x6 = link1 + link2     # 5 GHz + 6 GHz

Target transition example:
    BEFORE:  0x5 = 2.4 + 6
    KEEP:    link2 / 6 GHz alive
    ADD:     link1 / 5 GHz
    VERIFY:  link1 fully programmed, keyed and traffic-capable
    REMOVE:  link0 / 2.4 GHz
    AFTER:   0x6 = 5 + 6

No reassociation, no DHCP restart, no full disconnect.
```

Final acceptance requires all of the following:

valid_links=0x7 with exactly two active links selected at a time.

0x3, 0x5 and 0x6 each usable with both member links independently capable of encrypted traffic.

All pair-to-pair transitions in both directions without reassociation: 0x3<->0x5, 0x5<->0x6, 0x6<->0x3.

Surviving link remains alive while the replacement link is prepared and promoted.

PTK, GTK/IGTK/BMC, WCID, BSS, STA_REC and ROC state remain coherent across remove/re-add.

Automatic pair choice based on real link quality, with hysteresis and cooldown preventing oscillation.

No test-only EHT capability override or debug forcing required in a production platform/BIOS.

## 2. State of the Driver Before Project Edits

MT7927E is serviced through the mt7925/mt792x shared Linux driver architecture rather than a separate mt7927 source directory. The upstream MLO capability path already contained MLD support and encoded IEEE80211_MLD_CAP_OP_MAX_SIMUL_LINKS with value 0 in mt7925/main.c. The project therefore did not begin from a non-MLO driver; it began from an incomplete/unstable MT7927 MLO lifecycle whose critical gaps appeared when exercising three negotiated links, 5+6 GHz pairing, and live link replacement.

```
Representative upstream capability path:
    mt7925_init_mlo_caps(...)
        ...
        u16_encode_bits(0, IEEE80211_MLD_CAP_OP_MAX_SIMUL_LINKS)

Shared MT7927 path:
    drivers/net/wireless/mediatek/mt76/mt7925/
    drivers/net/wireless/mediatek/mt76/mt792x*
```

mac80211/cfg80211 already supplied the higher-level active/dormant-link and T2LM infrastructure. The MT7925/MT7927 driver did not advertise negotiated T2LM support or implement can_neg_ttlm in the audited baseline. Existing firmware-facing MLO operation used the established BSS_INFO, STA_REC and ROC paths.

### 2.1 Original link lifecycle design

mac80211 owns MLD/link state and invokes mt7925_change_vif_links() / mt7925_change_sta_links().

Driver creates per-link BSS and peer STA/WCID state and programs firmware through BSS_INFO_UPDATE / STA_REC_UPDATE.

ROC is used during secondary-link preparation; MT7927 uses shared MT7925 code paths.

TX link selection uses mt76_mlo_select_wcid() and driver-side per-TID link state in the experimental implementation.

The initial design did not robustly reconcile every firmware/key object when a link was removed and later re-added.

## 3. Windows Reverse Engineering

Reverse engineering of the MT7927 Windows driver image established that the vendor stack contains explicit MLO control logic beyond what the Linux mt76 path exposed. Symbol/string evidence identified T2LM and EML query/switch logic in the Windows stack. This supports the conclusion that MT7927 hardware/firmware is designed for dynamic multi-link policy, while the exact private firmware ABI cannot be reconstructed safely from symbol names alone.

|Windows evidence|What it supports|What it does NOT prove|

|---|---|---|

|MT7927-specific Windows source-path strings and symbols|Dedicated MT7927 vendor implementation exists.|Exact firmware command layouts.|

|T2LM-related symbols / logic|Vendor stack contains traffic-to-link mapping logic.|Numeric T2LM TLV/tag and payload ABI.|

|EML query/switch symbols|Vendor stack contains EML mode control/query logic.|Station-mode STA_REC_EML_OP parameters or event format.|

|Observed 5+6 failure on Windows too|Regression boundary is not Linux-only.|That Windows and Linux fail for identical internal reason.|

|Windows DBDC-path observations|MT7927 behavior differs from MT7925/MT7921 assumptions.|That Linux band_idx is a literal physical RF-chain selector.|

The Linux prototype therefore deliberately preferred host-managed mechanisms already supported by mac80211 instead of inventing undocumented firmware commands. A proposed T2LM prototype used TID_TO_LINK_MAP_NEG_SUPP_SAME and existing active-link transitions, while leaving unknown firmware T2LM/EML ABI untouched.

## 4. Major Discoveries During Linux Investigation

### 4.1 Historical pair matrix and the 5+6 regression boundary

|Pair mask|Bands|Historical state|Current experimental state|

|---|---|---|---|

|0x3|2.4 + 5 GHz|Working|Individually usable / both links TX-verified|

|0x5|2.4 + 6 GHz|Working|Individually usable / both links TX-verified|

|0x6|5 + 6 GHz|Broken on Windows and Linux|Individually usable after band-context fix|

This boundary was important: the problem was not generic 'secondary-link activation.' 2.4+5 and 2.4+6 were historically viable, while 5+6 was the repeatable failure combination on both operating systems.

### 4.2 EHT capability was suppressed by platform MTCL data

A separate platform issue initially prevented correct EHT/MLE parsing. MT7927 detection succeeded, but mt7925_regd_be_ctrl() consumed ACPI MTCL data whose selector did not contain an MT7927 case. The resulting configuration left dev->has_eht false, so mt7925_init_eht_caps() did not populate EHT capabilities. A TEST-ONLY module override proved the remainder of the MLO path once EHT was exposed.

```
TEST-ONLY parameter:
    test_mt7927_eht_override=1

Scope:
    MT7927 only
    forces final EHT enable after normal MTCL/CLC evaluation
    does NOT change country, channels, DFS, AP, supplicant, or parser

Production requirement:
    BIOS/ACPI MTCL must provide vendor-approved MT7927 data.
    The test override is not a production fix.
```

### 4.3 Basic Multi-Link element was present; parser gating was the issue

Kernel instrumentation proved the AP's association information contained the Basic Multi-Link element even when iw did not decode it. ieee802_11_parse_elems_full() skipped the element because association mode was capped at HE when EHT capability lookup returned NULL. Restoring EHT capability allowed the same bytes to parse and valid_links=0x7 to appear.

### 4.4 5+6 BSS band-context collision

The decisive 5+6 finding was that the normal MT7927 mapping assigned both 5 GHz and 6 GHz BSS contexts band_idx=1. With a 6 GHz resident BSS at context 1, adding the 5 GHz secondary with the same context correlated with post-secondary EAPOL suppression. A narrow test changed only the secondary 5 GHz BSS context to 0; 5+6 immediately reached COMPLETED, DHCP and traffic, and independent OTA capture showed the complete four-way handshake.

```
Normal mapping observed:
    2.4 GHz -> band_idx 0
    5 GHz   -> band_idx 1
    6 GHz   -> band_idx 1

Production-candidate allocator:
    mt7927_mld_assign_band_idx()

Behavior:
    1. assign normal mt7927_band_idx(chan->band)
    2. for MT7927 station MLD BSS contexts, inspect resident BSS contexts
    3. if new context collides, assign alternate context (band_idx ^ 1)
    4. preserve resident/primary context

5+6 example:
    resident 6 GHz: band_idx=1
    new 5 GHz:      orig=1 -> new=0
```

Important semantic correction: band_idx is treated by the project as a logical firmware DBDC/MAC context slot, not as proof of a physical 2.4/5/6 RF chain. Real channel/band programming is carried separately in the RLM TLV.

### 4.5 ROC lifecycle failure

The secondary-link ROC lifecycle required MT7927-specific correction. Firmware grant->reqtype was observed to echo 0 and was not reliable for distinguishing the MLO JOIN lifecycle. The driver instead used phy->roc_mlo_links to identify MLO JOIN, preserved JOIN rather than applying the generic 5 ms timer, and used dbdcband=0xfe for MLO ROC abort.

```
Relevant concepts:
    phy->roc_mlo_links
    ROC_JOIN_PRESERVED
    MLO ROC abort: dbdcband = 0xfe

Result:
    ROC two-slot abort / lifecycle fix preserved in commit 2e593919
    repeated cycles were later reported clean.
```

### 4.6 Late-link encryption/key reconciliation

Live pair replacement exposed a second class of lifecycle defects. A link created after the original 4-way handshake could receive a valid LINK_READY peer WCID but lack the pairwise key on that newly-created traffic WCID. mac80211's PTK is per-MLD and is not guaranteed to be re-issued as a new per-link .set_key() call. Transition-time GTK/IGTK calls are group-key operations and must not be mistaken for peer PTK installation.

```
Observed failure signature:
    MLO_LINK_READY: newly added peer WCID exists
    newly added traffic WCID: hw_key_idx = 255  # no pairwise key

Investigated functions:
    mt7925_set_key()
    mt7925_set_link_key()
    mt7925_mac_sta_add_links()
    mt7925_mac_sta_remove_links()
    mt76_wcid_key_setup()
    mt7925_mcu_add_key()

Architectural reconciliation:
    mt7925_mlo_reconcile_link() / late-link reconciliation logic
    reprogram PTK and required GTK/IGTK/BMC state for a re-added link

Preserved fix commit:
    2e593919  mt7925: MLO ROC two-slot abort + late-link PTK/GTK/IGTK reconciliation
```

Earlier intermediate theories involving deflink recycling and a direct ieee80211_iter_keys() PTK rebind were useful diagnostics but were not accepted as the final statement by themselves. The final report therefore records the proven requirement—late-link key reconciliation—and the preserved reconciliation commit, not every discarded hypothesis.

## 5. What We Want to Add

The desired feature is a production steering policy that continuously evaluates the three negotiated links and maintains the best two. This is not round-robin link switching and not a hard-coded preference for 5+6 GHz.

```
Existing steering architecture:
    mt7925_mlo_steer_work()
        -> collect per-link quality
        -> score candidate pairs: 0x3, 0x5, 0x6
        -> apply hysteresis
        -> enforce cooldown
        -> ieee80211_set_active_links_async()

Existing TX-side components:
    mt76_mlo_select_wcid()
    msta->mlo_tid_link[tid]
    mt7925_mlo_force_bulk_wcid()      # diagnostic/experimental control path

Quality-score extension:
    wcid->rate
    cfg80211_calculate_bitrate(...)
    commit 2ab6c2f2
        "mt7925: extend MLO pair-steering score with link-quality term" 
```

### 5.1 Required steering policy

RSSI/signal strength must contribute to link ranking.

PHY-rate / usable-rate quality must contribute; this was added to the scorer.

Hysteresis must prevent pair changes for insignificant score differences.

Cooldown must prevent oscillation after a transition.

The transition must preserve one member whenever the old and new pairs overlap.

The replacement link must be fully programmed and keyed before it is considered usable.

No band pair should be hard-coded as universally preferred; the score must decide from current conditions.

## 6. Current State

The most defensible current state is: static two-link MLO is substantially working across all three band pairs in the experimental branch, and the major lifecycle bugs discovered so far have targeted fixes. The project is now at the final dynamic-policy validation boundary rather than the initial association boundary.

|Item|Status|Evidence / implementation|

|---|---|---|

|valid_links=0x7|PROVEN achievable|Multiple negotiated three-link sessions.|

|0x3 static pair|PROVEN|Both links individually TX-verified; ARP/traffic PASS.|

|0x5 static pair|PROVEN|Both links individually TX-verified; ARP/traffic PASS.|

|0x6 static pair|PROVEN after fix|Band-context allocator; OTA EAPOL and traffic.|

|5+6 collision|FIXED in candidate|mt7927_mld_assign_band_idx(); commits include 33864712 / 1c1a4a88 lineage.|

|ROC lifecycle|FIXED|2e593919; two-slot abort/lifecycle reconciliation.|

|Late PTK|FIXED in experimental branch|2e593919 reconciliation.|

|Late GTK/IGTK/BMC|FIXED in experimental branch|2e593919 reconciliation.|

|Steering score|IMPLEMENTED|mt7925_mlo_steer_work(); RSSI + PHY-rate term; 2ab6c2f2.|

|RSSI monitor arming|NOT demonstrated broken|MCU return 0 observed; earlier failure inference retracted.|

|Automatic cross-pair switching|NOT YET PROVEN|Stable valid_links=0x7 window not sustained long enough in final test environment.|

## 7. Hypotheses: Proven, Rejected, and Still Open

|Hypothesis|Disposition|Reason|

|---|---|---|

|5+6 fails because secondary link never negotiates|REJECTED|valid_links/active pair and secondary setup were observed; failure occurred later.|

|5+6 failure is Linux-only|REJECTED|Historical 5+6 failure existed on Windows and Linux.|

|AP does not advertise Basic ML|REJECTED|Raw association IEs contained ext_id=107 Basic ML.|

|Updated wpa_supplicant alone fixes 5+6|REJECTED|Real 0x6 still reproduced failure before driver context fix.|

|ROC generic timeout is root cause|REJECTED after ROC fix|JOIN preservation corrected lifecycle; 5+6 required additional context work.|

|band_idx=0 literally means 2.4 GHz physical RF|REJECTED|band_idx is logical firmware context; RLM carries real operating band/channel separately.|

|5+6 BSS context collision is causal to EAPOL suppression|SUPPORTED / acted on|Changing only secondary context restored handshake; allocator reproduced success.|

|Late-added link can be keyless after original MLD PTK negotiation|SUPPORTED / fixed|hw_key_idx=255 observed on re-added traffic WCID; reconciliation implemented.|

|Automatic steering algorithm is absent|REJECTED|mt7925_mlo_steer_work(), pair scoring, hysteresis, cooldown and async link changes exist.|

|Automatic best-two steering is fully validated|NOT PROVEN|Real quality-triggered cross-pair transition has not completed the final validation matrix.|

|Inactive third-link RSSI monitor firmware call fails|NOT PROVEN|Absence of samples was initially over-interpreted; later MCU return=0 evidence required retraction.|

## 8. Critical Issues Before Saying 'MLO Finally Works'

Complete the full static pair matrix on a production-candidate build, with both member links independently verified for encrypted traffic in 0x3, 0x5 and 0x6.

Complete all six live pair transitions without reassociation: 0x3->0x5, 0x5->0x6, 0x6->0x3 and the three reverse directions.

For every transition, prove the surviving link remains usable while the replacement link receives correct BSS, STA_REC, WCID, PTK, GTK/IGTK/BMC and ROC state.

Demonstrate automatic cross-pair steering from real quality changes rather than debugfs pair forcing.

Sustain valid_links=0x7 long enough to sample all three links in one decision window and calculate all candidate-pair scores.

Verify the quality policy with recorded RSSI and PHY-rate inputs, calculated pair scores, hysteresis threshold and cooldown behavior.

Verify traffic continuity during automatic replacement: no reassociation, no DHCP restart, no full disconnect, and no unacceptable blackout.

Remove or isolate test-only controls from the production patch: test_mt7927_eht_override, pair forcing/debugfs controls and verbose diagnostic printk/trace code.

Resolve the platform MTCL/ACPI MT7927 EHT capability issue in BIOS/firmware or through a vendor-approved production mechanism; do not ship the lab EHT override as the solution.

Run regression testing for roam, suspend/resume, teardown, repeated transitions, link loss and failure rollback before upstream submission.

## 9. Engineering Validation Matrix Required for Sign-off

|Test|Pass condition|Current|

|---|---|---|

|0x3 = 2.4+5|Both links keyed and independently carry encrypted traffic|PASS demonstrated|

|0x5 = 2.4+6|Both links keyed and independently carry encrypted traffic|PASS demonstrated|

|0x6 = 5+6|Both links keyed and independently carry encrypted traffic|PASS demonstrated after fixes|

|0x3 <-> 0x5|No reassociation; survivor stays alive; replacement usable|Needs final matrix evidence|

|0x5 <-> 0x6|Same|Needs final matrix evidence|

|0x6 <-> 0x3|Same|Needs final matrix evidence|

|Automatic best-two selection|Real quality inputs cause correct pair selection|Not end-to-end proven|

|Hysteresis|No switch below configured score delta|Implementation exists; runtime sign-off pending|

|Cooldown|No oscillation during cooldown|Implementation exists; runtime sign-off pending|

|Platform EHT capability|No test override required|Not production-ready on current BIOS MTCL|

## 10. Relevant Code, Parameters, and Commits

|Symbol / parameter|Role|

|---|---|

|mt7927_mld_assign_band_idx()|Avoids MT7927 MLD BSS firmware context collision, especially historical 5+6 path.|

|mt7925_mlo_steer_work()|Periodic best-pair steering worker.|

|ieee80211_set_active_links_async()|mac80211 mechanism used by steering to request active-link changes.|

|mt76_mlo_select_wcid()|TX WCID/link selection path.|

|msta->mlo_tid_link[tid]|Experimental per-TID link selection/pinning state.|

|mt7925_mlo_force_bulk_wcid()|Diagnostic/experimental TX-link forcing hook; not production policy.|

|mt7925_change_vif_links()|Driver link-change callback path for vif/BSS state.|

|mt7925_change_sta_links()|Driver peer-link change callback path.|

|mt7925_mac_sta_add_links()|Creates/re-adds per-link peer/WCID state.|

|mt7925_mac_sta_remove_links()|Removes per-link peer/WCID state.|

|mt7925_set_key() / mt7925_set_link_key()|Key programming entry points.|

|mt76_wcid_key_setup()|mt76 WCID crypto state setup.|

|mt7925_mcu_add_key()|Firmware key programming.|

|phy->roc_mlo_links|Tracks MLO ROC/JOIN context.|

|test_mt7927_eht_override|TEST ONLY: bypasses missing MT7927 MTCL EHT enablement.|

|test_mt7927_mlo_pair_mask|TEST ONLY: deterministic pair selection for 0x3/0x5/0x6 validation.|

|mlo_force_tx_link|DEBUGFS TEST ONLY: forces TX toward a selected active link for validation.|

|mlo_auto_steering|Debug/control surface for experimental automatic steering.|

Key project commits / milestones:

4701636ed4b6c5926e6e64b6330e1e2aff347f53 — test-only MT7927 EHT override milestone.

85ea1f098f8228a0a5c9e2f0800bc15f3b0b6a2c — narrow 5+6 secondary-band-context causality experiment.

1c1a4a8842f3bc6a3e4bdc6df316cfd840123a73 — mt7925: avoid MT7927 MLO band context collisions.

33864712 — later project milestone containing 5+6 DBDC/band-context and associated MT7927 MLO fixes (project evidence).

2e593919 — mt7925: MLO ROC two-slot abort + late-link PTK/GTK/IGTK reconciliation.

2ab6c2f2 — mt7925: extend MLO pair-steering score with link-quality term.

956a6e53 — reverted temporary RSSI-rotate diagnostics after direct MCU-return verification.

## 11. Recommended MediaTek Review Focus

The highest-value vendor review is not generic 802.11be behavior. It is confirmation of the MT7927 firmware ABI and lifecycle assumptions that Linux currently has to infer.

Confirm intended semantics and allocation rules for MT7927 BSS band_idx / DBDC context when 5 GHz and 6 GHz links coexist.

Confirm whether the two-context collision allocator is architecturally valid for MT7927 station MLD operation.

Confirm the intended firmware lifecycle for secondary-link ROC/JOIN and abort on MT7927.

Confirm the required PTK/GTK/IGTK/BMC programming semantics when a peer link is removed and later re-added without MLD reassociation.

Provide/confirm the correct MTCL/ACPI selector/data for PCI ID 14c3:7927 so EHT capability is enabled without a Linux test override.

Confirm whether Windows T2LM/EML control uses a private firmware ABI that should be exposed in mt76, or whether host-managed mac80211 active-link steering is the intended Linux architecture.

Review quality-steering inputs and whether firmware exposes better per-link metrics than RSSI + reported PHY bitrate for candidate-pair ranking.

## 12. Final Status Statement

Do not state: "MT7927E MLO is fully solved."

Accurate statement: The experimental Linux mt76 MT7927E driver has demonstrated usable 2.4+5, 2.4+6 and 5+6 GHz two-link MLO pairs. The historical 5+6 association/EAPOL regression has been addressed by MT7927 BSS context allocation work, and ROC plus late-link encryption-state reconciliation have been repaired in the experimental branch. The existing automatic steering architecture now scores links using signal strength and PHY-rate quality with hysteresis and cooldown. Final completion still requires end-to-end proof that real quality changes automatically replace one active link with another across the full pair-transition matrix while preserving encrypted traffic and the surviving link, and it requires removal of test-only EHT/debug mechanisms for production.

## Appendix A — Evidence Provenance and Precision Notes

This report intentionally separates PROVEN, NOT PROVEN and REJECTED claims. It does not treat an active_links bitmap, a UniFi MLO badge, or a LINK_READY message alone as proof that both member links carry data. Static-pair PASS statements refer to later project evidence that both links were individually TX-verified with ARP/traffic. Automatic steering is not promoted to PASS because the final real-quality cross-pair transition was not demonstrated in a sustained three-link window.

Source basis: project engineering logs, local mt76 source references, Windows binary/symbol reverse-engineering notes, and recorded experimental commits. Intermediate hypotheses that were later contradicted are recorded as rejected rather than silently incorporated into the final architecture.