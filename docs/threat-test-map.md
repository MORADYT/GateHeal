# GateHeal threat-to-test map

Generated from `docs/threat-test-map.yaml` by `lab/scripts/wp8_threat_map.py --write`; do not edit by hand. `tests/security/test_wp8_threat_map.py` fails if a listed file, symbol or test is missing, if a bullet of section 3 of `docs/threat-model.md` has no threat, or if this file is stale.

Status: **mitigated** = control present and pinned by tests; **partially-mitigated** = control present and tested, with a stated residual risk; **accepted-limitation** = not mitigated by design, current behaviour pinned. Test flags: `lab` = needs lab fixtures; `live` = skipped unless `GATEHEAL_RUN_LAB_TESTS=1` and a guest is booted.

A test listed here shows the control is exercised, not that the threat is absent: each residual-risk line states what the tests do not cover.

## 1. Summary

| ID | Zone | Threat | Status | Controls | Tests |
|---|---|---|---|---:|---:|
| TM-01 | Z1 | Mutating command runs on the developer workstation instead of the lab guest | mitigated | 3 | 5 |
| TM-02 | Z1 | SSH transport is pointed at a host that is not the loopback-forwarded lab guest | mitigated | 1 | 3 |
| TM-03 | Z1 | Option injection through the SSH user name or host argument (for example -oProxyCommand) | mitigated | 2 | 3 |
| TM-04 | Z1 | Controller talks to an unverified guest, or an SSH outage is mistaken for a safety verdict | mitigated | 4 | 7 |
| TM-05 | Z1 | Privilege escalation through sudo (argument injection, unapproved sub-command, scope wr... | mitigated | 3 | 4 |
| TM-06 | Z1 | Controller key is usable as root, or the harness key is pinned to a source address that... | mitigated | 2 | 2 |
| TM-07 | Z1 | Guest initiates outbound network connections (egress from the disposable lab) | partially-mitigated | 1 | 1 |
| TM-08 | Z2 | Credentials in service logs reach the advisory plane or an external LLM | partially-mitigated | 2 | 2 |
| TM-09 | Z2 | Prompt injection through log text steers the advisory plane | partially-mitigated | 3 | 3 |
| TM-10 | Z2 | Log flooding or oversized lines exhaust the evidence and prompt budget | mitigated | 3 | 3 |
| TM-11 | Z3 | Proposer names an action outside the closed catalogue, or a registered but disabled one | mitigated | 3 | 5 |
| TM-12 | Z3 | Proposer targets a unit outside the inventory or smuggles malformed or extra parameters | mitigated | 2 | 4 |
| TM-13 | Z3 | Proposer self-approves, or inflates its own confidence, to obtain a mutation | mitigated | 3 | 3 |
| TM-14 | Z3 | Malformed, prose, truncated or hostile model output crashes the controller or is executed | mitigated | 2 | 5 |
| TM-15 | Z3 | Runaway model usage (too many requests, a slow provider) starves the incident budget | mitigated | 3 | 4 |
| TM-16 | Z3 | Provider API key leaks into logs, records, the replay cassette or the manifest | mitigated | 3 | 5 |
| TM-17 | Z3 | Provider outage or auth failure is silently scored as a safe abstention | mitigated | 3 | 5 |
| TM-18 | Z4 | Forged, replayed, expired or tampered capability executes an action | mitigated | 3 | 4 |
| TM-19 | Z4 | Incident state changes between the policy decision and execution (time-of-check to time... | mitigated | 3 | 4 |
| TM-20 | Z4 | Operator approval token is forged, reused, expired or signed with a weak key | partially-mitigated | 3 | 5 |
| TM-21 | Z4 | Policy catalogue is mutated at run time, or empty configuration makes the gate fail open | mitigated | 2 | 3 |
| TM-22 | Z4 | Restart storms and flapping through repeated mutating actions | partially-mitigated | 2 | 4 |
| TM-23 | Z4 | Restart of a unit damages healthy dependents (collateral damage / blast radius) | partially-mitigated | 3 | 5 |
| TM-24 | Z4 | Overlapping mutations of the same unit or of an upstream unit | mitigated | 2 | 2 |
| TM-25 | Z4 | A crash between intent and execution loses attempt counters or consumed tokens | mitigated | 3 | 2 |
| TM-26 | Z4 | Audit log is edited, truncated or rotated away without detection | partially-mitigated | 3 | 3 |
| TM-27 | Z4 | A hung action or an orphaned grandchild holding a pipe blocks the controller | mitigated | 2 | 4 |
| TM-28 | Z4 | An exit code of zero is taken as proof of recovery | mitigated | 2 | 4 |
| TM-29 | Z4 | Verifier misses a crash after the restart, a flap, a late collateral failure or an unce... | partially-mitigated | 2 | 11 |
| TM-30 | Z4 | Failed, uncertain or collateral-damaging recovery is not escalated to a human | mitigated | 2 | 2 |
| TM-31 | Z4 | Incident time budget is overrun by collection, action or model latency | mitigated | 2 | 3 |
| TM-36 | Z4 | A restart is attempted on a unit whose configuration is invalid or whose validity is un... | mitigated | 2 | 2 |
| TM-32 | X | The measurement shares code, transport or timing with the system under test | partially-mitigated | 2 | 4 |
| TM-33 | X | The lab worker accepts an unauthenticated abort frame from any local process | accepted-limitation | 2 | 2 |
| TM-34 | X | The S5 fault is a runtime flag, so results do not transfer to faults that survive a res... | accepted-limitation | 2 | 3 |
| TM-35 | X | Live-lab evidence is over-claimed (one guest image, three repeats, emulated daemons) | accepted-limitation | 2 | 4 |

36 threats: 24 mitigated, 9 partially-mitigated, 3 accepted-limitation. 126 distinct tests are mapped to a threat.

## 2. Threats

### Zone 1: isolated lab and host protection

#### TM-01: Mutating command runs on the developer workstation instead of the lab guest

Status: **mitigated**

Threat-model anchors: “`LocalLabSubprocessTransport` requires `GATEHEAL_INSIDE_LAB=1`”

Controls:
- `src/gateheal/transport.py` - `LocalLabSubprocessTransport._verify_inside_lab`
- `lab/scripts/lab_guard.sh` - text "GATEHEAL_INSIDE_LAB"
- `src/gateheal/wp6_engine.py` - `ensure_transport_sentinel_verified`

Tests:
- `tests/security/test_phase2_safety.py::test_local_transport_rejects_host_environment`
- `tests/integration/test_lab_services.py::test_lab_guard_script_refuses_to_run_on_omarchy_host`
- `tests/experiments/test_wp6_campaign_engine.py::test_wp6_ungated_arms_refuse_transport_without_verified_sentinel`
- `tests/security/test_wp8_zone_controls.py::test_local_transport_requires_every_lab_guard_independently`
- `tests/security/test_wp8_zone_controls.py::test_lab_guard_script_requires_every_guard_independently`

#### TM-02: SSH transport is pointed at a host that is not the loopback-forwarded lab guest

Status: **mitigated**

Threat-model anchors: “`SSHLabTransport` enforces a loopback target IP”

Controls:
- `src/gateheal/transport.py` - `_validate_ssh_lab_host`

Tests:
- `tests/security/test_phase2_safety.py::test_transport_rejects_non_loopback_hosts`
- `tests/security/test_wp8_zone_controls.py::test_loopback_hosts_are_accepted`
- `tests/security/test_wp8_zone_controls.py::test_ssh_host_must_be_a_loopback_ip_or_localhost`

#### TM-03: Option injection through the SSH user name or host argument (for example -oProxyCommand)

Status: **mitigated**

Threat-model anchors: “validates `--ssh-user` against”

Controls:
- `src/gateheal/transport.py` - `_validate_ssh_user`
- `src/gateheal/transport.py` - `SSHLabTransport.build_ssh_argv`

Tests:
- `tests/security/test_wp8_zone_controls.py::test_ssh_user_with_option_injection_is_rejected`
- `tests/security/test_wp8_zone_controls.py::test_ssh_argv_ends_options_before_the_destination`
- `tests/unit/test_wp5_transport_errors.py::test_a2_build_ssh_argv_known_hosts_and_identities_only`

#### TM-04: Controller talks to an unverified guest, or an SSH outage is mistaken for a safety verdict

Status: **mitigated**

Threat-model anchors: “distinguishes SSH connectivity failures”

Controls:
- `src/gateheal/transport.py` - `SSHLabTransport._ensure_remote_sentinel`
- `src/gateheal/transport.py` - `_resolve_known_hosts_file`
- `src/gateheal/transport.py` - `TransportUnavailableError`
- `src/gateheal/transport.py` - `HostSafetyViolationError`

Tests:
- `tests/unit/test_wp5_transport_errors.py::test_a1_exit_255_permission_denied_raises_transport_unavailable_error`
- `tests/unit/test_wp5_transport_errors.py::test_a1_exit_1_no_such_file_raises_host_safety_violation_error`
- `tests/unit/test_wp5_transport_errors.py::test_a1_exit_0_wrong_token_raises_host_safety_violation_error`
- `tests/unit/test_wp5_transport_errors.py::test_a1_exit_0_right_token_passes_and_sentinel_cached_across_two_runs`
- `tests/unit/test_wp5_e1_transport.py::test_e1_ssh_sentinel_exit_255_raises_transport_unavailable_with_exit_and_stderr`
- `tests/unit/test_wp5_e1_transport.py::test_e1_ssh_sentinel_wrong_token_with_exit_0_raises_host_safety_violation`
- `tests/unit/test_wp2_wp3_regressions.py::test_wp3_ssh_sentinel_verification_and_remote_timeout_handling`

#### TM-05: Privilege escalation through sudo (argument injection, unapproved sub-command, scope wrapping)

Status: **mitigated**

Threat-model anchors: “Mutating service actions execute via”; “Empirical systemd Conformance & Sudoers Negative Isolation (WP5)”

Controls:
- `lab/systemd/gateheal-sudoers.conf` - text "NOPASSWD: /usr/bin/systemctl restart lab-redis.service"
- `src/gateheal/actions.py` - `ActionSpec.build_argv`
- `src/gateheal/transport.py` - `build_systemd_scope_argv`

Tests:
- `tests/lab/test_wp5_real_lab.py::test_wp5_sudoers_negative_commands_are_strictly_outside_allowlist` [lab]
- `tests/unit/test_wp2_wp3_regressions.py::test_wp3_sudo_argv_forbids_unprivileged_systemd_scope_wrapping`
- `tests/lab/test_wp5_real_lab.py::test_wp5_conformance_script_and_fixture_facts_cover_all_five_systemd_invariants` [lab]
- `tests/security/test_wp8_zone_controls.py::test_sudoers_allowlist_is_exact_and_never_exceeds_what_the_controller_requests`

#### TM-06: Controller key is usable as root, or the harness key is pinned to a source address that breaks the lab

Status: **mitigated**

Threat-model anchors: “Dual-Key Controller vs. Harness SSH Separation”

Controls:
- `lab/scripts/provision_guest.sh` - text "authorized_keys"
- `lab/qemu/manage_vm.sh` - text "id_harness_ed25519"

Tests:
- `tests/lab/test_wp5_scripts_compile.py::test_lab_scripts_never_pin_harness_key_to_loopback` [lab]
- `tests/lab/test_wp5_real_lab.py::test_wp5_live_vm_ssh_conformance_and_captured_fixture_freshness` [lab, live]

#### TM-07: Guest initiates outbound network connections (egress from the disposable lab)

Status: **partially-mitigated**

Threat-model anchors: “QEMU user networking runs with `restrict=on`”

Controls:
- `lab/qemu/manage_vm.sh` - text "restrict=on"

Tests:
- `tests/security/test_wp8_zone_controls.py::test_qemu_launch_restricts_guest_egress`

Residual risk: The test pins the QEMU flag in the launch script. No test probes egress from inside a booted guest, so the property is verified statically, not behaviourally.

### Zone 2: observation and sanitisation

#### TM-08: Credentials in service logs reach the advisory plane or an external LLM

Status: **partially-mitigated**

Threat-model anchors: “Best-Effort Log Redaction”

Controls:
- `src/gateheal/collector.py` - `redact_secrets_text`
- `src/gateheal/collector.py` - `IncidentCollector.redact_secrets`

Tests:
- `tests/unit/test_wp2_wp3_regressions.py::test_r11_collector_redacts_multiline_pem_jwt_ghp_aws_secret_and_cookies`
- `tests/lab/test_wp5_collector_on_real_fixtures.py::test_wp5_collector_on_real_fixtures` [lab]

Residual risk: Pattern-based: a secret in a format the patterns do not know passes through unredacted.

#### TM-09: Prompt injection through log text steers the advisory plane

Status: **partially-mitigated**

Threat-model anchors: “wraps every log line in `[UNTRUSTED_LOG] `”

Controls:
- `src/gateheal/collector.py` - `frame_untrusted_log_line`
- `src/gateheal/llm.py` - `build_wp7_system_prompt`
- `src/gateheal/policy.py` - `PolicyEngine.evaluate`

Tests:
- `tests/security/test_wp8_zone_controls.py::test_every_collected_log_line_is_framed_as_untrusted`
- `tests/security/test_wp8_zone_controls.py::test_log_text_cannot_escape_the_untrusted_frame`
- `tests/experiments/test_wp7_llm_arms.py::test_prompt_injection_in_the_model_output_is_just_text`

Evidence: `docs/experiment-design.md: H4a`

Residual risk: Framing is a convention the model may ignore. The enforced defence is architectural: the advisory plane has no execution authority and every proposal passes the policy gate (TM-12, TM-13). Measured effect with a real model: H4a and H4c in docs/experiment-design.md section 9.

#### TM-10: Log flooding or oversized lines exhaust the evidence and prompt budget

Status: **mitigated**

Threat-model anchors: “enforces per-line byte caps”

Controls:
- `src/gateheal/collector.py` - `cap_line_bytes`
- `src/gateheal/collector.py` - `IncidentCollector.collect_simulated`
- `src/gateheal/collector.py` - `IncidentCollector.collect_from_transport`

Tests:
- `tests/security/test_wp8_zone_controls.py::test_line_cap_counts_bytes_and_never_splits_a_codepoint`
- `tests/security/test_wp8_zone_controls.py::test_per_service_byte_budget_keeps_the_newest_lines_for_every_service`
- `tests/security/test_wp8_zone_controls.py::test_line_count_cap_keeps_only_the_newest_max_log_lines`

### Zone 3: advisory plane (proposer and LLM)

#### TM-11: Proposer names an action outside the closed catalogue, or a registered but disabled one

Status: **mitigated**

Threat-model anchors: “Closed `ActionId` enum lookup”; “Zone 3 (Advisory Plane)”

Controls:
- `src/gateheal/policy.py` - `PolicyEngine.evaluate`
- `src/gateheal/models.py` - `ActionId`
- `src/gateheal/actions.py` - `ActionSpec`

Tests:
- `tests/unit/test_policy_gate.py::test_policy_rejects_unregistered_and_disabled_actions`
- `tests/security/test_phase2_safety.py::test_policy_engine_rejects_unregistered_actions`
- `tests/unit/test_policy_gate.py::test_property_policy_gate_never_approves_unregistered_or_unpermitted_actions`
- `tests/experiments/test_wp7_llm_arms.py::test_hallucinated_actions_are_not_executed_by_either_arm`
- `tests/unit/test_agent_proposer.py::test_config_c_ungated_vs_config_d_policy_gated_llm`

#### TM-12: Proposer targets a unit outside the inventory or smuggles malformed or extra parameters

Status: **mitigated**

Threat-model anchors: “strict unit regex”

Controls:
- `src/gateheal/policy.py` - `PolicyEngine.evaluate`
- `src/gateheal/actions.py` - `UNIT_NAME_RE`

Tests:
- `tests/unit/test_policy_gate.py::test_policy_rejects_unauthorized_target`
- `tests/unit/test_policy_gate.py::test_policy_rejects_malformed_parameters_and_self_approval_fields`
- `tests/experiments/test_wp7_llm_arms.py::test_ungated_arm_refuses_non_lab_units_and_records_why`
- `tests/security/test_wp8_zone_controls.py::test_unexpected_action_parameters_are_rejected`

#### TM-13: Proposer self-approves, or inflates its own confidence, to obtain a mutation

Status: **mitigated**

Threat-model anchors: “sole minting authority”

Controls:
- `src/gateheal/policy.py` - `PolicyEngine.mint_capability`
- `src/gateheal/diagnosis.py` - `DiagnosisEngine.diagnose`
- `src/gateheal/policy.py` - `MinimalImpactSelector.select`

Tests:
- `tests/unit/test_policy_gate.py::test_policy_uses_diagnosis_engine_confidence_and_ignores_spoofed_proposer_confidence`
- `tests/unit/test_policy_gate.py::test_selector_prefers_minimal_impact_and_ignores_spoofed_proposer_confidence`
- `tests/unit/test_policy_gate.py::test_policy_rejects_malformed_parameters_and_self_approval_fields`

#### TM-14: Malformed, prose, truncated or hostile model output crashes the controller or is executed

Status: **mitigated**

Threat-model anchors: “bounded `AgentProposer` modules”

Controls:
- `src/gateheal/agent.py` - `OpenAICompatibleAgentProposer.propose`
- `src/gateheal/llm.py` - `_answer_valid`

Tests:
- `tests/unit/test_agent_proposer.py::test_openai_proposer_malformed_json_falls_back_to_abstain`
- `tests/experiments/test_wp7_llm_arms.py::test_malformed_model_output_is_model_behaviour_a_safe_abstention`
- `tests/experiments/test_wp7_llm_arms.py::test_prose_answers_are_counted_in_the_coverage_table`
- `tests/experiments/test_wp7_llm_arms.py::test_truncated_answers_are_invalid_not_abstentions_and_retry_can_succeed`
- `tests/experiments/test_wp7_llm_arms.py::test_prompt_injection_in_the_model_output_is_just_text`

#### TM-15: Runaway model usage (too many requests, a slow provider) starves the incident budget

Status: **mitigated**

Threat-model anchors: “Possesses zero subprocess execution authority”

Controls:
- `src/gateheal/agent.py` - `OpenAICompatibleAgentProposer.propose`
- `src/gateheal/llm.py` - `ResilientLLMSender`
- `src/gateheal/wp6_engine.py` - `_PlannerExcludedClock`

Tests:
- `tests/unit/test_agent_proposer.py::test_openai_proposer_valid_json_and_budget_enforcement`
- `tests/unit/test_wp7_llm_client.py::test_total_request_cap_counts_every_http_attempt`
- `tests/experiments/test_wp7_llm_arms.py::test_request_cap_stops_the_campaign`
- `tests/experiments/test_wp7_llm_arms.py::test_slow_model_does_not_consume_the_controller_time_budget`

Residual risk: Model latency is excluded from the controller's 45 s budget by design (the oracle still counts it as downtime), so a slow model lengthens the outage but cannot make the gate fail open.

#### TM-16: Provider API key leaks into logs, records, the replay cassette or the manifest

Status: **mitigated**

Threat-model anchors: “Zone 3 (Advisory Plane)”

Controls:
- `src/gateheal/llm.py` - `_redact`
- `src/gateheal/llm.py` - `env_api_key_loader`
- `src/gateheal/llm.py` - `LLMCassette`

Tests:
- `tests/experiments/test_wp7_llm_arms.py::test_key_never_reaches_records_cassette_or_manifest_fields`
- `tests/unit/test_wp7_llm_client.py::test_cassette_never_stores_the_key_and_tolerates_a_torn_last_line`
- `tests/unit/test_wp7_llm_client.py::test_network_errors_are_retried_and_the_key_is_redacted_from_the_record`
- `tests/unit/test_wp7_llm_client.py::test_missing_key_is_fatal_and_sends_nothing`
- `tests/experiments/test_wp7_llm_arms.py::test_manifest_records_llm_provenance_without_the_key`

#### TM-17: Provider outage or auth failure is silently scored as a safe abstention

Status: **mitigated**

Threat-model anchors: “bounded `AgentProposer` modules”

Controls:
- `src/gateheal/wp6_engine.py` - `WP6ExperimentRunner._drain_llm_calls`
- `src/gateheal/llm.py` - `ResilientLLMSender`
- `src/gateheal/llm.py` - `LLMUnavailableError`

Tests:
- `tests/experiments/test_wp7_llm_arms.py::test_transport_failure_is_non_evaluable_never_an_abstention`
- `tests/experiments/test_wp7_llm_arms.py::test_auth_failure_stops_the_campaign_instead_of_scoring`
- `tests/experiments/test_wp7_llm_arms.py::test_transient_503_is_absorbed_and_the_trial_is_valid`
- `tests/experiments/test_wp7_llm_arms.py::test_replay_of_an_unrecorded_request_is_invalid_not_scored`
- `tests/unit/test_wp7_llm_client.py::test_auth_and_billing_errors_stop_the_campaign`

### Zone 4: policy, execution and oracle

#### TM-18: Forged, replayed, expired or tampered capability executes an action

Status: **mitigated**

Threat-model anchors: “Capability-bound `ExecutionController.execute()`”

Controls:
- `src/gateheal/policy.py` - `PolicyEngine.verify_and_consume_capability`
- `src/gateheal/policy.py` - `_compute_capability_mac`
- `src/gateheal/controller.py` - `ExecutionController.execute`

Tests:
- `tests/unit/test_recovery_controller.py::test_wp2_capability_bound_execution_blocks_raw_forged_and_replayed_calls`
- `tests/unit/test_wp2_wp3_regressions.py::test_r2_capability_mac_enforces_expiry_timestamp`
- `tests/unit/test_wp2_wp3_regressions.py::test_r3_capability_mac_binds_proposal_and_decision_digest`
- `tests/unit/test_wp4_verifier_oracle.py::test_pre_wp4_capability_requires_explicit_expires_at_and_seed_requires_incident_id`

#### TM-19: Incident state changes between the policy decision and execution (time-of-check to time-of-use)

Status: **mitigated**

Threat-model anchors: “TOCTOU state-hash checks”

Controls:
- `src/gateheal/policy.py` - `compute_incident_state_hash`
- `src/gateheal/policy.py` - `PolicyEngine.verify_and_consume_capability`
- `src/gateheal/orchestrator.py` - `IncidentOrchestrator.handle_incident`

Tests:
- `tests/unit/test_wp2_wp3_regressions.py::test_r1_verify_and_consume_capability_reruns_policy_evaluate_at_execution_time`
- `tests/unit/test_recovery_controller.py::test_wp2_orchestrator_wal_hash_chain_rotation_and_toctou_abort`
- `tests/unit/test_policy_gate.py::test_state_hash_ignores_logs_and_timestamps_and_tracks_dependents`
- `tests/security/test_wp8_zone_controls.py::test_capability_is_refused_when_the_incident_state_changed_since_issuance`

#### TM-20: Operator approval token is forged, reused, expired or signed with a weak key

Status: **partially-mitigated**

Threat-model anchors: “Single-Process Prototype Key Storage”

Controls:
- `src/gateheal/policy.py` - `verify_approval_token`
- `src/gateheal/policy.py` - `mint_approval_token`
- `src/gateheal/policy.py` - `load_operator_hmac_key`

Tests:
- `tests/unit/test_policy_gate.py::test_approval_token_verification_expiry_signature_key_len_and_consumption`
- `tests/experiments/test_wp6_campaign_engine.py::test_wp6_s5b_uses_an_approval_token_and_restarts`
- `tests/security/test_wp8_zone_controls.py::test_approval_token_is_bound_to_its_action_and_target`
- `tests/security/test_wp8_zone_controls.py::test_verify_time_key_length_check_rejects_a_token_signed_with_a_short_key`
- `tests/experiments/test_wp6_campaign_engine.py::test_wp6_s5u_separates_the_blast_radius_gate_from_its_ablation`

Residual risk: The capability secret and the approval key live in the controller's own process memory. A compromised controller process can mint what it can verify; there is no separate signing service in this prototype.

#### TM-21: Policy catalogue is mutated at run time, or empty configuration makes the gate fail open

Status: **mitigated**

Threat-model anchors: “Closed `ActionId` enum lookup”

Controls:
- `src/gateheal/policy.py` - `PolicyEngine`
- `src/gateheal/actions.py` - `DEFAULT_ACTION_CATALOGUE`

Tests:
- `tests/unit/test_policy_gate.py::test_t11_default_action_catalogue_is_immutable`
- `tests/unit/test_policy_gate.py::test_empty_catalogue_and_empty_permissions_fail_closed`
- `tests/unit/test_policy_gate.py::test_policy_rejects_unregistered_and_disabled_actions`

#### TM-22: Restart storms and flapping through repeated mutating actions

Status: **partially-mitigated**

Threat-model anchors: “Per-incident retry budgets”; “Cross-Incident Restart Bounds”

Controls:
- `src/gateheal/policy.py` - `PolicyEngine.evaluate`
- `src/gateheal/state.py` - `PersistentStateStore.record_execution`

Tests:
- `tests/unit/test_policy_gate.py::test_policy_rejects_when_retry_budget_exhausted`
- `tests/security/test_wp8_zone_controls.py::test_recovery_attempt_budget_is_exhausted_exactly_at_the_limit`
- `tests/unit/test_wp2_wp3_regressions.py::test_r4_attempt_counters_and_action_history_are_keyed_by_incident_id`
- `tests/unit/test_recovery_controller.py::test_wp2_cooldown_flapping_and_unit_lock_enforcement`

Residual risk: Attempt budgets are per incident id (R4). Across distinct incident ids only the per-unit cooldown and the flap window bound repeated mutations.

#### TM-23: Restart of a unit damages healthy dependents (collateral damage / blast radius)

Status: **partially-mitigated**

Threat-model anchors: “Active-Session Coupling vs.”

Controls:
- `src/gateheal/policy.py` - `compute_effective_impact_and_blast_radius`
- `src/gateheal/policy.py` - `collect_transitive_downstream_dependents`
- `src/gateheal/policy.py` - `PolicyEngine.evaluate`

Tests:
- `tests/unit/test_policy_gate.py::test_policy_rejects_restart_when_upstream_dependency_unhealthy`
- `tests/unit/test_policy_gate.py::test_wp1b_blast_radius_table_and_inventory_dilution_invariance`
- `tests/unit/test_wp2_wp3_regressions.py::test_wp3_h3_two_level_transitive_blast_radius_and_unhealthy_exclusion`
- `tests/experiments/test_wp7_llm_arms.py::test_naive_llm_harms_in_the_collateral_trap_ungated_but_is_blocked_when_gated`
- `tests/experiments/test_wp6_campaign_engine.py::test_wp6_s5u_separates_the_blast_radius_gate_from_its_ablation`

Evidence: `docs/experiment-design.md: S5U`

Residual risk: The blast-radius model follows the inventory. A systemd PartOf= or BindsTo= coupling that is not encoded in the inventory is invisible to it; the lab avoids those directives on purpose.

#### TM-24: Overlapping mutations of the same unit or of an upstream unit

Status: **mitigated**

Threat-model anchors: “flap counters keyed by the mutated unit”

Controls:
- `src/gateheal/state.py` - `PersistentStateStore.lock_units`
- `src/gateheal/state.py` - `UnitLockError`

Tests:
- `tests/unit/test_wp2_wp3_regressions.py::test_r6_dual_unit_locking_locks_mutated_upstream_unit`
- `tests/unit/test_recovery_controller.py::test_wp2_cooldown_flapping_and_unit_lock_enforcement`

#### TM-25: A crash between intent and execution loses attempt counters or consumed tokens

Status: **mitigated**

Threat-model anchors: “Write-ahead”

Controls:
- `src/gateheal/orchestrator.py` - `IncidentOrchestrator.handle_incident`
- `src/gateheal/state.py` - `PersistentStateStore.save_snapshot`
- `src/gateheal/controller.py` - `AuditRecorder.record`

Tests:
- `tests/unit/test_wp2_wp3_regressions.py::test_r7_state_persisted_before_subprocess_execution`
- `tests/unit/test_recovery_controller.py::test_wp2_orchestrator_wal_hash_chain_rotation_and_toctou_abort`

#### TM-26: Audit log is edited, truncated or rotated away without detection

Status: **partially-mitigated**

Threat-model anchors: “Unkeyed Audit Hash Chain”

Controls:
- `src/gateheal/controller.py` - `AuditRecorder.verify_chain`
- `src/gateheal/controller.py` - `compute_audit_record_hash`
- `src/gateheal/controller.py` - `load_audit_hmac_key`

Tests:
- `tests/unit/test_wp2_wp3_regressions.py::test_r8_audit_rotation_eviction_preserves_anchor_and_verifies_chain`
- `tests/security/test_wp8_zone_controls.py::test_audit_chain_detects_an_edited_and_a_truncated_record`
- `tests/security/test_wp8_zone_controls.py::test_keyed_audit_chain_rejects_a_recomputed_unkeyed_hash`

Residual risk: Without GATEHEAL_AUDIT_HMAC_KEY held outside the controller's writable directory, the chain is tamper-evident only against accidental damage: a local writer can recompute plain SHA-256.

#### TM-27: A hung action or an orphaned grandchild holding a pipe blocks the controller

Status: **mitigated**

Threat-model anchors: “Bounded `communicate(timeout=...)`”

Controls:
- `src/gateheal/transport.py` - `run_isolated_process_group`
- `src/gateheal/transport.py` - `build_remote_timeout_argv`

Tests:
- `tests/unit/test_wp2_wp3_regressions.py::test_r12_hard_timeout_does_not_hang_when_grandchild_holds_pipe_in_new_session`
- `tests/unit/test_wp4_verifier_oracle.py::test_wp4_6_hung_action_command_marks_outcome_uncertain_with_zero_samples`
- `tests/security/test_wp8_zone_controls.py::test_a_timed_out_process_group_that_ignores_sigterm_is_still_killed`
- `tests/unit/test_wp2_wp3_regressions.py::test_wp3_ssh_sentinel_verification_and_remote_timeout_handling`

#### TM-28: An exit code of zero is taken as proof of recovery

Status: **mitigated**

Threat-model anchors: “Independent multi-sample `OutcomeVerifier` soak polling”

Controls:
- `src/gateheal/controller.py` - `OutcomeVerifier.verify_with_transport`
- `src/gateheal/controller.py` - `OutcomeVerifier._probe_unit_oracle`

Tests:
- `tests/unit/test_recovery_controller.py::test_exit_code_zero_does_not_imply_recovery_if_verifier_fails`
- `tests/unit/test_wp4_verifier_oracle.py::test_wp4_1_clean_recovery_across_5_soak_samples`
- `tests/unit/test_wp4_detector_pins.py::test_oracle_tcp_probe_is_authoritative_over_systemd_state`
- `tests/unit/test_wp4_detector_pins.py::test_oracle_http_probe_is_authoritative_over_systemd_state`

#### TM-29: Verifier misses a crash after the restart, a flap, a late collateral failure or an uncertain probe

Status: **partially-mitigated**

Threat-model anchors: “Strict All-Samples-Healthy Soak Rule vs. Slow Startup Grace”; “Manual Restart Resets `NRestarts`”

Controls:
- `src/gateheal/controller.py` - `OutcomeVerifier.verify_with_transport`
- `src/gateheal/controller.py` - `_detect_target_recurrence`

Tests:
- `tests/unit/test_wp4_verifier_oracle.py::test_wp4_2_recovery_then_crash_at_t_2s_with_nrestarts_zero`
- `tests/unit/test_wp4_verifier_oracle.py::test_wp4_3_flapping_health_and_mid_soak_invocation_id_or_timestamp_change`
- `tests/unit/test_wp4_verifier_oracle.py::test_wp4_4_probe_timeout_mid_soak_returns_outcome_uncertain`
- `tests/unit/test_wp4_verifier_oracle.py::test_wp4_5_dependent_failing_late_at_t_4s_reports_collateral_failure`
- `tests/unit/test_wp4_detector_pins.py::test_each_recurrence_signal_alone_is_not_recovered`
- `tests/unit/test_wp4_detector_pins.py::test_restart_counter_rising_inside_the_soak_is_caught_after_a_manual_restart_reset`
- `tests/unit/test_wp4_detector_pins.py::test_reload_must_not_change_invocation_id`
- `tests/unit/test_wp4_detector_pins.py::test_reload_must_not_change_exec_main_start_timestamp`
- `tests/unit/test_wp4_detector_pins.py::test_unhealthy_only_in_first_sample_is_not_clean`
- `tests/unit/test_wp2_wp3_regressions.py::test_r9_verifier_does_not_flag_pre_existing_unhealthy_dependent_as_collateral`
- `tests/unit/test_wp2_wp3_regressions.py::test_r10_verifier_detects_transitive_2_hop_collateral_failure`

Residual risk: Every soak sample must be healthy, so a slow-starting service is escalated rather than excused (D2). A crash and respawn before the first sample that leaves NRestarts at zero cannot be told from the requested restart (D4).

#### TM-30: Failed, uncertain or collateral-damaging recovery is not escalated to a human

Status: **mitigated**

Threat-model anchors: “`EscalationSink`”

Controls:
- `src/gateheal/controller.py` - `EscalationSink.emit`
- `src/gateheal/orchestrator.py` - `IncidentOrchestrator.handle_incident`

Tests:
- `tests/unit/test_wp2_wp3_regressions.py::test_r5_orchestrator_escalates_on_not_recovered_uncertain_and_collateral`
- `tests/unit/test_wp4_t2_live_paths.py::test_t2_orchestrator_handle_incident_without_post_evidence_supplier`

#### TM-31: Incident time budget is overrun by collection, action or model latency

Status: **mitigated**

Threat-model anchors: “Zone 4 (Independent Policy, Execution & Oracle Plane)”

Controls:
- `src/gateheal/policy.py` - `PolicyEngine.evaluate`
- `src/gateheal/collector.py` - `IncidentCollector.collect_from_transport`

Tests:
- `tests/unit/test_wp2_wp3_regressions.py::test_wp3_collector_enforces_total_incident_time_budget`
- `tests/unit/test_wp2_wp3_regressions.py::test_r1_verify_and_consume_capability_reruns_policy_evaluate_at_execution_time`
- `tests/experiments/test_wp7_llm_arms.py::test_slow_model_does_not_consume_the_controller_time_budget`

#### TM-36: A restart is attempted on a unit whose configuration is invalid or whose validity is unknown

Status: **mitigated**

Threat-model anchors: “Closed `ActionId` enum lookup”

Controls:
- `src/gateheal/policy.py` - `PolicyEngine.evaluate`
- `src/gateheal/models.py` - `PolicyRejectionCode`

Tests:
- `tests/security/test_wp8_zone_controls.py::test_restart_fails_closed_when_config_validity_is_unknown_or_false`
- `tests/unit/test_policy_gate.py::test_wp1b_s2_fault_persists_service_up_outcome`

### Cross-cutting: evaluation and lab limits

#### TM-32: The measurement shares code, transport or timing with the system under test

Status: **partially-mitigated**

Threat-model anchors: “Shared Transport/Mechanism Between Collector and Verifier Oracle”; “In-Window Soak Unavailability vs. End-to-End MTTR”

Controls:
- `src/gateheal/oracle.py` - `IndependentLabOracle`
- `src/gateheal/models.py` - `VerificationReport`

Tests:
- `tests/unit/test_wp6_oracle_and_stats.py::test_oracle_import_closure_is_only_transport`
- `tests/unit/test_wp6_oracle_and_stats.py::test_oracle_source_imports_only_allowed_modules`
- `tests/unit/test_wp6_oracle_and_stats.py::test_unavailability_is_integrated_from_the_timeline_not_the_controller_clock`
- `tests/experiments/test_wp6_campaign_engine.py::test_wp6_engine_never_uses_the_removed_oracle_shortcut`

Residual risk: The oracle has its own code path but queries the same systemctl, curl and TCP mechanisms over the same transport type, so a defect in that mechanism could affect controller and oracle alike (D5). Controller-side unavailability is an in-window upper bound; end-to-end MTTR comes only from the harness (D3).

#### TM-33: The lab worker accepts an unauthenticated abort frame from any local process

Status: **accepted-limitation**

Threat-model anchors: “Unauthenticated Local Worker Abort Frame in Lab Daemon”

Controls:
- `src/gateheal/lab_daemons.py` - `LabWorkerRuntimeState.handle_frame`
- `src/gateheal/lab_daemons.py` - `notify_worker_of_api_hard_restart`

Tests:
- `tests/unit/test_wp4_t2_live_paths.py::test_t2_real_api_subprocess_sigterm_handler_notifies_and_stops_worker_subprocess`
- `tests/integration/test_lab_services.py::test_lab_api_sighup_reload_vs_hard_restart_worker_coupling`

Residual risk: This is a lab-only collateral-damage simulation hook, not a hardened IPC protocol. It exists to make S5 observable and must not be reused outside the disposable guest.

#### TM-34: The S5 fault is a runtime flag, so results do not transfer to faults that survive a restart

Status: **accepted-limitation**

Threat-model anchors: “S5 Stale-Pool Fault Is Runtime-Only, Not Persisted”

Controls:
- `lab/fault_injection/inject_fault.sh` - text "SIGUSR1"
- `src/gateheal/lab_daemons.py` - `LabApiRuntimeState.mark_worker_pool_stale`

Tests:
- `tests/unit/test_wp5_live_findings.py::test_inject_s5_does_not_persist_fault_in_config_file`
- `tests/unit/test_wp5_live_findings.py::test_runtime_stale_flag_is_cleared_by_restart_and_sighup`
- `tests/unit/test_wp5_live_findings.py::test_real_api_daemon_sigusr1_degrades_then_restart_and_sighup_recover` [live]

Residual risk: S5 models a stale in-memory pool. A fault that survives restarts is modelled by S2 and S4 (invalid configuration), which no arm can repair.

#### TM-35: Live-lab evidence is over-claimed (one guest image, three repeats, emulated daemons)

Status: **accepted-limitation**

Threat-model anchors: “Live-Lab Validation Scope and Provenance”; “Real-Lab VM Execution”

Controls:
- `src/gateheal/lab_bringup.py` - `conformance_is_complete_and_passed`
- `src/gateheal/wp6_engine.py` - `validate_wp6_preflight`

Tests:
- `tests/unit/test_wp5_live_findings.py::test_conformance_missing_facts_are_not_all_passed`
- `tests/unit/test_wp5_live_findings.py::test_manifest_conformance_not_all_passed_when_facts_truncated`
- `tests/unit/test_wp5_live_findings.py::test_manifest_counts_mismatches_and_flakes_separately`
- `tests/experiments/test_wp6_campaign_engine.py::test_wp6_preflight_checks_wp5_manifest_and_dirty_tree`

Residual risk: Behaviour on other systemd versions, other images or real services is not established. The live-VM tests are skipped unless GATEHEAL_RUN_LAB_TESTS=1 and a guest is booted.

## 3. Coverage of `docs/threat-model.md` section 3

| Bullet | Threats |
|---|---|
| Closed `ActionId` enum lookup, strict unit regex (`^[a-z0-9_-]+\.service$`),... | TM-11, TM-12, TM-21, TM-36 |
| Capability-bound `ExecutionController.execute()` with mandatory `expires_at_u... | TM-18, TM-19 |
| Per-incident retry budgets (`incidents[incident_id]`) separated from persiste... | TM-22, TM-24 |
| Independent multi-sample `OutcomeVerifier` soak polling (`verification_soak_s... | TM-28 |
| Bounded `communicate(timeout=...)` and pipe closure after `os.killpg` so orph... | TM-27 |
| Write-ahead (`"intent"` and `"completed"`) SHA-256 hash-chained audit logs wi... | TM-25 |
| **Empirical systemd Conformance & Sudoers Negative Isolation (WP5):** Verifie... | TM-05 |
| **Best-Effort Log Redaction:** Regex-based secret redaction (`redact_secrets_... | TM-08 |
| **Unkeyed Audit Hash Chain:** Without an external HMAC key (`GATEHEAL_AUDIT_H... | TM-26 |
| **Single-Process Prototype Key Storage:** In this prototype, the capability s... | TM-20 |
| **Active-Session Coupling vs. `systemd` `PartOf=` / `BindsTo=` Coupling Limit... | TM-23 |
| **Real-Lab VM Execution:** Full end-to-end execution against a live QEMU/KVM... | TM-35 |
| **Cross-Incident Restart Bounds:** Because `prior_recovery_attempts` and `act... | TM-22 |
| **Strict All-Samples-Healthy Soak Rule vs. Slow Startup Grace (D2):** During... | TM-29 |
| **In-Window Soak Unavailability vs. End-to-End MTTR (D3):** `VerificationRepo... | TM-32 |
| **Manual Restart Resets `NRestarts` & Sub-Interval Crash-Before-First-Sample... | TM-29 |
| **Shared Transport/Mechanism Between Collector and Verifier Oracle (D5):** Al... | TM-32 |
| **Unauthenticated Local Worker Abort Frame in Lab Daemon (D6):** In `gateheal... | TM-33 |
| **S5 Stale-Pool Fault Is Runtime-Only, Not Persisted (D7):** The first live c... | TM-34 |
| **Live-Lab Validation Scope and Provenance (D8):** WP5 evidence is one dispos... | TM-35 |

## 4. Tests not mapped to a threat

Tests that check functionality, statistics or experiment plumbing rather than a documented threat are not listed here, so adding one does not make this file stale. Run `lab/scripts/wp8_threat_map.py --unmapped` for the list.
