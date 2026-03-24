//! Unit tests for EpochCache (src/state_transition/cache/epoch_cache.zig)
//!
//! Tests are run via `zig build test:state_transition` because root.zig
//! calls `testing.refAllDecls(@This())` which traverses all pub exports and
//! discovers tests in imported modules (including this file via epoch_cache.zig).

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;

const types = @import("consensus_types");
const preset = @import("preset").preset;
const c = @import("constants");
const ssz = @import("ssz");
const Node = @import("persistent_merkle_tree").Node;

const state_transition = @import("../root.zig");
const EpochCache = state_transition.EpochCache;
const EpochCacheImmutableData = state_transition.EpochCacheImmutableData;

const TestCachedBeaconState = state_transition.test_utils.TestCachedBeaconState;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Convenience: create TestCachedBeaconState with given validator count.
/// Returns the test state and a pool; caller calls .deinit() on both.
fn makeTestState(allocator: Allocator, pool: *Node.Pool, n: usize) !TestCachedBeaconState {
    return TestCachedBeaconState.init(allocator, pool, n);
}

// ---------------------------------------------------------------------------
// createFromState: epoch / shuffling population
// ---------------------------------------------------------------------------

test "epoch_cache: createFromState sets epoch from slot" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 64);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const slot = try ts.cached_state.state.slot();
    const expected_epoch = @divFloor(slot, preset.SLOTS_PER_EPOCH);

    try testing.expectEqual(expected_epoch, ec.epoch);
}

test "epoch_cache: createFromState populates previous/current/next shufflings" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 64);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const epoch = ec.epoch;
    const prev_epoch = if (epoch == 0) 0 else epoch - 1;

    try testing.expectEqual(prev_epoch, ec.getPreviousShuffling().epoch);
    try testing.expectEqual(epoch, ec.getCurrentShuffling().epoch);
    try testing.expectEqual(epoch + 1, ec.getNextEpochShuffling().epoch);
}

// ---------------------------------------------------------------------------
// effective_balance_increments
// ---------------------------------------------------------------------------

test "epoch_cache: effective_balance_increments length matches validator count" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    const n = 128;
    var ts = try makeTestState(allocator, &pool, n);
    defer ts.deinit();

    const ebi = ts.cached_state.epoch_cache.getEffectiveBalanceIncrements();
    try testing.expectEqual(n, ebi.items.len);
}

test "epoch_cache: effective_balance_increments values are floor(eff_balance / EBI)" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    const n = 32;
    var ts = try makeTestState(allocator, &pool, n);
    defer ts.deinit();

    const ebi = ts.cached_state.epoch_cache.getEffectiveBalanceIncrements();

    // generate_state sets effective_balance = 32 Gwei * 1e9 = 32_000_000_000
    // EFFECTIVE_BALANCE_INCREMENT (minimal preset) = 1_000_000_000
    // => increment = 32
    const expected: u64 = 32_000_000_000 / preset.EFFECTIVE_BALANCE_INCREMENT;
    for (ebi.items) |inc| {
        try testing.expectEqual(expected, inc);
    }
}

// ---------------------------------------------------------------------------
// active validator indices
// ---------------------------------------------------------------------------

test "epoch_cache: all n validators are active in current epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    const n = 64;
    var ts = try makeTestState(allocator, &pool, n);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    try testing.expectEqual(n, ec.getCurrentShuffling().active_indices.len);
}

test "epoch_cache: getActiveIndicesAtEpoch returns correct count for current epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    const n = 48;
    var ts = try makeTestState(allocator, &pool, n);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const indices = ec.getActiveIndicesAtEpoch(ec.epoch) orelse return error.NoActiveIndices;
    try testing.expectEqual(n, indices.len);
}

test "epoch_cache: getActiveIndicesAtEpoch returns null for distant epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 32);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const result = ec.getActiveIndicesAtEpoch(ec.epoch + 100);
    try testing.expectEqual(null, result);
}

// ---------------------------------------------------------------------------
// committee counts
// ---------------------------------------------------------------------------

test "epoch_cache: getCommitteeCountPerSlot is non-zero" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 64);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const count = try ec.getCommitteeCountPerSlot(ec.epoch);
    try testing.expect(count > 0);
}

test "epoch_cache: getCommitteeCountPerSlot errors for unknown epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 32);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const result = ec.getCommitteeCountPerSlot(ec.epoch + 100);
    try testing.expectError(error.EpochShufflingNotFound, result);
}

// ---------------------------------------------------------------------------
// getBeaconProposer
// ---------------------------------------------------------------------------

test "epoch_cache: getBeaconProposer returns valid index for every slot in epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    const n = 64;
    var ts = try makeTestState(allocator, &pool, n);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const epoch_start = ec.epoch * preset.SLOTS_PER_EPOCH;

    for (0..preset.SLOTS_PER_EPOCH) |i| {
        const proposer = try ec.getBeaconProposer(epoch_start + i);
        try testing.expect(proposer < n);
    }
}

test "epoch_cache: getBeaconProposer is deterministic" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 64);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const slot = ec.epoch * preset.SLOTS_PER_EPOCH;

    const p1 = try ec.getBeaconProposer(slot);
    const p2 = try ec.getBeaconProposer(slot);
    try testing.expectEqual(p1, p2);
}

test "epoch_cache: getBeaconProposer errors for wrong epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 32);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const future_slot = (ec.epoch + 10) * preset.SLOTS_PER_EPOCH;
    try testing.expectError(error.NotCurrentEpoch, ec.getBeaconProposer(future_slot));
}

// ---------------------------------------------------------------------------
// getBeaconCommittee
// ---------------------------------------------------------------------------

test "epoch_cache: getBeaconCommittee index 0 is non-empty" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 64);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const slot = ec.epoch * preset.SLOTS_PER_EPOCH;
    const committee = try ec.getBeaconCommittee(slot, 0);
    try testing.expect(committee.len > 0);
}

test "epoch_cache: getBeaconCommittee out-of-bounds index errors" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 32);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const slot = ec.epoch * preset.SLOTS_PER_EPOCH;
    // committee_index beyond MAX_COMMITTEES_PER_SLOT is always out of bounds
    try testing.expectError(
        error.CommitteeIndexOutOfBounds,
        ec.getBeaconCommittee(slot, preset.MAX_COMMITTEES_PER_SLOT + 1),
    );
}

test "epoch_cache: each validator appears exactly once across all committees in the epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    const n = 64;
    var ts = try makeTestState(allocator, &pool, n);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const epoch_start = ec.epoch * preset.SLOTS_PER_EPOCH;
    const committees_per_slot = try ec.getCommitteeCountPerSlot(ec.epoch);

    var seen = try allocator.alloc(u32, n);
    defer allocator.free(seen);
    @memset(seen, 0);

    // Validators are distributed across the whole epoch, not a single slot
    for (0..preset.SLOTS_PER_EPOCH) |s| {
        const slot = epoch_start + s;
        for (0..committees_per_slot) |ci| {
            const committee = try ec.getBeaconCommittee(slot, ci);
            for (committee) |vi| {
                try testing.expect(vi < n);
                seen[vi] += 1;
            }
        }
    }

    // Every active validator appears in exactly one committee across the epoch
    for (seen) |count| {
        try testing.expectEqual(@as(u32, 1), count);
    }
}

test "epoch_cache: all committee sizes are at least 1" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    const n = 256;
    var ts = try makeTestState(allocator, &pool, n);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const epoch_start = ec.epoch * preset.SLOTS_PER_EPOCH;
    const committees_per_slot = try ec.getCommitteeCountPerSlot(ec.epoch);

    for (0..preset.SLOTS_PER_EPOCH) |s| {
        for (0..committees_per_slot) |ci| {
            const committee = try ec.getBeaconCommittee(epoch_start + s, ci);
            try testing.expect(committee.len >= 1);
        }
    }
}

// ---------------------------------------------------------------------------
// getAttestingIndices (phase0)
// ---------------------------------------------------------------------------

test "epoch_cache: getAttestingIndicesPhase0 all-set bits returns full committee" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 64);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const slot = ec.epoch * preset.SLOTS_PER_EPOCH;
    const committee_index: u64 = 0;

    const committee = try ec.getBeaconCommittee(slot, committee_index);
    const comm_len = committee.len;

    // All validators attesting: set every bit true
    const bools = try allocator.alloc(bool, comm_len);
    defer allocator.free(bools);
    @memset(bools, true);
    var aggregation_bits = try ssz.BitList(preset.MAX_VALIDATORS_PER_COMMITTEE).fromBoolSlice(allocator, bools);
    defer aggregation_bits.deinit(allocator);

    const attestation = types.phase0.Attestation.Type{
        .aggregation_bits = aggregation_bits,
        .data = .{
            .slot = slot,
            .index = committee_index,
            .beacon_block_root = [_]u8{0} ** 32,
            .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            .target = .{ .epoch = ec.epoch, .root = [_]u8{0} ** 32 },
        },
        .signature = [_]u8{0} ** 96,
    };

    var attesting = try ec.getAttestingIndicesPhase0(&attestation);
    defer attesting.deinit();

    try testing.expectEqual(comm_len, attesting.items.len);
}

test "epoch_cache: getAttestingIndicesPhase0 no bits set returns empty" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 32);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const slot = ec.epoch * preset.SLOTS_PER_EPOCH;

    const committee = try ec.getBeaconCommittee(slot, 0);
    const comm_len = committee.len;

    // No validators attesting: all bits false
    const bools = try allocator.alloc(bool, comm_len);
    defer allocator.free(bools);
    @memset(bools, false);
    var aggregation_bits = try ssz.BitList(preset.MAX_VALIDATORS_PER_COMMITTEE).fromBoolSlice(allocator, bools);
    defer aggregation_bits.deinit(allocator);

    const attestation = types.phase0.Attestation.Type{
        .aggregation_bits = aggregation_bits,
        .data = .{
            .slot = slot,
            .index = 0,
            .beacon_block_root = [_]u8{0} ** 32,
            .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            .target = .{ .epoch = ec.epoch, .root = [_]u8{0} ** 32 },
        },
        .signature = [_]u8{0} ** 96,
    };

    var attesting = try ec.getAttestingIndicesPhase0(&attestation);
    defer attesting.deinit();

    try testing.expectEqual(@as(usize, 0), attesting.items.len);
}

test "epoch_cache: getAttestingIndicesPhase0 first-bit-only returns one index" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 32);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const slot = ec.epoch * preset.SLOTS_PER_EPOCH;

    const committee = try ec.getBeaconCommittee(slot, 0);
    const comm_len = committee.len;

    const bools = try allocator.alloc(bool, comm_len);
    defer allocator.free(bools);
    @memset(bools, false);
    bools[0] = true; // only first member attests

    var aggregation_bits = try ssz.BitList(preset.MAX_VALIDATORS_PER_COMMITTEE).fromBoolSlice(allocator, bools);
    defer aggregation_bits.deinit(allocator);

    const attestation = types.phase0.Attestation.Type{
        .aggregation_bits = aggregation_bits,
        .data = .{
            .slot = slot,
            .index = 0,
            .beacon_block_root = [_]u8{0} ** 32,
            .source = .{ .epoch = 0, .root = [_]u8{0} ** 32 },
            .target = .{ .epoch = ec.epoch, .root = [_]u8{0} ** 32 },
        },
        .signature = [_]u8{0} ** 96,
    };

    var attesting = try ec.getAttestingIndicesPhase0(&attestation);
    defer attesting.deinit();

    try testing.expectEqual(@as(usize, 1), attesting.items.len);
    // The returned index must be a valid validator index
    try testing.expect(attesting.items[0] < 32);
}

// ---------------------------------------------------------------------------
// clone
// ---------------------------------------------------------------------------

test "epoch_cache: clone is independent with matching epoch and proposers" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 32);
    defer ts.deinit();

    const original = ts.cached_state.epoch_cache;
    const cloned = try original.clone(allocator);
    defer cloned.deinit();

    try testing.expectEqual(original.epoch, cloned.epoch);
    try testing.expectEqual(original.sync_period, cloned.sync_period);
    try testing.expectEqual(original.total_active_balance_increments, cloned.total_active_balance_increments);
    try testing.expectEqual(original.churn_limit, cloned.churn_limit);
    try testing.expectEqual(original.activation_churn_limit, cloned.activation_churn_limit);

    for (0..preset.SLOTS_PER_EPOCH) |i| {
        try testing.expectEqual(original.proposers[i], cloned.proposers[i]);
    }
}

// ---------------------------------------------------------------------------
// total_active_balance_increments floor
// ---------------------------------------------------------------------------

test "epoch_cache: total_active_balance_increments >= 1 (spec minimum)" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 1);
    defer ts.deinit();

    try testing.expect(ts.cached_state.epoch_cache.total_active_balance_increments >= 1);
}

// ---------------------------------------------------------------------------
// churn limits
// ---------------------------------------------------------------------------

test "epoch_cache: churn_limit >= MIN_PER_EPOCH_CHURN_LIMIT" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 64);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    try testing.expect(ec.churn_limit >= @as(u64, ts.config.chain.MIN_PER_EPOCH_CHURN_LIMIT));
}

// ---------------------------------------------------------------------------
// getShufflingAtSlotOrNull / getShufflingAtEpochOrNull
// ---------------------------------------------------------------------------

test "epoch_cache: getShufflingAtSlotOrNull returns current shuffling for current epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 32);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const slot = ec.epoch * preset.SLOTS_PER_EPOCH;
    const shuffling = ec.getShufflingAtSlotOrNull(slot) orelse return error.NoShuffling;
    try testing.expectEqual(ec.epoch, shuffling.epoch);
}

test "epoch_cache: getShufflingAtEpochOrNull returns null for distant epoch" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 32);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    try testing.expectEqual(null, ec.getShufflingAtEpochOrNull(ec.epoch + 50));
}

test "epoch_cache: getShufflingAtEpochOrNull covers prev/current/next epochs" {
    const allocator = testing.allocator;
    var pool = try Node.Pool.init(allocator, 200_000);
    defer pool.deinit();

    var ts = try makeTestState(allocator, &pool, 32);
    defer ts.deinit();

    const ec = ts.cached_state.epoch_cache;
    const prev_epoch = if (ec.epoch == 0) 0 else ec.epoch - 1;

    try testing.expect(ec.getShufflingAtEpochOrNull(prev_epoch) != null);
    try testing.expect(ec.getShufflingAtEpochOrNull(ec.epoch) != null);
    try testing.expect(ec.getShufflingAtEpochOrNull(ec.epoch + 1) != null);
    try testing.expectEqual(null, ec.getShufflingAtEpochOrNull(ec.epoch + 2));
}
