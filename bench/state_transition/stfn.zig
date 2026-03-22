//! Benchmark for state transition function (STFN) hot paths.
//!
//! Measures the production-critical operations:
//! - Warm slot transition (clone → processSlots(+1) → commit)
//! - Warm epoch boundary transition (clone → processSlots across epoch → commit)
//! - State clone cost (with/without cache transfer)
//! - Cold deserialization pipeline (SSZ → deserialize → syncPubkeys → createCachedBeaconState)
//!
//! Run with: zig build run:bench_stfn -Doptimize=ReleaseFast

const std = @import("std");
const zbench = @import("zbench");
const Node = @import("persistent_merkle_tree").Node;
const state_transition = @import("state_transition");
const types = @import("consensus_types");
const config = @import("config");
const fork_types = @import("fork_types");
const download_era_options = @import("download_era_options");
const era = @import("era");
const preset = state_transition.preset;
const ForkSeq = config.ForkSeq;
const CachedBeaconState = state_transition.CachedBeaconState;
const AnyBeaconState = fork_types.AnyBeaconState;
const slotFromStateBytes = @import("utils.zig").slotFromStateBytes;
const loadState = @import("utils.zig").loadState;

const Slot = types.primitive.Slot.Type;

// ── Segmented timing infrastructure ──────────────────────────────────────────

const Step = enum {
    // Warm slot transition segments
    warm_slot_total,
    warm_slot_clone,
    warm_slot_process_slots,
    warm_slot_commit,
    warm_slot_deinit,
    // Warm epoch boundary segments
    warm_epoch_total,
    warm_epoch_clone,
    warm_epoch_process_slots,
    warm_epoch_commit,
    warm_epoch_deinit,
    // Cold deserialization segments
    cold_total,
    cold_deserialize,
    cold_sync_pubkeys,
    cold_create_cached_state,
};

const step_count = std.enums.values(Step).len;
var step_durations_ns: [step_count]u128 = [_]u128{0} ** step_count;
var step_run_counts: [step_count]u64 = [_]u64{0} ** step_count;

fn resetSegmentStats() void {
    for (&step_durations_ns) |*v| v.* = 0;
    for (&step_run_counts) |*v| v.* = 0;
}

fn recordSegment(step: Step, duration_ns: u64) void {
    const idx = @intFromEnum(step);
    step_durations_ns[idx] += duration_ns;
    step_run_counts[idx] += 1;
}

fn elapsedSince(start: i128) u64 {
    return @as(u64, @intCast(std.time.nanoTimestamp() - start));
}

fn printSegmentStats(stdout: anytype) !void {
    try stdout.print("\nSegmented STFN breakdown:\n", .{});
    try stdout.print("{s:<28} {s:<8} {s:<14} {s:<14}\n", .{ "step", "runs", "total time", "time/run (avg)" });
    try stdout.print("{s:-<66}\n", .{""});
    for (std.enums.values(Step)) |step| {
        const idx = @intFromEnum(step);
        const count = step_run_counts[idx];
        if (count == 0) continue;
        const total_ns = step_durations_ns[idx];
        const avg_ns: u128 = total_ns / count;
        const total_ms = @as(f64, @floatFromInt(total_ns)) / std.time.ns_per_ms;
        const avg_ms = @as(f64, @floatFromInt(avg_ns)) / std.time.ns_per_ms;
        const total_s = total_ms / std.time.ms_per_s;
        if (total_ms >= std.time.ms_per_s) {
            try stdout.print("{s:<28} {d:<8} {d:>10.3}s   {d:>10.3}ms\n", .{ @tagName(step), count, total_s, avg_ms });
        } else {
            try stdout.print("{s:<28} {d:<8} {d:>10.3}ms   {d:>10.3}ms\n", .{ @tagName(step), count, total_ms, avg_ms });
        }
    }
    try stdout.print("\n", .{});
}

// ── Scenario 1: Warm Slot Transition ─────────────────────────────────────────

fn WarmSlotBench(comptime segmented: bool) type {
    return struct {
        cached_state: *CachedBeaconState,
        target_slot: Slot,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const total_start = if (segmented) std.time.nanoTimestamp() else 0;

            const clone_start = if (segmented) std.time.nanoTimestamp() else 0;
            const cloned = self.cached_state.clone(allocator, .{ .transfer_cache = true }) catch unreachable;
            if (segmented) recordSegment(.warm_slot_clone, elapsedSince(clone_start));

            const process_start = if (segmented) std.time.nanoTimestamp() else 0;
            state_transition.state_transition.processSlots(
                allocator,
                cloned,
                self.target_slot,
                .{},
            ) catch unreachable;
            if (segmented) recordSegment(.warm_slot_process_slots, elapsedSince(process_start));

            const commit_start = if (segmented) std.time.nanoTimestamp() else 0;
            cloned.state.commit() catch unreachable;
            if (segmented) recordSegment(.warm_slot_commit, elapsedSince(commit_start));

            const deinit_start = if (segmented) std.time.nanoTimestamp() else 0;
            cloned.deinit();
            allocator.destroy(cloned);
            if (segmented) recordSegment(.warm_slot_deinit, elapsedSince(deinit_start));

            if (segmented) recordSegment(.warm_slot_total, elapsedSince(total_start));
        }
    };
}

// ── Scenario 2: Warm Epoch Boundary ──────────────────────────────────────────

fn WarmEpochBoundaryBench(comptime segmented: bool) type {
    return struct {
        cached_state: *CachedBeaconState,
        target_slot: Slot,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const total_start = if (segmented) std.time.nanoTimestamp() else 0;

            const clone_start = if (segmented) std.time.nanoTimestamp() else 0;
            const cloned = self.cached_state.clone(allocator, .{ .transfer_cache = false }) catch unreachable;
            if (segmented) recordSegment(.warm_epoch_clone, elapsedSince(clone_start));

            const process_start = if (segmented) std.time.nanoTimestamp() else 0;
            state_transition.state_transition.processSlots(
                allocator,
                cloned,
                self.target_slot,
                .{},
            ) catch unreachable;
            if (segmented) recordSegment(.warm_epoch_process_slots, elapsedSince(process_start));

            const commit_start = if (segmented) std.time.nanoTimestamp() else 0;
            cloned.state.commit() catch unreachable;
            if (segmented) recordSegment(.warm_epoch_commit, elapsedSince(commit_start));

            const deinit_start = if (segmented) std.time.nanoTimestamp() else 0;
            cloned.deinit();
            allocator.destroy(cloned);
            if (segmented) recordSegment(.warm_epoch_deinit, elapsedSince(deinit_start));

            if (segmented) recordSegment(.warm_epoch_total, elapsedSince(total_start));
        }
    };
}

// ── Scenario 3: State Clone Cost ─────────────────────────────────────────────

const CloneWithTransferBench = struct {
    cached_state: *CachedBeaconState,

    pub fn run(self: @This(), allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator, .{ .transfer_cache = true }) catch unreachable;
        cloned.deinit();
        allocator.destroy(cloned);
    }
};

const CloneNoTransferBench = struct {
    cached_state: *CachedBeaconState,

    pub fn run(self: @This(), allocator: std.mem.Allocator) void {
        const cloned = self.cached_state.clone(allocator, .{ .transfer_cache = false }) catch unreachable;
        cloned.deinit();
        allocator.destroy(cloned);
    }
};

// ── Scenario 4: Cold Deserialization Pipeline ────────────────────────────────

fn ColdDeserializationBench(comptime fork: ForkSeq) type {
    return struct {
        state_bytes: []const u8,
        chain_config: config.ChainConfig,

        pub fn run(self: @This(), allocator: std.mem.Allocator) void {
            const total_start = std.time.nanoTimestamp();

            // Use a fresh pool per iteration to simulate true cold deserialization.
            // Reusing a pool with recycled nodes from prior deinits causes stale data reads.
            var pool = Node.Pool.init(allocator, 10_000_000) catch unreachable;
            defer pool.deinit();

            // Step 1: Deserialize
            const deser_start = std.time.nanoTimestamp();
            const beacon_state = loadState(fork, allocator, &pool, self.state_bytes) catch unreachable;
            recordSegment(.cold_deserialize, elapsedSince(deser_start));

            // Step 2: Sync pubkeys
            const sync_start = std.time.nanoTimestamp();
            var pubkey_index_map = state_transition.PubkeyIndexMap.init(allocator);
            const index_pubkey_cache = allocator.create(state_transition.Index2PubkeyCache) catch unreachable;
            index_pubkey_cache.* = state_transition.Index2PubkeyCache.init(allocator);

            const validators = beacon_state.validatorsSlice(allocator) catch unreachable;
            defer allocator.free(validators);
            state_transition.syncPubkeys(validators, &pubkey_index_map, index_pubkey_cache) catch unreachable;
            recordSegment(.cold_sync_pubkeys, elapsedSince(sync_start));

            // Step 3: Create CachedBeaconState
            const cache_start = std.time.nanoTimestamp();
            const genesis_root = beacon_state.genesisValidatorsRoot() catch unreachable;
            const beacon_config = config.BeaconConfig.init(self.chain_config, genesis_root.*);
            const cached_state = CachedBeaconState.createCachedBeaconState(allocator, beacon_state, .{
                .config = &beacon_config,
                .index_to_pubkey = index_pubkey_cache,
                .pubkey_to_index = &pubkey_index_map,
            }, .{ .skip_sync_committee_cache = !comptime fork.gte(.altair), .skip_sync_pubkeys = false }) catch unreachable;
            recordSegment(.cold_create_cached_state, elapsedSince(cache_start));

            recordSegment(.cold_total, elapsedSince(total_start));

            // Cleanup
            cached_state.deinit();
            allocator.destroy(cached_state);
            pubkey_index_map.deinit();
            index_pubkey_cache.deinit();
            allocator.destroy(index_pubkey_cache);
        }
    };
}

// ── Main ─────────────────────────────────────────────────────────────────────

fn loadStateBytesFromConfiguredEraFiles(allocator: std.mem.Allocator, stdout: anytype) ![]const u8 {
    if (download_era_options.era_files.len == 0) return error.NoEraFilesConfigured;

    var last_err: ?anyerror = null;

    for (download_era_options.era_files) |era_file| {
        const era_path = try std.fs.path.join(
            allocator,
            &[_][]const u8{ download_era_options.era_out_dir, era_file },
        );
        defer allocator.free(era_path);

        var era_reader = era.Reader.open(allocator, config.mainnet.config, era_path) catch |err| {
            last_err = err;
            try stdout.print("Skipping ERA file {s}: {s}\n", .{ era_path, @errorName(err) });
            continue;
        };
        defer era_reader.close(allocator);

        const state_bytes = era_reader.readSerializedState(allocator, null) catch |err| {
            last_err = err;
            try stdout.print("Skipping ERA file {s}: {s}\n", .{ era_path, @errorName(err) });
            continue;
        };

        try stdout.print("State file loaded from {s}: {} bytes\n", .{ era_path, state_bytes.len });
        return state_bytes;
    }

    if (last_err) |err| return err;
    return error.NoUsableEraStateFound;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);

    const allocator = gpa.allocator();
    const stdout = std.io.getStdOut().writer();
    var pool = try Node.Pool.init(allocator, 10_000_000);
    defer pool.deinit();

    const state_bytes = try loadStateBytesFromConfiguredEraFiles(allocator, stdout);
    defer allocator.free(state_bytes);

    const chain_config = config.mainnet.chain_config;
    const slot = slotFromStateBytes(state_bytes);
    const detected_fork = config.mainnet.config.forkSeq(slot);
    try stdout.print("Benchmarking STFN with state at fork: {s} (slot {})\n", .{ @tagName(detected_fork), slot });

    inline for (comptime std.enums.values(ForkSeq)) |fork| {
        if (detected_fork == fork) return runBenchmark(fork, allocator, &pool, stdout, state_bytes, chain_config);
    }
    return error.NoBenchmarkRan;
}

fn runBenchmark(
    comptime fork: ForkSeq,
    allocator: std.mem.Allocator,
    pool: *Node.Pool,
    stdout: anytype,
    state_bytes: []const u8,
    chain_config: config.ChainConfig,
) !void {
    defer state_transition.deinitStateTransition();

    // ── Setup: load and build warm CachedBeaconState ─────────────────────

    var beacon_state: ?*AnyBeaconState = try loadState(fork, allocator, pool, state_bytes);
    defer if (beacon_state) |state| {
        state.deinit();
        allocator.destroy(state);
    };

    const beacon_config = config.BeaconConfig.init(chain_config, (try beacon_state.?.genesisValidatorsRoot()).*);

    var pubkey_index_map = state_transition.PubkeyIndexMap.init(allocator);
    defer pubkey_index_map.deinit();

    const index_pubkey_cache = try allocator.create(state_transition.Index2PubkeyCache);
    index_pubkey_cache.* = state_transition.Index2PubkeyCache.init(allocator);
    defer {
        index_pubkey_cache.deinit();
        allocator.destroy(index_pubkey_cache);
    }

    const validators = try beacon_state.?.validatorsSlice(allocator);
    defer allocator.free(validators);
    try state_transition.syncPubkeys(validators, &pubkey_index_map, index_pubkey_cache);

    const cached_state = try CachedBeaconState.createCachedBeaconState(allocator, beacon_state.?, .{
        .config = &beacon_config,
        .index_to_pubkey = index_pubkey_cache,
        .pubkey_to_index = &pubkey_index_map,
    }, .{ .skip_sync_committee_cache = !comptime fork.gte(.altair), .skip_sync_pubkeys = false });
    beacon_state = null;
    defer {
        cached_state.deinit();
        allocator.destroy(cached_state);
    }

    const state_slot = try cached_state.state.slot();
    const validator_count = try cached_state.state.validatorsCount();
    try stdout.print("State deserialized: slot={}, validators={}\n", .{ state_slot, validator_count });

    // Advance state by 1 slot to warm all caches (processSlot populates hash caches)
    try state_transition.state_transition.processSlots(allocator, cached_state, state_slot + 1, .{});
    try cached_state.state.commit();
    try state_transition.buildSlashingsCacheFromStateIfNeeded(allocator, cached_state.state, &cached_state.slashings_cache);

    const warm_slot = try cached_state.state.slot();
    try stdout.print("State warmed to slot={}\n", .{warm_slot});

    // ── Compute target slots ─────────────────────────────────────────────

    // For warm slot: advance by 1 more slot (no epoch boundary)
    const warm_slot_target = warm_slot + 1;

    // For epoch boundary: find the next epoch boundary from the current slot
    const current_epoch_start = (warm_slot / preset.SLOTS_PER_EPOCH) * preset.SLOTS_PER_EPOCH;
    const next_epoch_start = current_epoch_start + preset.SLOTS_PER_EPOCH;
    // We need the seed state to be at last slot of epoch (next_epoch_start - 1)
    // Then the measured iteration advances by 1 slot, crossing the boundary
    const epoch_boundary_seed_slot = next_epoch_start - 1;
    const epoch_boundary_target = next_epoch_start;

    try stdout.print("Warm slot target: {} → {}\n", .{ warm_slot, warm_slot_target });
    try stdout.print("Epoch boundary: {} → {} (crossing epoch {})\n", .{ epoch_boundary_seed_slot, epoch_boundary_target, epoch_boundary_target / preset.SLOTS_PER_EPOCH });

    // ── Build epoch-boundary seed state ──────────────────────────────────
    // Advance a clone to last slot of the epoch so caches are warm at epoch boundary

    const epoch_seed_state = try cached_state.clone(allocator, .{ .transfer_cache = true });
    defer {
        epoch_seed_state.deinit();
        allocator.destroy(epoch_seed_state);
    }
    try state_transition.state_transition.processSlots(allocator, epoch_seed_state, epoch_boundary_seed_slot, .{});
    try epoch_seed_state.state.commit();

    try stdout.print("Epoch seed state advanced to slot={}\n\n", .{try epoch_seed_state.state.slot()});

    // ── Run benchmarks ───────────────────────────────────────────────────

    try stdout.print("Starting STFN benchmarks for {s} fork...\n\n", .{@tagName(fork)});

    var bench = zbench.Benchmark.init(allocator, .{ .iterations = 50 });
    defer bench.deinit();

    // Scenario 1: Warm slot transition (non-segmented)
    try bench.addParam("warm_slot", &WarmSlotBench(false){
        .cached_state = cached_state,
        .target_slot = warm_slot_target,
    }, .{});

    // Scenario 1: Warm slot transition (segmented)
    resetSegmentStats();
    try bench.addParam("warm_slot(segments)", &WarmSlotBench(true){
        .cached_state = cached_state,
        .target_slot = warm_slot_target,
    }, .{});

    // Scenario 2: Warm epoch boundary (non-segmented)
    try bench.addParam("warm_epoch_boundary", &WarmEpochBoundaryBench(false){
        .cached_state = epoch_seed_state,
        .target_slot = epoch_boundary_target,
    }, .{ .iterations = 10 });

    // Scenario 2: Warm epoch boundary (segmented)
    try bench.addParam("warm_epoch(segments)", &WarmEpochBoundaryBench(true){
        .cached_state = epoch_seed_state,
        .target_slot = epoch_boundary_target,
    }, .{ .iterations = 10 });

    // Scenario 3: State clone cost
    try bench.addParam("clone_transfer_cache", &CloneWithTransferBench{
        .cached_state = cached_state,
    }, .{});

    try bench.addParam("clone_no_transfer", &CloneNoTransferBench{
        .cached_state = cached_state,
    }, .{});

    // Scenario 4: Cold deserialization pipeline (segmented)
    try bench.addParam("cold_deser_pipeline", &ColdDeserializationBench(fork){
        .state_bytes = state_bytes,
        .chain_config = chain_config,
    }, .{ .iterations = 5 });

    try bench.run(stdout);
    try printSegmentStats(stdout);
}
