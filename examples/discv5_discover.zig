//! End-to-end discv5 discovery smoke test.
//!
//! Run with:
//!   zig build run:discv5_discover -- --timeout-ms 30000 --duration-ms 60000 --max-results 65536 --lookups 64 --quiet

const std = @import("std");
const discv5 = @import("discv5");

pub const std_options: std.Options = .{ .log_level = .info };

const Allocator = std.mem.Allocator;
const Address = discv5.Address;
const NodeId = discv5.NodeId;
const event_poll_interval_ms: i64 = 10;
const request_timeout_ms: u64 = 2_000;
const request_retries: u32 = 1;
const maintenance_interval_ms: u64 = 100;
// A detached lookup request may first wait for its queue deadline, then each
// active attempt may wait once for WHOAREYOU and once for the authenticated
// response. Include one maintenance tick for queue pruning and another for
// active-request pruning.
const lookup_finish_grace_ms: i64 = request_timeout_ms +
    2 * request_timeout_ms * (request_retries + 1) +
    2 * maintenance_interval_ms;
const max_streamed_results: usize = 65_536;
const max_concurrent_lookups: usize = 1_024;
const max_total_lookups: usize = 65_536;
const max_duration_ms: u64 = 3_600_000;
const reconcile_interval_ms: i64 = 100;
const max_deadline_drain_events: usize = 1_024;

const LookupStatus = enum {
    active,
    finished,
    timed_out,
    event_deadline,
    runtime_stopped,

    fn label(self: LookupStatus) []const u8 {
        return switch (self) {
            .active => "active",
            .finished => "finished",
            .timed_out => "timed out",
            .event_deadline => "event deadline reached",
            .runtime_stopped => "runtime stopped",
        };
    }
};

const StopReason = enum {
    lookup_settled,
    output_limit,
    duration,
    event_deadline,
    runtime_stopped,

    fn label(self: StopReason) []const u8 {
        return switch (self) {
            .lookup_settled => "lookup settled",
            .output_limit => "output limit reached",
            .duration => "duration reached",
            .event_deadline => "event deadline reached",
            .runtime_stopped => "runtime stopped",
        };
    }
};

// Source, fetched 2026-05-15:
// https://github.com/eth-clients/eth2-networks/blob/master/shared/mainnet/bootstrap_nodes.txt
const default_bootnodes = [_][]const u8{
    "enr:-KG4QNTx85fjxABbSq_Rta9wy56nQ1fHK0PewJbGjLm1M4bMGx5-3Qq4ZX2-iFJ0pys_O90sVXNNOxp2E7afBsGsBrgDhGV0aDKQu6TalgMAAAD__________4JpZIJ2NIJpcIQEnfA2iXNlY3AyNTZrMaECGXWQ-rQ2KZKRH1aOW4IlPDBkY4XDphxg9pxKytFCkayDdGNwgiMog3VkcIIjKA",
    "enr:-KG4QF4B5WrlFcRhUU6dZETwY5ZzAXnA0vGC__L1Kdw602nDZwXSTs5RFXFIFUnbQJmhNGVU6OIX7KVrCSTODsz1tK4DhGV0aDKQu6TalgMAAAD__________4JpZIJ2NIJpcIQExNYEiXNlY3AyNTZrMaECQmM9vp7KhaXhI-nqL_R0ovULLCFSFTa9CPPSdb1zPX6DdGNwgiMog3VkcIIjKA",
    "enr:-Ku4QImhMc1z8yCiNJ1TyUxdcfNucje3BGwEHzodEZUan8PherEo4sF7pPHPSIB1NNuSg5fZy7qFsjmUKs2ea1Whi0EBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpD1pf1CAAAAAP__________gmlkgnY0gmlwhBLf22SJc2VjcDI1NmsxoQOVphkDqal4QzPMksc5wnpuC3gvSC8AfbFOnZY_On34wIN1ZHCCIyg",
    "enr:-Le4QPUXJS2BTORXxyx2Ia-9ae4YqA_JWX3ssj4E_J-3z1A-HmFGrU8BpvpqhNabayXeOZ2Nq_sbeDgtzMJpLLnXFgAChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISsaa0Zg2lwNpAkAIkHAAAAAPA8kv_-awoTiXNlY3AyNTZrMaEDHAD2JKYevx89W0CcFJFiskdcEzkH_Wdv9iW42qLK79ODdWRwgiMohHVkcDaCI4I",
    "enr:-Le4QLHZDSvkLfqgEo8IWGG96h6mxwe_PsggC20CL3neLBjfXLGAQFOPSltZ7oP6ol54OvaNqO02Rnvb8YmDR274uq8ChGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLosQxg2lwNpAqAX4AAAAAAPA8kv_-ax65iXNlY3AyNTZrMaEDBJj7_dLFACaxBfaI8KZTh_SSJUjhyAyfshimvSqo22WDdWRwgiMohHVkcDaCI4I",
    "enr:-Le4QH6LQrusDbAHPjU_HcKOuMeXfdEB5NJyXgHWFadfHgiySqeDyusQMvfphdYWOzuSZO9Uq2AMRJR5O4ip7OvVma8BhGV0aDKQtTA_KgEAAAAAIgEAAAAAAIJpZIJ2NIJpcISLY9ncg2lwNpAkAh8AgQIBAAAAAAAAAAmXiXNlY3AyNTZrMaECDYCZTZEksF-kmgPholqgVt8IXr-8L7Nu7YrZ7HUpgxmDdWRwgiMohHVkcDaCI4I",
    "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg",
    "enr:-LK4QA8FfhaAjlb_BXsXxSfiysR7R52Nhi9JBt4F8SPssu8hdE1BXQQEtVDC3qStCW60LSO7hEsVHv5zm8_6Vnjhcn0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAN4aBKJc2VjcDI1NmsxoQJerDhsJ-KxZ8sHySMOCmTO6sHM3iCFQ6VMvLTe948MyYN0Y3CCI4yDdWRwgiOM",
};

const Options = struct {
    timeout_ms: u64 = 30_000,
    max_results: usize = 4_096,
    lookup_count: usize = 1,
    sample_ms: u64 = 1_000,
    duration_ms: ?u64 = null,
    session_capacity: u32 = (discv5.Limits{}).session_capacity,
    print_enrs: bool = true,
    use_default_bootnodes: bool = true,
    target: ?NodeId = null,
    extra_bootnodes: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *Options, alloc: Allocator) void {
        for (self.extra_bootnodes.items) |bootnode| alloc.free(bootnode);
        self.extra_bootnodes.deinit(alloc);
    }

    fn appendBootnode(self: *Options, alloc: Allocator, bootnode: []const u8) !void {
        const owned = try alloc.dupe(u8, bootnode);
        errdefer alloc.free(owned);
        try self.extra_bootnodes.append(alloc, owned);
    }
};

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);

    const alloc = gpa.allocator();
    const output_io = init.io;

    var options = (try parseOptions(alloc, init.minimal.args)) orelse {
        var stdout_buf: [8192]u8 = undefined;
        var stdout_file_writer = std.Io.File.stdout().writer(output_io, &stdout_buf);
        const stdout = &stdout_file_writer.interface;
        try printUsage(stdout);
        try stdout.flush();
        return;
    };
    defer options.deinit(alloc);

    var runtime = std.Io.Threaded.init(alloc, .{});
    defer runtime.deinit();

    try runDiscovery(alloc, runtime.io(), output_io, &options);
}

fn runDiscovery(alloc: Allocator, io: std.Io, output_io: std.Io, options: *const Options) !void {
    var stdout_buf: [8192]u8 = undefined;
    var stdout_file_writer = std.Io.File.stdout().writer(output_io, &stdout_buf);
    const stdout = &stdout_file_writer.interface;
    defer stdout.flush() catch {};

    const target = options.target orelse blk: {
        var random_target: NodeId = undefined;
        io.random(&random_target);
        break :blk random_target;
    };

    const key_pair = discv5.secp256k1.KeyPair.generate(io);
    const pubkey = discv5.secp256k1.compressedPubkey(&key_pair);
    const local_node_id = try discv5.enr.nodeIdFromCompressedPubkey(&pubkey);

    const setup_started_at = std.Io.Timestamp.now(io, .awake);
    const runtime_config = discv5.Config{
        .bind_addresses = .{
            .ip4 = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        },
        .local_key_pair = key_pair,
        .local_node_id = local_node_id,
        .request_timeout_ms = request_timeout_ms,
        .request_retries = request_retries,
        // Keep the protocol's final K-closest result independent from the
        // executable's larger streamed-output budget.
        .lookup_num_results = discv5.MAX_LOOKUP_RESULTS,
        .lookup_timeout_ms = options.timeout_ms,
        .limits = .{ .session_capacity = options.session_capacity },
    };
    const runtime_options = discv5.Options{
        .maintenance_interval_ms = maintenance_interval_ms,
    };

    const discovery_runtime = try discv5.Runtime.init(io, alloc, runtime_config, runtime_options);
    var runtime_group: std.Io.Group = .init;
    runtime_group.concurrent(io, runRuntime, .{discovery_runtime}) catch |err| {
        discovery_runtime.deinit();
        return err;
    };
    defer {
        discovery_runtime.stop();
        runtime_group.await(io) catch {};
        discovery_runtime.deinit();
    }

    try waitForRuntime(discovery_runtime);
    try setLocalEnr(alloc, discovery_runtime, key_pair);

    var added_bootnodes: usize = 0;
    if (options.use_default_bootnodes) {
        for (default_bootnodes) |bootnode| {
            if (try addBootnode(alloc, discovery_runtime, bootnode)) added_bootnodes += 1;
        }
    }
    for (options.extra_bootnodes.items) |bootnode| {
        if (try addBootnode(alloc, discovery_runtime, bootnode)) added_bootnodes += 1;
    }
    if (added_bootnodes == 0) return error.NoBootnodes;

    var pending_lookups = std.AutoHashMap(u32, void).init(alloc);
    defer pending_lookups.deinit();
    try pending_lookups.ensureTotalCapacity(@intCast(options.lookup_count));
    var lookups_launched: usize = 0;
    for (0..options.lookup_count) |index| {
        const lookup_target = deriveLookupTarget(target, index);
        const lookup_id = try discovery_runtime.startLookup(lookup_target);
        try pending_lookups.put(lookup_id, {});
        lookups_launched += 1;
    }

    const workload_started_at = std.Io.Timestamp.now(io, .awake);
    const setup_elapsed_ms = setup_started_at.durationTo(workload_started_at).toMilliseconds();
    const event_deadline = workload_started_at.addDuration(.fromMilliseconds(
        @intCast(options.timeout_ms + @as(u64, @intCast(lookup_finish_grace_ms))),
    ));
    const duration_deadline: ?std.Io.Timestamp = if (options.duration_ms) |duration_ms|
        workload_started_at.addDuration(.fromMilliseconds(@intCast(duration_ms)))
    else
        null;

    try stdout.print("discv5 discovery stress run\n", .{});
    try stdout.print("bound: ", .{});
    if (discovery_runtime.boundAddress(.ip4)) |addr| {
        try addr.format(stdout);
    } else {
        try stdout.print("<none>", .{});
    }
    try stdout.print("\nbootnodes: {d}\nlookups: {d}\nsession_capacity: {d}\nbase_target: ", .{
        added_bootnodes,
        options.lookup_count,
        options.session_capacity,
    });
    try printNodeId(stdout, &target);
    if (options.duration_ms) |duration_ms| try stdout.print("\nduration_ms: {d}", .{duration_ms});
    try stdout.print("\n\n", .{});
    try stdout.flush();

    var seen = std.AutoHashMap(NodeId, void).init(alloc);
    defer seen.deinit();

    var found: usize = 0;
    var discovered_events: usize = 0;
    var final_results: usize = 0;
    var lookups_finished: usize = 0;
    var lookups_timed_out: usize = 0;
    var lookup_status: LookupStatus = .active;
    var stop_reason: StopReason = .event_deadline;
    var finish_drain_deadline: ?std.Io.Timestamp = null;
    var deadline_drain_remaining = max_deadline_drain_events;
    var next_sample_at = workload_started_at.addDuration(.fromMilliseconds(@intCast(options.sample_ms)));
    var next_reconcile_at = workload_started_at.addDuration(.fromMilliseconds(reconcile_interval_ms));
    var peak_sessions: usize = 0;
    var peak_routing: usize = 0;
    var peak_connected: usize = 0;

    while (true) {
        while (discovery_runtime.popLookupResult()) |lookup_result| {
            if (!pending_lookups.remove(lookup_result.lookup_id)) continue;
            lookups_finished += 1;
            if (lookup_result.reason == .timed_out) lookups_timed_out += 1;
            final_results += lookup_result.enrs.slice().len;
            for (lookup_result.enrs.slice()) |*raw_enr| {
                if (found >= options.max_results) break;
                if (try recordFoundEnr(alloc, stdout, &seen, raw_enr.slice(), options.print_enrs)) found += 1;
            }
            if (lookup_result.reason == .runtime_stopped) lookup_status = .runtime_stopped;
            if (duration_deadline == null and pending_lookups.count() == 0) {
                if (lookup_status != .runtime_stopped)
                    lookup_status = if (lookups_timed_out == 0) .finished else .timed_out;
                finish_drain_deadline = std.Io.Timestamp.now(io, .awake).addDuration(
                    .fromMilliseconds(lookup_finish_grace_ms),
                );
                deadline_drain_remaining = max_deadline_drain_events;
            }
            try stdout.flush();
        }

        if (found >= options.max_results) {
            stop_reason = .output_limit;
            break;
        }

        const now = std.Io.Timestamp.now(io, .awake);
        if (duration_deadline) |deadline| {
            if (deadline.durationTo(now).toNanoseconds() >= 0) {
                stop_reason = .duration;
                break;
            }
        }
        if (duration_deadline != null and next_reconcile_at.durationTo(now).toNanoseconds() >= 0) {
            // Pending IDs include both actor-active lookups and terminal results
            // whose reserved slots have not been consumed yet.
            var deficit = options.lookup_count -| pending_lookups.count();
            while (deficit > 0 and lookups_launched < max_total_lookups) : (deficit -= 1) {
                const replacement_target = deriveLookupTarget(target, lookups_launched);
                const replacement_id = discovery_runtime.startLookup(replacement_target) catch |err| switch (err) {
                    error.TooManyLookups => break,
                    else => return err,
                };
                try pending_lookups.put(replacement_id, {});
                lookups_launched += 1;
            }
            next_reconcile_at = now.addDuration(.fromMilliseconds(reconcile_interval_ms));
        }
        if (next_sample_at.durationTo(now).toNanoseconds() >= 0) {
            if (discovery_runtime.metricsSnapshot()) |sample| {
                peak_sessions = @max(peak_sessions, sample.active_session_count);
                peak_routing = @max(peak_routing, sample.kad_table_size);
                peak_connected = @max(peak_connected, sample.connected_peer_count);
                const elapsed_ms = workload_started_at.durationTo(now).toMilliseconds();
                try stdout.print(
                    "sample: elapsed_ms={d} unobserved_lookup_ids={d} active_lookups={d} active_requests={d} queued_requests={d} unique_enrs={d} routing={d} connected={d} sessions={d} packets={d} findnode={d} nodes={d} dropped={d}\n",
                    .{
                        elapsed_ms,
                        pending_lookups.count(),
                        sample.active_lookup_count,
                        sample.active_request_count,
                        sample.queued_request_count,
                        found,
                        sample.kad_table_size,
                        sample.connected_peer_count,
                        sample.active_session_count,
                        sample.received_packet_count,
                        sample.sentMessageCount(.findnode),
                        sample.rcvdMessageCount(.nodes),
                        sample.dropped_event_count,
                    },
                );
                try stdout.flush();
            } else |_| {}
            next_sample_at = now.addDuration(.fromMilliseconds(@intCast(options.sample_ms)));
        }
        const expired: ?StopReason = if (finish_drain_deadline) |deadline|
            if (deadline.durationTo(now).toNanoseconds() >= 0) .lookup_settled else null
        else if (duration_deadline == null and lookup_status == .active and event_deadline.durationTo(now).toNanoseconds() >= 0)
            .event_deadline
        else
            null;
        if (expired != null and deadline_drain_remaining == 0) {
            if (expired.? == .event_deadline) lookup_status = .event_deadline;
            stop_reason = expired.?;
            break;
        }

        const event_value = discovery_runtime.popEvent() orelse {
            if (expired) |reason| {
                if (reason == .event_deadline) lookup_status = .event_deadline;
                stop_reason = reason;
                break;
            }
            if (discovery_runtime.isClosed()) {
                if (lookup_status == .active) lookup_status = .runtime_stopped;
                stop_reason = .runtime_stopped;
                break;
            }
            try std.Io.sleep(io, .fromMilliseconds(event_poll_interval_ms), .awake);
            continue;
        };
        if (expired != null) {
            deadline_drain_remaining -= 1;
        } else {
            deadline_drain_remaining = max_deadline_drain_events;
        }
        var event = event_value;
        defer event.deinit(alloc);

        switch (event) {
            .discovered_enr => |discovered| {
                discovered_events += 1;
                if (try recordFoundParsedEnr(
                    alloc,
                    stdout,
                    &seen,
                    discovered.raw.slice(),
                    &discovered.enr,
                    options.print_enrs,
                )) {
                    found += 1;
                    if (options.print_enrs) try stdout.flush();
                }
            },
            // Compatibility observation only. Terminal lookup state and payloads
            // are consumed from the reserved reliable result plane above.
            .lookup_finished => {},
            else => {},
        }
    }

    const lookup_elapsed_ms = workload_started_at.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds();
    try stdout.print("\nsummary: {d} unique ENRs observed from {d} discovery events and {d} final results\n", .{
        found,
        discovered_events,
        final_results,
    });
    try stdout.print(
        "lookup_status: {s}\nobservation_stop: {s}\nlookups: {d} launched, {d} completion events, {d} timed out, {d} unobserved IDs\n",
        .{ lookup_status.label(), stop_reason.label(), lookups_launched, lookups_finished, lookups_timed_out, pending_lookups.count() },
    );
    try stdout.print("setup_ms: {d}\nlookup_elapsed_ms: {d}\n", .{ setup_elapsed_ms, lookup_elapsed_ms });
    const snapshot = discovery_runtime.metricsSnapshot() catch |err| {
        try stdout.print("metrics: unavailable ({})\n", .{err});
        return;
    };
    peak_sessions = @max(peak_sessions, snapshot.active_session_count);
    peak_routing = @max(peak_routing, snapshot.kad_table_size);
    peak_connected = @max(peak_connected, snapshot.connected_peer_count);
    const actor_completed = lookups_launched -| snapshot.active_lookup_count;
    try stdout.print(
        "routing: {d} peers, {d} connected, {d} sessions\nwork: {d} active lookups, {d} actor-completed lookups, {d} active requests, {d} queued requests\nsampled_peaks: {d} routing, {d} connected, {d} sessions\npackets: {d} received, {d} processed, {d} filtered\nmessages: {d} FINDNODE sent, {d} NODES received\nevents_dropped: {d}\n",
        .{
            snapshot.kad_table_size,
            snapshot.connected_peer_count,
            snapshot.active_session_count,
            snapshot.active_lookup_count,
            actor_completed,
            snapshot.active_request_count,
            snapshot.queued_request_count,
            peak_routing,
            peak_connected,
            peak_sessions,
            snapshot.received_packet_count,
            snapshot.processed_packet_count,
            snapshot.filtered_packet_count,
            snapshot.sentMessageCount(.findnode),
            snapshot.rcvdMessageCount(.nodes),
            snapshot.dropped_event_count,
        },
    );
    try stdout.print(
        "contacts: {d}/{d} retained, inserted={d} updated={d} capacity_rejected={d} policy_rejected={d} removed={d}\nsession_churn: capacity={d} inserted={d} rekeyed={d} capacity_reused={d} maintenance_expired={d} authenticated_refreshed={d} replay_rejected={d} nonce_exhaustion_rejected={d}\n",
        .{
            snapshot.contact_count,
            snapshot.contact_capacity,
            snapshot.contact_inserted_total,
            snapshot.contact_updated_total,
            snapshot.contact_capacity_rejected_total,
            snapshot.contact_policy_rejected_total,
            snapshot.contact_removed_total,
            snapshot.session_capacity,
            snapshot.session_inserted_total,
            snapshot.session_rekeyed_total,
            snapshot.session_capacity_reused_total,
            snapshot.session_maintenance_expired_total,
            snapshot.session_authenticated_refreshed_total,
            snapshot.session_replay_rejected_total,
            snapshot.session_nonce_exhaustion_rejected_total,
        },
    );
    for (std.enums.values(discv5.EventKind)) |kind| {
        const count = snapshot.droppedEventCount(kind);
        if (count == 0) continue;
        try stdout.print("event_drop_kind: kind={s} count={d}\n", .{ kind.label(), count });
    }
}

fn runRuntime(runtime: *discv5.Runtime) void {
    runtime.run() catch |err| std.debug.print("discv5 runtime stopped with {}\n", .{err});
}

fn waitForRuntime(runtime: *const discv5.Runtime) !void {
    while (!runtime.isRunning()) {
        if (runtime.isClosed()) return error.RuntimeStopped;
        try std.Thread.yield();
    }
}

fn setLocalEnr(
    alloc: Allocator,
    runtime: *discv5.Runtime,
    key_pair: discv5.secp256k1.KeyPair,
) !void {
    var builder = discv5.enr.Builder.init(alloc, key_pair, 1);
    if (runtime.boundAddress(.ip4)) |addr| {
        builder.udp = addr.getPort();
    }

    const local_enr = try builder.encode();
    defer alloc.free(local_enr);

    try runtime.setLocalEnr(local_enr);
}

fn parseOptions(alloc: Allocator, args_value: std.process.Args) !?Options {
    var options = Options{};
    errdefer options.deinit(alloc);

    var args = try std.process.Args.Iterator.initAllocator(args_value, alloc);
    defer args.deinit();

    _ = args.next();
    while (args.next()) |arg_z| {
        const arg = arg_z[0..arg_z.len];

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            options.deinit(alloc);
            return null;
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            const value = args.next() orelse return error.MissingTimeout;
            options.timeout_ms = try parsePositiveInt(u64, value);
            if (options.timeout_ms > std.math.maxInt(i64) - lookup_finish_grace_ms)
                return error.TimeoutTooLarge;
        } else if (std.mem.eql(u8, arg, "--max-results")) {
            const value = args.next() orelse return error.MissingMaxResults;
            options.max_results = try parsePositiveInt(usize, value);
            if (options.max_results > max_streamed_results) return error.TooManyResults;
        } else if (std.mem.eql(u8, arg, "--lookups")) {
            const value = args.next() orelse return error.MissingLookupCount;
            options.lookup_count = try parsePositiveInt(usize, value);
            if (options.lookup_count > max_concurrent_lookups) return error.TooManyLookups;
        } else if (std.mem.eql(u8, arg, "--sample-ms")) {
            const value = args.next() orelse return error.MissingSampleInterval;
            options.sample_ms = try parsePositiveInt(u64, value);
            if (options.sample_ms > std.math.maxInt(i64)) return error.SampleIntervalTooLarge;
        } else if (std.mem.eql(u8, arg, "--duration-ms")) {
            const value = args.next() orelse return error.MissingDuration;
            options.duration_ms = try parsePositiveInt(u64, value);
            if (options.duration_ms.? > max_duration_ms) return error.DurationTooLarge;
        } else if (std.mem.eql(u8, arg, "--session-capacity")) {
            const value = args.next() orelse return error.MissingSessionCapacity;
            options.session_capacity = try parsePositiveInt(u32, value);
            if (options.session_capacity > (discv5.Limits{}).session_capacity)
                return error.TooManySessions;
        } else if (std.mem.eql(u8, arg, "--quiet")) {
            options.print_enrs = false;
        } else if (std.mem.eql(u8, arg, "--target")) {
            const value = args.next() orelse return error.MissingTarget;
            options.target = try parseNodeId(value);
        } else if (std.mem.eql(u8, arg, "--bootnode")) {
            const value = args.next() orelse return error.MissingBootnode;
            try options.appendBootnode(alloc, value);
        } else if (std.mem.eql(u8, arg, "--no-default-bootnodes")) {
            options.use_default_bootnodes = false;
        } else if (std.mem.startsWith(u8, arg, "enr:")) {
            try options.appendBootnode(alloc, arg);
        } else {
            std.debug.print("unknown argument: {s}\n", .{arg});
            return error.InvalidArgument;
        }
    }

    return options;
}

fn parsePositiveInt(comptime T: type, text: []const u8) !T {
    const value = try std.fmt.parseUnsigned(T, text, 10);
    if (value == 0) return error.ValueMustBePositive;
    return value;
}

fn parseNodeId(text: []const u8) !NodeId {
    if (text.len != 64 and text.len != 66) return error.InvalidNodeId;
    if (text.len == 66 and !std.mem.startsWith(u8, text, "0x")) return error.InvalidNodeId;

    var node_id: NodeId = undefined;
    _ = discv5.hex.hexToBytes(&node_id, text) catch return error.InvalidNodeId;
    return node_id;
}

fn addBootnode(alloc: Allocator, runtime: *discv5.Runtime, bootnode: []const u8) !bool {
    const raw = discv5.enr.decodeText(alloc, bootnode) catch |err| {
        std.debug.print("skipping invalid bootnode: {}\n", .{err});
        return false;
    };
    defer alloc.free(raw);

    if (!try runtime.addEnr(raw)) {
        std.debug.print("skipping unusable bootnode ENR\n", .{});
        return false;
    }
    return true;
}

fn deriveLookupTarget(base: NodeId, index: usize) NodeId {
    if (index == 0) return base;
    var index_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &index_bytes, @intCast(index), .big);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&base);
    hasher.update(&index_bytes);
    var target: NodeId = undefined;
    hasher.final(&target);
    return target;
}

fn recordFoundEnr(
    alloc: Allocator,
    stdout: *std.Io.Writer,
    seen: *std.AutoHashMap(NodeId, void),
    raw_enr: []const u8,
    print_enr: bool,
) !bool {
    const parsed = discv5.enr.decode(raw_enr) catch return false;
    return try recordFoundParsedEnr(alloc, stdout, seen, raw_enr, &parsed, print_enr);
}

fn recordFoundParsedEnr(
    alloc: Allocator,
    stdout: *std.Io.Writer,
    seen: *std.AutoHashMap(NodeId, void),
    raw_enr: []const u8,
    parsed: *const discv5.Enr,
    print_enr: bool,
) !bool {
    const node_id = (try parsed.nodeId()) orelse return false;
    const seen_entry = try seen.getOrPut(node_id);
    if (seen_entry.found_existing) return false;
    if (!print_enr) return true;

    const text = try discv5.enr.encodeText(alloc, raw_enr);
    defer alloc.free(text);

    try stdout.print("found ", .{});
    try printNodeId(stdout, &node_id);
    try printEnrAddresses(stdout, parsed);
    try stdout.print("\n{s}\n", .{text});
    return true;
}

fn printNodeId(stdout: *std.Io.Writer, node_id: *const NodeId) !void {
    try stdout.print("0x{x}", .{node_id});
}

fn printEnrAddresses(stdout: *std.Io.Writer, parsed: *const discv5.Enr) !void {
    if (parsed.ip) |ip| {
        if (parsed.udp) |port| {
            const addr = Address{ .ip4 = .{ .bytes = ip, .port = port } };
            try stdout.print(" ", .{});
            try addr.format(stdout);
        }
    }
    if (parsed.ip6) |ip6| {
        if (parsed.udp6) |port| {
            const addr = Address{ .ip6 = .{ .bytes = ip6, .port = port } };
            try stdout.print(" ", .{});
            try addr.format(stdout);
        }
    }
}

fn printUsage(stdout: *std.Io.Writer) !void {
    try stdout.print(
        \\Usage:
        \\  zig build run:discv5_discover -- [options] [enr:...]
        \\
        \\Options:
        \\  --timeout-ms N            Stop after N milliseconds (default: 30000)
        \\  --max-results N           Stop after N unique ENRs, max 65536 (default: 4096)
        \\  --lookups N               Start N concurrent lookups, max 1024 (default: 1)
        \\  --sample-ms N             Print state every N milliseconds (default: 1000)
        \\  --duration-ms N           Replenish lookups for N ms, max 3600000
        \\  --session-capacity N      Session LRU capacity, max 2000 (default: 2000)
        \\  --quiet                   Suppress individual ENR output
        \\  --target 0xHEX            Base target; concurrent lookups derive spread targets
        \\  --bootnode enr:...        Add an extra bootnode ENR
        \\  --no-default-bootnodes    Use only bootnodes passed on the command line
        \\  -h, --help                Show this help
        \\
    , .{});
}
