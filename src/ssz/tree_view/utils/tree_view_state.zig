const std = @import("std");
const Allocator = std.mem.Allocator;
const Node = @import("persistent_merkle_tree").Node;
const Gindex = @import("persistent_merkle_tree").Gindex;
const CloneOpts = @import("clone_opts.zig").CloneOpts;

/// Common state for tree views that use runtime gindex-based child caching.
///
/// Used by list, array, bitvector, and bitlist views (chunk-based).
/// NOT used by ContainerTreeView (which uses comptime field-indexed tuples).
pub const TreeViewState = struct {
    allocator: Allocator,
    pool: *Node.Pool,
    root: Node.Id,

    /// cached nodes for faster access of already-visited children
    children_nodes: std.AutoHashMapUnmanaged(Gindex, Node.Id),

    /// whether the corresponding child node/data has changed since the last update of the root
    changed: std.AutoArrayHashMapUnmanaged(Gindex, void),

    pub fn init(self: *TreeViewState, allocator: Allocator, pool: *Node.Pool, root: Node.Id) !void {
        try pool.ref(root);
        self.* = .{
            .allocator = allocator,
            .pool = pool,
            .root = root,
            .children_nodes = .empty,
            .changed = .empty,
        };
    }

    pub fn deinit(self: *TreeViewState) void {
        self.clearChildrenNodesCache();
        self.children_nodes.deinit(self.allocator);
        self.changed.deinit(self.allocator);
        self.pool.unref(self.root);
    }

    pub fn getChildNode(self: *TreeViewState, gindex: Gindex) !Node.Id {
        const gop = try self.children_nodes.getOrPut(self.allocator, gindex);
        if (gop.found_existing) {
            return gop.value_ptr.*;
        }
        const child_node = try self.root.getNode(self.pool, gindex);
        gop.value_ptr.* = child_node;
        return child_node;
    }

    pub fn setChildNode(self: *TreeViewState, gindex: Gindex, node: Node.Id) !void {
        // Check if this gindex was already marked changed BEFORE marking it.
        // If it was, the old node in children_nodes was placed by a prior setChildNode
        // call (an uncommitted newly-allocated node) and is now orphaned — free it.
        // If it wasn't, the old node was placed by getChildNode (a borrowed reference
        // navigated from the tree) and must NOT be freed — its lifetime is managed
        // by the tree structure, not individual refcounts.
        const was_changed = self.changed.contains(gindex);
        try self.changed.put(self.allocator, gindex, {});
        const opt_old_node = try self.children_nodes.fetchPut(
            self.allocator,
            gindex,
            node,
        );
        if (opt_old_node) |old_node| {
            if (was_changed) {
                self.pool.unref(old_node.value);
            }
        }
    }

    pub fn commitNodes(self: *TreeViewState) !void {
        if (self.changed.count() == 0) {
            return;
        }

        const nodes = try self.allocator.alloc(Node.Id, self.changed.count());
        defer self.allocator.free(nodes);

        const gindices = self.changed.keys();
        Gindex.sortAsc(gindices);

        for (gindices, 0..) |gindex, i| {
            if (self.children_nodes.get(gindex)) |child_node| {
                nodes[i] = child_node;
            } else {
                return error.ChildNotFound;
            }
        }

        const new_root = try self.root.setNodesGrouped(self.pool, gindices, nodes);
        try self.pool.ref(new_root);
        self.pool.unref(self.root);
        self.root = new_root;

        self.changed.clearRetainingCapacity();
    }

    pub fn clearChildrenNodesCache(self: *TreeViewState) void {
        // Only unref nodes that were placed by setChildNode (tracked in `changed`)
        // and haven't been committed yet. These are owned, uncommitted nodes.
        // Nodes placed by getChildNode are borrowed references navigated from the
        // tree — their lifetime is managed by the tree structure (parent→child refs),
        // not by individual refcounts. Freeing them corrupts live trees that share
        // those subtrees via structural sharing.
        for (self.changed.keys()) |gindex| {
            if (self.children_nodes.get(gindex)) |node_id| {
                self.pool.unref(node_id);
            }
        }
        self.children_nodes.clearRetainingCapacity();
    }

    pub fn clearCache(self: *TreeViewState) void {
        self.clearChildrenNodesCache();
        self.changed.clearRetainingCapacity();
    }

    pub fn clone(self: *TreeViewState, opts: CloneOpts, out: *TreeViewState) !void {
        try out.init(self.allocator, self.pool, self.root);

        if (!opts.transfer_cache) {
            return;
        }

        out.children_nodes = self.children_nodes;

        for (self.changed.keys()) |gindex| {
            _ = out.children_nodes.remove(gindex);
        }

        self.children_nodes = .empty;
        self.changed.clearRetainingCapacity();
    }
};
