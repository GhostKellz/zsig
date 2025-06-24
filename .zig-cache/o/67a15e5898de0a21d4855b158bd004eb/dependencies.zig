pub const packages = struct {
    pub const @"12200000000000000000000000000000000000000000000000000000000000000000" = struct {
        pub const available = false;
    };
    pub const @"12207b5911f4f8f3467953249a7be385d48209ba235854722be1103d6735ed84ce38" = struct {
        pub const build_root = "/home/chris/.cache/zig/p/zcrypto-0.0.0-rgQAI9hbAwB7WRH0-PNGeVMkmnvjhdSCCbojWFRyK-EQ";
        pub const build_zig = @import("12207b5911f4f8f3467953249a7be385d48209ba235854722be1103d6735ed84ce38");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "zcrypto", "12207b5911f4f8f3467953249a7be385d48209ba235854722be1103d6735ed84ce38" },
    .{ "tokioZ", "12200000000000000000000000000000000000000000000000000000000000000000" },
};
