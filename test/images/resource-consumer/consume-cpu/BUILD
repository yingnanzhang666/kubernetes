package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_binary",
    "go_library",
)

go_binary(
    name = "consume-cpu",
    library = ":go_default_library",
    tags = ["automanaged"],
)

go_library(
    name = "go_default_library",
    srcs = ["consume_cpu.go"],
    tags = ["automanaged"],
    deps = ["//vendor:bitbucket.org/bertimus9/systemstat"],
)
