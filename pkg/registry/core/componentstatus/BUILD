package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_library",
    "go_test",
)

go_library(
    name = "go_default_library",
    srcs = [
        "doc.go",
        "rest.go",
        "validator.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//pkg/api:go_default_library",
        "//pkg/apis/meta/v1:go_default_library",
        "//pkg/probe:go_default_library",
        "//pkg/probe/http:go_default_library",
        "//pkg/runtime:go_default_library",
        "//pkg/util/net:go_default_library",
    ],
)

go_test(
    name = "go_default_test",
    srcs = [
        "rest_test.go",
        "validator_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
    deps = [
        "//pkg/api:go_default_library",
        "//pkg/apis/meta/v1:go_default_library",
        "//pkg/probe:go_default_library",
        "//pkg/util/diff:go_default_library",
    ],
)
