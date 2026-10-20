module github.com/peacedouts/lightning_ir

go 1.24

replace (
	cel.dev/expr => github.com/google/cel-spec v0.24.0
	golang.org/x/exp => github.com/golang/exp v0.0.0-20230515195305-f3d0a9c9a5cc
	golang.org/x/text => github.com/golang/text v0.22.0
	google.golang.org/genproto/googleapis/api => github.com/googleapis/go-genproto/googleapis/api v0.0.0-20240826202546-f6391c0de4c7
	google.golang.org/genproto/googleapis/rpc => github.com/googleapis/go-genproto/googleapis/rpc v0.0.0-20240826202546-f6391c0de4c7
	google.golang.org/protobuf => github.com/protocolbuffers/protobuf-go v1.34.2
	gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20201130134442-10cb98267c6c
	gopkg.in/yaml.v2 => github.com/go-yaml/yaml v0.0.0-20201117154620-7649d4548cb5
	gopkg.in/yaml.v3 => github.com/go-yaml/yaml v0.0.0-20220527083530-f6f7691b1fde
)

require (
	github.com/goccy/go-yaml v1.19.2
	github.com/google/cel-go v0.26.1
	github.com/lib/pq v1.12.3
)

require (
	cel.dev/expr v0.25.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	golang.org/x/exp v0.0.0-20240823005443-9b4947da3948 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
