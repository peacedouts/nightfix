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

require github.com/lib/pq v1.12.3
