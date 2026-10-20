package canonical

import "testing"

func TestTransform(t *testing.T) {
	cases := map[string]string{
		`{"b":2,"a":1}`:                       `{"a":1,"b":2}`,
		`{ "z" : [ 1 , 2.50, -0 ] , "y":null}`: `{"y":null,"z":[1,2.5,0]}`,
		`{"s":"tab\there \u00e9 \u2028"}`:      "{\"s\":\"tab\\there é \u2028\"}",
		`{"n":1e21,"m":1e-7,"k":123456789012}`: `{"k":123456789012,"m":1e-7,"n":1e+21}`,
		`{"\u20ac":1,"\r":2,"1":3}`:            "{\"\\r\":2,\"1\":3,\"€\":1}",
		`{"html":"<a>&</a>"}`:                  `{"html":"<a>&</a>"}`,
		`[true,false,{"x":{"b":1,"a":2}}]`:     `[true,false,{"x":{"a":2,"b":1}}]`,
	}
	for in, want := range cases {
		got, err := Transform([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if string(got) != want {
			t.Errorf("Transform(%s)\n got %s\nwant %s", in, got, want)
		}
	}
}

func TestStableAcrossKeyOrder(t *testing.T) {
	a, _ := Marshal(map[string]any{"x": 1, "y": map[string]any{"q": true, "p": "s"}})
	b, _ := Transform([]byte(`{"y":{"p":"s","q":true},"x":1.0}`))
	if string(a) != string(b) {
		t.Fatalf("%s != %s", a, b)
	}
}
