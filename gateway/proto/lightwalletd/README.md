# Vendored lightwalletd protocol files

`compact_formats.proto` and `service.proto` are copied unchanged from
[zcash/lightwalletd](https://github.com/zcash/lightwalletd), tag `v0.6.1`, commit
`0bf0a40854de6bd9a50400f94f0f94fbb53ac743`, directory `lightwallet-protocol/walletrpc/`.
`LICENSE` is that directory's license (MIT), which covers them.

The gateway does not compile them: it decodes the few fields it needs with hand-written
`prost` messages. Tests read these files and check that the field numbers of those messages
match (`ChainMetadata`, `LightdInfo`, `TreeState`). To update, copy the files of a newer tag and
change the tag and commit above.
