# GreenMail fixture inputs

Upgrade the image and schema together, review upstream changes, and rerun
`cargo run --locked --example check-policy`, `cargo deny --locked --all-features check`,
and `cargo test --locked --test greenmail --features docker-tests`.

- Release: **2.1.13**, tag `release-2.1.13`.
- Source commit: `cd4d14ff26fca905dae8e250c29879402287d32d`.
- [Unmodified upstream OpenAPI schema](https://github.com/greenmail-mail-test/greenmail/blob/cd4d14ff26fca905dae8e250c29879402287d32d/greenmail-standalone/src/main/resources/greenmail-openapi.yml):
  vendored as `greenmail-2.1.13.yml`. Upstream leaves `info.version` as the Maven
  placeholder `${project.version}`; the source commit fixes its provenance.
- [Upstream license](https://github.com/greenmail-mail-test/greenmail/blob/cd4d14ff26fca905dae8e250c29879402287d32d/license.txt):
  Apache-2.0, retained in `GREENMAIL-LICENSE.txt`.
- `checksums.json` contains SHA-256 checksums checked by the policy command.
- Image: `greenmail/standalone:2.1.13@sha256:3df66b7edd01c8a301343ca5e3601d8674760d4708655573560c24745e624fb2`.
- ARM64 manifest: `sha256:9553f455b79f009cf1330805e4691907ac73d4a40935f55374eb9d4885b18cac`.
- x86-64 manifest: `sha256:04962e71656a058b8cb5245b52836486470a7447e9ef6920b52cf04fe47097b3`.

The image index was inspected with `docker buildx imagetools inspect
greenmail/standalone:2.1.13` on 2026-09-08. Both native architectures are present;
no emulation fallback is needed.

## Schema corrections

The upstream YAML remains byte-for-byte unchanged. The typed client applies
`message-uid-schema.json` to `Message.properties.uid`: GreenMail returns a decimal
**string**, while its schema declares a number. The string must encode a positive
UID; the DTO consumer also checks it fits `u64`.

The live wire key for message identity is `Message-ID`, not the schema's optional
`messageId`. The DTO requires `Message-ID` for our synthetic fixture. The
[release serializer](https://github.com/greenmail-mail-test/greenmail/blob/cd4d14ff26fca905dae8e250c29879402287d32d/greenmail-standalone/src/main/java/com/icegreen/greenmail/standalone/JacksonObjectMapperProvider.java)
confirms both differences. The Docker contract checks actual responses on every run.

The configuration schema also requires `serviceConfigurations` while declaring
`serverSetups`. The bootstrap does not consume that endpoint; it verifies actual
listener bindings and authentication instead. Review that discrepancy before
adding configuration DTOs.
