# GreenMail fixture inputs

Upgrade the image and schema together, review upstream changes, and rerun
`cargo run --locked --example check-policy`, `cargo deny --locked --all-features check`,
and `cargo test --locked --test greenmail --features docker-tests`.

- Release: **2.1.15**, tag `release-2.1.15`.
- Source commit: `3b8ea7df70e48bb67052a333a6707c34b5790c30`.
- [Unmodified upstream OpenAPI schema](https://github.com/greenmail-mail-test/greenmail/blob/3b8ea7df70e48bb67052a333a6707c34b5790c30/greenmail-standalone/src/main/resources/greenmail-openapi.yml):
  vendored as `greenmail-2.1.15.yml`. Upstream leaves `info.version` as the Maven
  placeholder `${project.version}`; the source commit fixes its provenance.
- [Upstream license](https://github.com/greenmail-mail-test/greenmail/blob/3b8ea7df70e48bb67052a333a6707c34b5790c30/license.txt):
  Apache-2.0, retained in `GREENMAIL-LICENSE.txt`.
- `checksums.json` contains SHA-256 checksums checked by the policy command.
- Image: `greenmail/standalone:2.1.15@sha256:309ba544ea482e5d4265d09921cdab07c8dad2cc4481d715c9b8ff5d3f0a149f`.
- ARM64 manifest: `sha256:175af0b7d45bc9978ffb28fb87e1d3fe1dee4d5791fcf59fa3fbb184378c90fb`.
- x86-64 manifest: `sha256:3e72e4b4a24f2977e26fd6f619bbd62ac039c5185b33f9366de99fb5da118150`.

The image index was inspected with `docker buildx imagetools inspect
greenmail/standalone:2.1.15` on 2026-11-04. Both native architectures are present;
no emulation fallback is needed.

The [release notes](https://github.com/greenmail-mail-test/greenmail/releases/tag/release-2.1.15)
include mailbox namespace confinement and updated Jackson, Bouncy Castle, and JDK
dependencies. The schema and license are unchanged from 2.1.13.

## Schema corrections

The upstream YAML remains byte-for-byte unchanged. The typed client applies
`message-uid-schema.json` to `Message.properties.uid`: GreenMail returns a decimal
**string**, while its schema declares a number. The string must encode a positive
UID; the DTO consumer also checks it fits `u64`.

The live wire key for message identity is `Message-ID`, not the schema's optional
`messageId`. The DTO requires `Message-ID` for our synthetic fixture. The
[release serializer](https://github.com/greenmail-mail-test/greenmail/blob/3b8ea7df70e48bb67052a333a6707c34b5790c30/greenmail-standalone/src/main/java/com/icegreen/greenmail/standalone/JacksonObjectMapperProvider.java)
confirms both differences. The Docker contract checks actual responses on every run.

The configuration schema also requires `serviceConfigurations` while declaring
`serverSetups`. The bootstrap does not consume that endpoint; it verifies actual
listener bindings and authentication instead. Review that discrepancy before
adding configuration DTOs.
