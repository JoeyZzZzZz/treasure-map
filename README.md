# Treasure Map

Treasure Map is a static analysis tool for IoT firmware research.

Given an extracted firmware filesystem, it decompiles every binary,
traces data flow from external input sources to sensitive sinks, and
produces structured analyses optimized for AI-assisted reasoning.

Designed for security researchers who reverse IoT firmware and want
their AI co-pilot (Claude Code, Cursor, ChatGPT) to do the heavy
lifting on vulnerability understanding.

CLI: `tmap`. AGPL-3.0.

## Status

This project is in early development. APIs and behaviors will change.

## Upgrading from earlier versions

Treasure Map is at v0.x and the database schema is not yet stable. When
upgrading, delete existing workspace directories and re-run `tmap analyze`:

    rm -rf <your-workspace-directory>

## CLI alias

The `tm` command is preserved as a deprecated alias for `tmap` to help
existing users transition. It will be removed in v0.3. New documentation
and examples use `tmap` exclusively.

## License

This project is licensed under [AGPL-3.0](LICENSE). See [LICENSE-FAQ.md](LICENSE-FAQ.md) for details.

For commercial licensing inquiries, please open an issue or contact the maintainer.
