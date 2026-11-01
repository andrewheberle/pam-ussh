# Changelog

## [1.3.0](https://github.com/andrewheberle/pam-ussh/compare/v1.2.4...v1.3.0) (2026-11-01)


### Features

* add agent_timeout option, defaulting to 30s, for the ssh-agent exchange ([#69](https://github.com/andrewheberle/pam-ussh/issues/69)) ([11cfddc](https://github.com/andrewheberle/pam-ussh/commit/11cfddc57204ddb32d0bdb702ba9d10739234d30))
* log each record at the syslog priority matching its slog level ([#70](https://github.com/andrewheberle/pam-ussh/issues/70)) ([8e25236](https://github.com/andrewheberle/pam-ussh/commit/8e25236c29139ea257b1f3192cccbcc14877d2a0))


### Bug Fixes

* check certificate principals once, before the possession proof ([#65](https://github.com/andrewheberle/pam-ussh/issues/65)) ([a7394f0](https://github.com/andrewheberle/pam-ussh/commit/a7394f0ad20196d4cc655b69c43a2b949722faea))
* **deps:** update module golang.org/x/crypto to v0.52.0 [security] ([#43](https://github.com/andrewheberle/pam-ussh/issues/43)) ([0b27b7a](https://github.com/andrewheberle/pam-ussh/commit/0b27b7a889e17111fe67a5a8024c43b37287a467))
* **deps:** update module golang.org/x/crypto to v0.58.0 ([#57](https://github.com/andrewheberle/pam-ussh/issues/57)) ([7bb77aa](https://github.com/andrewheberle/pam-ussh/commit/7bb77aa0f46cd0157ca3457e3a46f8f4968824a8))
* fail closed on PAM options missing a value instead of panicking ([#58](https://github.com/andrewheberle/pam-ussh/issues/58)) ([9009a8a](https://github.com/andrewheberle/pam-ussh/commit/9009a8a84f77f000c128c773986249efeff1e8eb))
* make the last authorized_principals option win, as documented ([#68](https://github.com/andrewheberle/pam-ussh/issues/68)) ([9eeabc1](https://github.com/andrewheberle/pam-ussh/commit/9eeabc136220382ae4b57639d6c2ec61c5490e55))
* open syslog once per authentication and log with log/slog ([#61](https://github.com/andrewheberle/pam-ussh/issues/61)) ([a2b536e](https://github.com/andrewheberle/pam-ussh/commit/a2b536e7557b200be07af5e5743755e4f9496df3))
* **packaging:** ship the license in the .deb and drop a no-op ldflag ([#72](https://github.com/andrewheberle/pam-ussh/issues/72)) ([99c709e](https://github.com/andrewheberle/pam-ussh/commit/99c709e804b0acaec2464cdd5797aab27c900ee8))
* reject host certificates and certificates without principals ([#66](https://github.com/andrewheberle/pam-ussh/issues/66)) ([c751021](https://github.com/andrewheberle/pam-ussh/commit/c751021b573606f082183c97a0737d5fefa51c5d))
* report a User CA with no valid keys as ErrNoValidCA ([#64](https://github.com/andrewheberle/pam-ussh/issues/64)) ([91c695a](https://github.com/andrewheberle/pam-ussh/commit/91c695a3c12283e1284f6cb82d8c7e78f0fa5040))
* try the next certificate when a possession proof fails ([#67](https://github.com/andrewheberle/pam-ussh/issues/67)) ([054b7bb](https://github.com/andrewheberle/pam-ussh/commit/054b7bbb0ca47f46041bdddd9d56a4adad677725))
