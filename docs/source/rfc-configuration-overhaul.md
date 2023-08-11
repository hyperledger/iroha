# Iroha 2 Configuration Overhaul RFC

## Introduction

Configuration is often the first point of interaction for users with Hyperledger Iroha 2. It's crucial to make this experience as smooth as possible. However, the current system, marred by issues like redundant fields, ambiguous naming, and unclear error messages, necessitates a thorough review. This RFC sets out to propose vital improvements for a more intuitive and efficient configuration experience.

## Background

### Redundant Fields

There are configuration fields that shouldn't be initialized by the user, meaning that including them in the configuration reference is redundant. For example, here's the [excerpt](https://github.com/hyperledger/iroha/blob/35ba182e1d1b6b594712cf63bf448a2edefcf2cd/docs/source/references/config.md#sumeragi-default-null-values) about configuration options for Sumeragi:

> **Sumeragi: default `null` values**
>
> A special note about sumeragi fields with `null` as default: only the `trusted_peers` field out of the three can be initialized via a provided file or an environment variable.
>
> The other two fields, namely `key_pair` and `peer_id`, go through a process of finalization where their values are derived from the corresponding ones in the uppermost Iroha config (using its `public_key` and `private_key` fields) or the Torii config (via its `p2p_addr`). This ensures that these linked fields stay in sync, and prevents the programmer error when different values are provided to these field pairs. Providing either `sumeragi.key_pair` or `sumeragi.peer_id` by hand will result in an error, as it should never be done directly.

As we can see, if the user tries to initialize `key_pair` and `peer_id` via the config file or env variables, they'll get an error. We are creating a terrible user experience by presenting the user with an option to configure something they should not be configuring.

We should avoid exposing fields like this to the user.

### Naming Issues

The configuration parameters naming presents a few challenges.

#### Overcomplicated ENV Variables

ENV variables for all configuration parameters are named according to the internal module names. These technical designations might resonate with developers but can be confusing or alienating for users not deeply immersed in the project's inner mechanisms. Many FOSS projects gravitate towards generic, descriptive names to ensure broader comprehension and enhanced usability.

#### Inconsistent Naming of ENV Variables

The output from the `iroha --help` command displays a mix of naming conventions:

```
Iroha 2 is configured via environment variables:
    IROHA2_CONFIG_PATH is the location of your `config.json` or `config.json5`
    IROHA2_GENESIS_PATH is the location of your `genesis.json` or `genesis.json5`
...
    IROHA_TORII: Torii (gateway) endpoint configuration
    IROHA_SUMERAGI: Sumeragi (emperor) consensus configuration
    IROHA_KURA: Kura (storage). Configuration of block storage
    IROHA_BLOCK_SYNC: Block synchronisation configuration
...
```

The inconsistency between the `IROHA2` and `IROHA` prefixes can be confusing.

#### Inconsistent Naming of Configuration Parameters

Current configuration demonstrates some inconsistencies in parameter naming, leading to potential user confusion. Specifically:

- In the `torii` section:
  - We have terms like `p2p_addr`, `api_url`, and `telemetry_url`. While "addr" and "url" may convey similar intents, the interchangeability of these terms is non-intuitive.
  - Using prefixes instead of suffixes, like transitioning from `p2p_addr` to `addr_p2p`, progresses from a general term to a specific one, simplifying interpretation.
- In the `logger` section:
  - The term `max_log_level` could be simplified to `log_level` or just `level` to make it more concise without losing meaning.
- In the `wsv` section:
  - The field `wasm_runtime_config` has a redundant `_config` suffix. Given the nature of these parameters as configurations, such suffixes are extraneous and can be dropped for clarity.

Implementing a consistent naming convention will further streamline the configuration process for users.

#### Redundant SCREAMING_CASE in JSON Configuration

The adoption of SCREAMING_CASE for parameters within the JSON configuration appears out of place. Such uppercase field names might be customary for environment variables, but in a JSON setting, they don't offer any distinctive benefit. Here's a snippet from the current configuration showcasing this:

```json
{
  "PUBLIC_KEY": null,
  "PRIVATE_KEY": null,
  "DISABLE_PANIC_TERMINAL_COLORS": false
}
```

---

In sum, these issues underscore the need for clearer, more intuitive naming conventions in Iroha 2's configuration.

### Rustisms in the Configuration Reference

Configuration reference contains Rust-specific expressions that wouldn't make sense to the end-user who is configuring Iroha and might not be familiar with Rust. Here are some examples:

- [Using `Option<..>`](https://github.com/hyperledger/iroha/blob/35ba182e1d1b6b594712cf63bf448a2edefcf2cd/docs/source/references/config.md#option)
- [Using `std::path::PathBuf`](https://github.com/hyperledger/iroha/blob/35ba182e1d1b6b594712cf63bf448a2edefcf2cd/docs/source/references/config.md#loggerlog_file_path)

The use of rustisms like that overcomplicates the configuration reference and affects the user experience.

### Unhelpful Error Messages

Some of the error messages related to Iroha configuration are inconsistent and misleading. Here's a quick rundown of various scenarios, associated errors and possible confusions.

#### 1. No configuration file

Running Iroha without a configuration file results in the following log and error:

```
IROHA_TORII: environment variable not found
IROHA_SUMERAGI: environment variable not found
IROHA_KURA: environment variable not found
IROHA_BLOCK_SYNC: environment variable not found
IROHA_PUBLIC_KEY: environment variable not found
IROHA_PRIVATE_KEY: environment variable not found
IROHA_GENESIS: environment variable not found
Configuration file not found. Using environment variables as fallback.
Error:
   0: Please add `PUBLIC_KEY and PRIVATE_KEY` to the configuration.
```

Several things are wrong with this error message:

- The information about using environment variables as fallback comes after the messages about them not being found.
- Hinting to add `PUBLIC_KEY` and `PRIVATE_KEY` to the configuration does not explain what happened (the absence of the config file and no environment variables to fallback to). This hint is also not helpful as there is no information on whether public and private keys should be added to the config file or to ENV variables, and no information about the ENV variables these fields are mapped to.

#### 2. Path to non-existent config file

Providing a path to a configuration file that doesn't exist results in the exact same error as if there was no configuration file specified at all.

While it makes sense to silently fallback to ENV variables if the user doesn't provide a path to a config file, in case when the user **does** specify the path to a config file, it would be better for the program to fail with an appropriate error message.

#### 3. Empty config file

Running Iroha with an empty `config.json` results in the error that does not provide any information about the fallback to the environment variables even though it does happen. This behaviour is inconsistent.

```
Error:
   0: Please add `PUBLIC_KEY and PRIVATE_KEY` to the configuration.
```

#### 4. Config file with only `PUBLIC_KEY` and `PRIVATE_KEY` specificed

Running Iroha with a config file that only contains `PUBLIC_KEY` and `PRIVATE_KEY` results in the following error:

```
Error:
   0: Please add `p2p_addr` to the configuration.
```

This error message is misleading and inconsistent:

- If the `p2p_addr` field is added to the config file, the error stays the same.
- The `p2p_addr` field is not a root-level field, it's actually a part of the `TORII` configuration and should be `TORII.P2P_ADDR`.
- Error messages asking to add public and private keys use uppercase for configuration fields, while in this error the field name is written in lowercase.

#### 5. Config file with only `PUBLIC_KEY`, `PRIVATE_KEY`, and `TORII.P2P_ADDR` specified

Running Iroha with a config file that only contains `PUBLIC_KEY`, `PRIVATE_KEY`, and `TORII.P2P_ADDR` results in the following error:

```
Error:
   0: Please add `api_url` to the configuration.
```

Comparing this scenario to the previous one, we can notice that the `TORII.API_URL` was missing before as well but the previous error message didn't mention it.

There are also two inconsistencies:

- Similar to `p2p_addr` in the previous scenario, this field name is lowercase, while for public and private keys it was uppercase.
- While `TORII.P2P_ADDR` and `TORII.API_URL` share the same root-level (`TORII`), their names are different: "addr" derived from "address" and "URL". Logically these are both addresses or URLs, and it would make sense for the names to be aligned.

#### 6. Config file with invalid `PUBLIC_KEY`

Providing an invalid `PUBLIC_KEY` in the `config.json` results in the same error as when there is no config file at all, or an empty config file:

```
Error:
   0: Please add `PUBLIC_KEY and PRIVATE_KEY` to the configuration.
```

This is not a helpful error message as it does not mention what exactly is wrong, why and where the parsing failed.

#### 7. Invalid `IROHA2_PUBLIC_KEY` environment variable

Providing an invalid `IROHA2_PUBLIC_KEY` environment variable results in the following error:

```
Error:
   0: Failed to build configuration from env
   1: Failed to deserialize the field `IROHA_PUBLIC_KEY`: JSON5: Key could not be parsed. Key could not be parsed. Invalid character 's' at position 4
   2: JSON5: Key could not be parsed. Key could not be parsed. Invalid character 's' at position 4
```

While this message is more helful than the ones we discussed above, there are still issues:

- The message contains repetition.
- Without an input snippet, the `Invalid character 's' at position 4` part of the message is not as helpful as it could be.

#### 8. Config file with extra fields

Providing a configuration file with extra fields that are not supposed to be there does not produce any errors at all.

This might lead to a bad user experience when user expects some options to apply, but doesn't have any idea that those in fact are silently ignored.

#### 9. Specifying `SUMERAGI.PUBLIC_KEY`

As you can see in the "Redundant fields" section, user should not specify any non-null value for `SUMERAGI.PUBLIC_KEY` parameter. However, if they do, they will get the following error:

```
Error:
   0: Please add `PUBLIC_KEY and PRIVATE_KEY` to the configuration.
```

The problem is that the error message tells something completely unrelated to the actual cause. This produces a terrible experience for users.

#### 10. Config file is an invalid JSON file

Providing an invalid JSON file as a config results in the same error we've seen before, which is not useful at all in this particular case and doesn't tell the user anything about the invalid JSON:

```
Error:
   0: Please add `PUBLIC_KEY and PRIVATE_KEY` to the configuration.
```

### Ambiguity in Setting Root-Level Fields via ENV

To understand the issue with ambiguity at the root-level fields, let's once again look at the excerpt from the [configuration reference](https://github.com/hyperledger/iroha/blob/35ba182e1d1b6b594712cf63bf448a2edefcf2cd/docs/source/references/config.md#network):

> **`network`**
>
> Network configuration
>
> Has type `Option<network::ConfigurationProxy>`. Can be configured via environment variable `IROHA_NETWORK`
>
> ```json
> {
>   "ACTOR_CHANNEL_CAPACITY": 100
> }
> ```

As we can see, `network` is not actually a configuration field in itself. Instead, there are various `network.*` fields that can be configured. This bring a question of what will happen when we set the `IROHA_NETWORK` environment variable as mentioned in the excerpt above? Will it override the nested `IROHA_NETWORK_CAPACITY` fields? Is there a use case for providing an ability to set `IROHA_NETWORK` all-in-one through an environment variable?

### Chaotic Code Organisation

Internally, not all of the configuration-related logic is contained within a single `iroha_config` crate. Instead, some of the configuration resolution logic is located in other crates, such as `iroha_cli`. This makes the configuration-related code error-prone and harder to maintain.

## Proposals

### Proposal 1 - Use TOML

#### Objective

Transition to TOML as Iroha's standard configuration format to provide a cleaner, more intuitive setup and to align with Rust community standards.

#### Rationale

- **Human-Friendly Syntax:** TOML's format is easier to read and understand compared to JSON, especially given its support for comments.
- **Rust Ecosystem Alignment:** Adopting TOML ensures that Iroha remains consistent with prevalent configuration practices in the Rust community.
- **Elimination of SCREAMING_CASE:** By using TOML, Iroha can also abandon the use of SCREAMING_CASE in configuration, making it more in line with conventional formatting standards.

#### Summary

Adopting TOML allows Iroha to embrace a more readable and conventional configuration format. The move away from JSON will simplify user interaction and align Iroha better with the broader Rust ecosystem.

#### See Also

- [Proposal 3 - Consistent Naming of Configuration Parameters](#proposal-3---consistent-naming-of-configuration-parameters)
- [Proposal 4 - Better Aliases for ENV](#proposal-4---better-aliases-for-env)
- [Proposal 5 - Define Deprecation and Migration Policy](#proposal-5---define-deprecation-and-migration-policy)

### Proposal 2 - Reference Before Implementation

#### Objective

Establish a clear and comprehensive configuration reference prior to actual code implementation. This approach ensures that any new features or changes are well-documented, understandable, and in alignment with the project's goals.

#### Rationale

- **Clarity and Direction:** By laying out a detailed reference before diving into coding, we make sure everyone's on the same page and knows the direction we're headed.
- **Efficient Development:** Prevents potential backtracking or revisions in the coding phase, as developers will be working with a clear guide.
- **Enhanced Collaboration:** A preliminary reference can be critiqued, discussed, and iterated upon, leading to better decisions in the design phase.
- **User Engagement:** Early availability of a configuration reference aids in early user feedback, ensuring that the implementation is user-centric.

#### Sub-points and References:

- **[Proposal 1 - Use TOML](#proposal-1---use-toml)**: Settling on TOML as the standard configuration format before diving into the coding phase will prevent format-switching complications.
- **[Proposal 3 - Consistent Naming of Configuration Parameters](#proposal-3---consistent-naming-of-configuration-parameters)**: Prior to implementation, deciding on naming conventions and potential changes (like nesting keys under `iroha` or changing parameter names) will streamline development and ensure consistency.
- **[Proposal 4 - Better Aliases for ENV](#proposal-4---better-aliases-for-env)**: Defining environment variable aliases in advance allows for more predictable and user-friendly configuration handling.
- **[Proposal 5 - Define Deprecation and Migration Policy](#proposal-5---define-deprecation-and-migration-policy)**: Establishing guidelines on how to handle deprecated features or migrations ensures smoother transitions and fewer surprises for users.

#### Summary

Developing a configuration reference before the actual implementation can lead to a more coherent, user-friendly, and efficient development process. By addressing key points beforehand, like naming conventions, format choices, and alias definitions, Iroha 2 will be better positioned to deliver a configuration system that resonates with its users.

#### See Also

- [[suggestion] Remove the requirement to set `sumeragi.key_pair` and `sumeragi.peer_id` to `null` in the configuration · Issue #3504 · hyperledger/iroha](https://github.com/hyperledger/iroha/issues/3504)
- [[suggestion] Get rid of "rustisms" in the configuration reference · Issue #3505 · hyperledger/iroha](https://github.com/hyperledger/iroha/issues/3505)
- [[suggestion] Enhance configuration reference format · Issue #3507 · hyperledger/iroha](https://github.com/hyperledger/iroha/issues/3507)

### Proposal 3 - Consistent Naming of Configuration Parameters

#### Objective

Standardise the naming conventions of Iroha's configuration parameters, enhancing their intuitiveness and consistency for improved user interaction.

#### Rationale

- **Clarity:** Consistent naming reduces ambiguity, allowing users to more easily understand and predict parameter names.
- **Documentation Ease:** A unified naming convention simplifies the documentation process, ensuring coherence and easier updates.
- **Error Minimisation:** Predictable and clear naming reduces the risk of configuration errors by users.

#### Proposed Renamings

Here are the proposed changes for more consistent naming:

- `torii`:
  - Rename from `p2p_addr` to `addr_p2p`.
  - Rename from `api_url` to `addr_api`.
  - Rename from `telemetry_url` to `addr_telemetry`.
- `logger`:
  - Rename from `max_log_level` to `log_level` or simply `level`.
- `wsv`:
  - Rename from `wasm_runtime_config` to `wasm_runtime`.

For the sake of uniformity, it might be beneficial to nest the root `public_key` and `private_key` under an `iroha` namespace, resulting in `iroha.public_key` and `iroha.private_key`.

Please note that this list is not exhaustive. During the configuration reference design process, we might encounter further areas of improvement and additional renaming suggestions.

#### Summary

This proposal aims to standardise the naming conventions within Iroha's configuration parameters, ensuring clarity and predictability, which will enhance user experience and streamline documentation efforts.

#### See Also

- [Proposal 1 - Use TOML](#proposal-1---use-toml)
- [Proposal 4 - Better Aliases for ENV](#proposal-4---better-aliases-for-env)
- [Proposal 5 - Define Deprecation and Migration Policy](#proposal-5---define-deprecation-and-migration-policy)
- [Representation of key pair in configuration files · Issue #2135 · hyperledger/iroha](https://github.com/hyperledger/iroha/issues/2135)

### Proposal 4 - Better Aliases for ENV

#### Objective

Introduce intuitive and standardized environment variable names, moving away from internal code-names, to simplify user experience.

#### Rationale

- **User Accessibility:** Generifying names improves understanding and avoids confusion. Using internal module names can be restrictive and lead to misconfiguration.
- **Consistency:** A uniform naming convention for environment variables enhances predictability, aiding users in setting up configurations without constantly referring to documentation.
- **Transition Support:** New aliases will coexist with existing ones, ensuring no disruptions and aiding users during the transitional phase.

#### Proposed Changes

1. **Rename Based on Functionality:** Shift from code-based naming to function-based naming. For example:
   - `TORII_API_URL` becomes `API_ENDPOINT_URL`.
   - Convert `KURA_INIT_MODE` to `BLOCK_REVALIDATION_MODE`.
   - `LOGGER_MAX_LOG_LEVEL` becomes `MAX_LOG_LEVEL` or simply `LOG_LEVEL`
2. **Document All Aliases:** Clearly list main variables and their respective aliases in the configuration reference.
3. **Trace Resolution in Logs:** For clarity, ensure that when an alias is used, its resolution to the actual parameter is evident in logs.

#### Summary

By transitioning to more user-friendly ENV variable names and reducing reliance on internal naming conventions, we aim to make Iroha 2's configuration process more intuitive and error-free.

#### See Also

- [Proposal 2 - Reference Before Implementation](#proposal-2---reference-before-implementation)
- [Proposal 3 - Consistent Naming of Configuration Parameters](#proposal-3---consistent-naming-of-configuration-parameters)
- [Proposal 7 - Trace Configuration Resolution](#proposal-7---trace-configuration-resolution)

### Proposal 5 - Define Deprecation and Migration Policy

#### Objective

To establish a clear and structured policy for marking features as deprecated and guiding users towards adopting newer alternatives or configurations.

#### Rationale

- **User Trust:** A well-documented deprecation policy ensures that users can trust the software's lifecycle and understand the trajectory of its development.
- **Smooth Transitions:** Clear policies guide users in migrating from older configurations or features to newer ones, ensuring continuity of operations.
- **Maintainability:** Developers benefit from clear guidelines on when and how to retire older code, helping in reducing technical debt.
- **Clear Communication:** A standardized policy ensures that all users, from developers to end-users, have a clear understanding of changes.

#### Proposed Policy

1. **Notification:** When a feature or configuration is marked for deprecation, it should be communicated via release notes, documentation updates, and, when relevant, through warnings within the software itself.
2. **Grace Period:** Provide users a sufficient grace period (e.g., a few versions ahead) before the deprecated feature is removed. This period allows them to adjust and migrate without sudden disruptions.
3. **Migration Guidelines:** Offer detailed documentation on how to transition from the deprecated feature or configuration to its modern replacement.
4. **Clear Timeline:** Specify a clear timeline from the moment of deprecation to the removal, giving users ample time to prepare.
5. **Deprecated Feature Registry:** Maintain a list or registry of all deprecated features and configurations, along with their slated removal dates, for users to reference.

#### Summary

Introducing a structured deprecation and migration policy not only establishes trust with users but also ensures the software evolves efficiently, balancing innovation with stability.

### Proposal 6 - Exhaustive Error Messages

#### Objective

To enhance user troubleshooting by offering comprehensive and descriptive error messages during the configuration stage, specifically for two main types of configuration errors.

#### Rationale

Diagnosing and resolving configuration errors can be challenging without detailed insights. A more descriptive error messaging system offers the following benefits:

1. **Parsing with Precision:**
   - **Highlight Invalid Data's Location:** Pinpoint the exact location of errors, making it easier for users to address.
   - **Identify Missing Fields:** Rapidly flag any necessary but absent data, speeding up the configuration process.
   - **Spot Unknown Fields:** Alert users to any unrecognized fields, helping them to quickly catch and fix typographical mistakes or redundant information.
2. **Clear Directions for Domain-Specific Errors:**
   - **Highlighting Semantic Issues:** Inform users about errors or warnings tied to the higher-level domain details specific to Iroha. This ensures that users are aware of any nuances or complexities related to Iroha itself, allowing for a more refined and accurate configuration.
3. **Eliminate Guesswork:**
   - **Full Transparency in Reporting:** Ensure users are immediately and fully informed of any issues, preventing oversights and minimizing confusion.
4. **Consistency in Communication:**
   - **Uniform, Informative Messaging:** Maintain a consistent style across error messages, bolstering clarity and user understanding.
5. **Streamline Multi-Error Solutions:**
   - **Bulk Reporting of Missing Fields:** If several fields are missing, display them all simultaneously for more efficient troubleshooting.

#### Potential Solutions & Samples

To illustrate the potential of this system, a Proof-of-Concept (PoC) repository should be created, showcasing the clarity and utility of these enhanced error messages in Rust.

#### Summary

Implementing exhaustive error messages will drastically enhance user troubleshooting, ensuring a smoother and more efficient configuration process for Iroha users.

#### See Also

- [[suggestion] Enhance configuration parsing with precise field locations · Issue #3470 · hyperledger/iroha](https://github.com/hyperledger/iroha/issues/3470)

### Proposal 7 - Trace Configuration Resolution

#### Objective

Implement a mechanism that displays the sequence in which configuration is determined. This allows users to grasp the sources from which configuration values are derived, whether they're being overridden, and which resort to default values.

#### Rationale

Transparency in configuration resolution is vital for troubleshooting and ensuring the correct setup. By providing clear feedback on how parameters are set, users can identify potential misconfigurations or conflicts quickly.

#### Proposed Tracing Output

```
iroha-config: Loaded `~/config.toml`
  Configured:
    `iroha.public_key`
    `iroha.private_key`
    `sumeragi.block_time_ms`
    ...
iroha-config: Sourced ENV variables
  Configured:
    `torii.addr_p2p` from `API_ENDPOINT_URL` ENV var
    ...
  Overridden:
    `sumeragi.block_time_ms` from `BLOCK_TIME_MS` ENV var
    ...
iroha-config: Defaulted to:
  Fields:
    ...
```

#### Enabling Configuration Tracing

To activate configuration tracing, users can use the `--trace-config` command-line argument or set the `IROHA_TRACE_CONFIG=1` environment variable. Given the sequential nature of the configuration resolution process, the tracing mechanism is intentionally separated from Iroha's main logger. This ensures that tracing can be performed even before the configuration (which defines parameters like `logger.log_level`) is fully resolved. Keeping configuration tracing as a straightforward on-off switch, without the complexity of log levels, further simplifies the user's interaction and guarantees that all relevant trace data is captured when enabled.

#### Sensitive Information

While the trace provides detailed information, caution should be taken to avoid exposing sensitive data, such as private keys, ensuring security isn't compromised.

#### Further Integration

Incorporating these traces into configuration-related error messages can further streamline troubleshooting, enhancing user experience. (Refer to: [Proposal 6 - Exhaustive Error Messages](#proposal-6---exhaustive-error-messages))

#### Summary

This proposal aims to allow users to see how the config gets pieced together, making it easier to set up and fix any hiccups along the way.

#### See Also

- [[suggestion] Trace configuration parameters resolution · Issue #3502 · hyperledger/iroha](https://github.com/hyperledger/iroha/issues/3502)

### Proposal 8 - Dual-View Configuration Resolution

The dichotomy between configurations which are user-friendly and those that are efficient for software interpretation and validation can be bridged through a dual-view configuration system: "User Config" and "Resolved Config".

#### Objective

Provide a distinction between the configuration as perceived by the user and the software's operational, validated configuration view, striking a balance between user-friendliness and software efficiency & correctness.

#### Rationale

1. **User Clarity and Software Efficiency:** Keeping a representation that directly mirrors the reference for users (User Config) and a separate, robustly-typed structure for the software's operational use (Resolved Config) benefits both users and developers.
2. **Parse, Not Validate:** Transitioning from the User Config to the Resolved Config involves rigorous parsing and validation. Upon the formation of the Resolved Config, it's inherently valid, minimising the likelihood of runtime configuration errors.
3. **Domain-Specific Considerations:** The transformation phase applies domain (in this case, Iroha) specific rules and logic, ensuring the final Resolved Config is both syntactically and semantically apt.

#### Research about Resolved Configuration

##### Redundant Fields

In the background about [redundant fields](#redundant-fields), it's mentioned that these fields were made available to end users primarily because the user config wasn't separated from the resolved config. However, in a two-stage configuration resolution, these redundant fields can be managed more efficiently.

##### Root-Level `public_key` and `private_key`

When users provide their configuration input, it should be possible for them to specify only the private key. From this, the public key can be derived. If both keys are provided, the system should derive the public key from the given private key for validation. A discrepancy between the derived public key and the provided one would lead to an error.

##### Telemetry Configuration

Considering the user config's structure:

```rust
struct Telemetry {
    /// The node's name to be seen on the telemetry
    name: Option<String>,
    /// The url of the telemetry, e.g., ws://127.0.0.1:8001/submit
    url: Option<Url>,
    /// The minimum period of time in seconds to wait before reconnecting
    min_retry_period: u64,
    /// The maximum exponent of 2 that is used for increasing delay between reconnections
    max_retry_delay_exponent: u8,
    /// The filepath that to write dev-telemetry to
    file: Option<std::path::PathBuf>,
}
```

The telemetry functionality in Iroha relies heavily on the `name` field. Without it:

- If other fields are set but `name` is omitted, the system could issue a warning indicating the ignored fields.
- If the `name` is given, but neither `url` nor `file` are specified, the system should either issue a warning or terminate, signaling that the telemetry configuration is incomplete.
- If both the `url` and `file` fields are filled (indicating a potential conflict), a warning about the conflict should be raised, followed by a system termination.

#### Summary

This proposal introduces a distinction between user-centric configuration (User Config) and the system's operational perspective (Resolved Config). By separating these views, it facilitates clearer user inputs, streamlines domain-specific validation, and aims to achieve a more robust and accurate software implementation of the configuration. The goal is to ensure that the system operates optimally while still accommodating user input effectively.

#### See Also

- [[suggestion] Separate "user" config from "resolved" config · Issue #3500 · hyperledger/iroha](https://github.com/hyperledger/iroha/issues/3500)

## Implementation Plan

### Step 1 - Configuration Design & Reference Creation

**Description**: This phase focuses on designing the configuration, considering user needs, best practices, and ensuring alignment with project requirements.

**Resources & Prerequisites**:

- Comprehensive understanding of the current Iroha 2 configuration.
- Knowledge of best practices in configuration design.
- Collaboration with technical writers who will serve as the primary authors of the reference.
- Collaboration with developers and potential users to gather requirements and feedback.

**Specific Objectives**:

- Re-design naming of configuration parameters, introducing aliases for the ENV.
- Employ TOML as a domain language to describe the configuration.
- Establish a deprecation and migration policy as part of the reference.

**Deliverables**:

- A detailed configuration reference document outlining the structure, default values, data types, and descriptions for each configuration parameter.

**Potential Risks**:

- Misalignment with user needs if not adequately consulted.
- Overcomplication or oversimplification of configuration design.

**Feedback Loop**:

- Regularly consult with both developers and potential users to ensure design alignment with their expectations and use cases.

### Step 2 - Development of a Generic Configuration Library

**Description**: Develop a robust configuration library to act as the foundational piece for Iroha 2 and potentially other projects due to its open-source nature.

**Resources & Prerequisites**:

- Might be done concurrently with [Step 1](#step-1---configuration-design--reference-creation)
- Proficient Rust developers with experience in procmacros.
- Understanding of requirements from the Configuration Design phase.

**Specific Criteria**:

- Support for exhaustive error messages, including batch-error collection and dependable deserialization failure messages.
- Capabilities to compose configurations from incomplete parts for merging.
- Customizable merge strategies on a field-level.
- Support for multiple configuration source formats, notably TOML.
- Consider best and worst practices used in existing configuration-related libraries (namely: [`config`](https://docs.rs/config/latest/config/), [`figment`](https://docs.rs/figment/latest/figment/), [`schematic`](https://docs.rs/schematic/latest/schematic/)).

**Deliverables**:

- A well-documented, open-source configuration library.
- Unit and integration tests to ensure functionality.

**Potential Risks**:

- The library might not cater to all specific needs of Iroha 2.
- Potential technical debt if rushed or not adequately tested.

**Feedback Loop**:

- Continuous integration and testing setup.
- Regular checks with the Configuration Design team.

### Step 3 - Iterative Implementation & Testing

**Description**: Implement the designed configuration reference using the developed library. Ensure its functionality through iterative testing.

**Resources & Prerequisites**:

- The configuration reference from [Step 1](#step-1---configuration-design--reference-creation).
- The configuration library from [Step 2](#step-2---development-of-a-generic-configuration-library).
- Testing environment and tools.

**Deliverables**:

- Fully implemented configuration for Iroha 2 according to the reference.
- Comprehensive tests showcasing the configuration's functionality and adherence to the reference.

**Potential Risks**:

- Implementation might diverge from the design if not regularly checked.
- Unforeseen technical challenges or limitations.

**Feedback Loop**:

- Regular testing and validation against the configuration reference.
- Potential beta testing or feedback sessions with a subset of users to understand usability and issues.

### Step 4 - Integration, Field Testing & Feedback Collection

**Description**: Integrate the newly developed configuration with Iroha 2. Conduct field tests to assess its real-world performance and gather feedback.

**Resources & Prerequisites**:

- Completed and tested configuration from [Step 3](#step-3---iterative-implementation--testing).
- Access to Iroha 2 codebase and integration tools.
- A pool of testers or users for field testing.

**Deliverables**:

- Configuration successfully integrated into Iroha 2.
- Feedback report from field tests detailing user experience, potential issues, and improvements.

**Potential Risks**:

- Integration challenges due to unforeseen incompatibilities.
- Negative user feedback or usability challenges.

**Feedback Loop**:

- Regular integration testing and validation.
- Direct communication channels with field testers to gather timely feedback.

### Step 5 - Iterative Refinement & Optimization

**Description**: After integrating the new configuration into Iroha 2, there might be some elements that need refining based on user feedback and field testing.

**Resources & Prerequisites**:

- Feedback from the [integration phase](#step-4---integration-field-testing--feedback-collection).
- Development and testing environments.

**Deliverables**:

- A refined configuration addressing user feedback.
- Documentation updates reflecting changes made.

**Potential Risks**:

- Over-optimization leading to reduced clarity.
- Potential rework if feedback indicates major design flaws.

**Feedback Loop**:

- Continued consultation with users.
- Performance isn't a primary concern, but the configuration should be robust and user-friendly.

## Impact Assessment

The proposed overhaul of Iroha 2's configuration system stands to significantly impact various facets of the project, both technical and user-facing. These implications touch on the project's future scalability, user experience, and maintainability.

### Technical Impact

- **Code Complexity**: The pursuit of an enhanced user experience may lead to a more intricate configuration codebase. This increased complexity might make the system harder to maintain and debug.
- **Performance Impact**: While the configuration happens at startup and isn't a recurring process, there might be a slight performance dip due to the enhancements. This is considered acceptable given the trade-off for improved user experience.

### Operational Impact

- **User Transition**: Given the main goal of this RFC — simplifying the configuration for end users — we anticipate a minimal migration pain for current users. The proposed changes, informed by earlier sections of this RFC, are intended to streamline and simplify the process for them.
- **Deployment & Migration**: The revamped configuration could bring new deployment methods or procedures. Clear documentation will be essential to guide system administrators and users through these changes.

### User Impact

- **Enhanced User Experience**: The main drive behind these changes is to offer users a more intuitive configuration mechanism, reducing barriers to adoption and use.
- **Communication & Feedback**: Regular interaction with the community, especially the early adopters, will be crucial. This helps to ensure that user feedback is accounted for, leading to a more refined final product.

### Documentation & Training

- **Updated Documentation**: Every change made to the configuration system should be meticulously documented. Updated release notes and configuration guides will serve as primary resources for early adopters.
- **Training Sessions**: While intensive tutorials might not be needed, organizing small workshops or webinars for significant changes can be beneficial, especially to ease any potential transition concerns.

### Financial & Time Impact

- **Resource Allocation**: The development of a new configuration library, alongside other proposed changes, will necessitate both time and expertise. Efficiently managing these resources is vital to maintaining the momentum of the project.
- **Project Timeline**: While we haven't set a specific timeline or deadline for the release, it's essential that the configuration overhaul doesn't become a hindrance to the broader project's progress.

### Risk Assessment

- **Anticipating Challenges**: As the project progresses, unforeseen challenges related to the proposed changes may arise. Having strategies to address these in advance ensures minimal disruption.
- **Backup Strategies**: Given the scope and depth of the changes, it's prudent to have contingency plans. These plans ensure the project continues to progress smoothly, even when faced with unexpected hurdles.

In essence, this RFC's primary objective is to drastically simplify Iroha 2's configuration for its users. Careful planning, consistent communication, and regular feedback loops will be pivotal in achieving this objective successfully.

## Conclusion

Throughout this RFC, we've discussed fundamental enhancements for the Iroha 2 configuration system. From transitioning to TOML and refining naming conventions, to creating an early configuration reference and clearer error messages, each proposed change aims to elevate the user experience. Adopting these suggestions can transform Iroha 2's configuration from a potential stumbling block to a robust foundation. We eagerly anticipate community feedback to refine these ideas further.
