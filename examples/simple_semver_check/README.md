# Simple Semver Check

This can be used as a simple example of how the AVP local agent works, 
a playground for profiling this crate, or to validate against a semver violation. 

## Steps for Checking a Semver Violation

1. Create a release branch with new code and publish it. 
2. Set the branch target in `Cargo.toml` to the new release branch. 
3. Compile and run this example. 
4. If the behavior is the same and no code changes need to be made, there's no semver violation!
5. Make sure to run `cargo-semver-checks` and double check each PR too. Neither this check nor `cargo-semver-checks` is guaranteed to catch everything. 
6. Commit the version bump and any changes to the new release branch. If there have been any changes, make sure the new version is a major version. 