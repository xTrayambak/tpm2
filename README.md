# A work-in-progress implementation of the TPM2 stack in native Nim.
Keep in mind that most stuff does not work right now. Only the serialization module works as of right now, work is being done on the commands handler.

# Roadmap
- Stop using `ref object`, use ORC and destructors instead.
- Implement an `easy` module that lets you read/write from the chip without the headache of setting everything up.

# Attributions
I'm mostly learning how TPM2 works via [the TPM2 stack implementation in Rust](https://github.com/marcoguerri/rust-tpm2)
