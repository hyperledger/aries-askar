_Generating the C header:_

Install [cbindgen](https://github.com/eqrion/cbindgen/):

```sh
cargo install cbindgen
```

Install rust toolchain nightly (required for macro expansion):

```sh
rustup toolchain install nightly
rustup default nightly
```

From the root directory, generate the header file:

```sh
cbindgen --config include/cbindgen.toml --output include/libaries_askar.h
```
