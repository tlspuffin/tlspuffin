# protofuzz, profuzz, protfuzz, proto-tls-fuzz

## Setup

Install [rustup](https://rustup.rs/) and setup a toolchain:

```bash
rustup install 1.51.0-x86_64-unknown-linux-gnu
```

The toolchain `1.51.0-x86_64-unknown-linux-gnu` is tested and is used for development. You may also use `rustup install 1.51.0` to install the toolchain for your OS. 

Now, build the project:

```bash
git clone git@gitlab.inria.fr:mammann/symbolic-tls-fuzzer.git
git submodule update --init --recursive
cargo build
```

## Run

```bash
RUST_LOG=trace cargo run --package crotofuzz --bin crotofuzz
```

## Interesting Libraries:

* Graph/Tree https://sachanganesh.com/programming/graph-tree-traversals-in-rust/
  * https://rosettacode.org/wiki/Visualize_a_tree#Rust
* Plot Tree Plotly
    * https://plotly.com/python/tree-plots/
    * https://docs.rs/plotly/0.6.0/plotly/scatter/struct.Scatter.html
* https://github.com/google/evcxr/blob/master/evcxr_jupyter/samples/evcxr_jupyter_tour.ipynb