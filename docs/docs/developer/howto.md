---
title: 'How To'
---


## How to add a preset to a vendor library?

For a preset configuration 'P' of a library 'L':
1. add a section `[<P>]` to the presets file `puffin-build/vendors/<L>/presets.toml` with the appropriate configuration
2. edit the documentation's support matrix in `docs/docs/reference/support-matrix.md`
3. add the preset to the CI test matrix in `.github/tlspuffin.matrix.json`

For more info about the preset configuration, see also the [mk_vendor documentation](../developer/build.md#mk_vendor)

