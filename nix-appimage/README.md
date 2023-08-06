# nix-appimage

Create an AppImage, bundling a derivation and all its dependencies into a single-file executable.
Like [nix-bundle](https://github.com/matthewbauer/nix-bundle), but much faster and without the glibc dependency.

## Getting started

To use this, you will need to have [Nix](https://nixos.org/) available.
Then, run this via the [nix bundle](https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-bundle.html) interface, replacing `nixpkgs.hello` with the flake you want to build:

```
$ nix bundle --bundler github:ralismark/nix-appimage nixpkgs#hello
```

This produces `hello-2.12.1-x86_64.AppImage`, which prints "Hello world!" when run:

```
$ ./hello-2.12.1-x86_64.AppImage
Hello, world!
```

If you get a `main program ... does not exist` error, or want to specify a different binary to run, you can instead use the `./bundle` script:

```
$ ./bundle dnsutils /bin/dig # or ./bundle dnsutils dig
$ ./dig-x86_64.AppImage -v
DiG 9.18.14
```

### Caveats

- The produced file isn't a fully conforming AppImage.
For example, it's missing the relevant .desktop file and icons -- this doesn't affect the running of bundled apps in any way, but might cause issues with showing up correctly in application launchers (e.g. rofi).
Please open an issue if this is something you want.
- This requires Linux User Namespaces (i.e. `CAP_SYS_USER_NS`), which are available since Linux 3.8 (released in 2013).
- Plain files in the root directory aren't visible to the bundled app.

### OpenGL

Addressing issues with running OpenGL apps on non-NixOS systems is also *out of scope* for this project -- you'll still have to use e.g. [nixGL](https://github.com/guibou/nixGL) to make those graphical programs work without NixOS.

### How it works / Comparison with nix-bundle

This project wouldn't be possible without the groundwork already laid out in [nix-bundle](https://github.com/matthewbauer/nix-bundle), and a lot here is inspired by what's done there.

The main benefit over nix-bundle's default arx format is that we don't need to unpack the files every time we start up.
This significantly speeds up startup to the point that it's practically instant.

Thanks to using [AppImageCrafers/appimage-runtime](https://github.com/AppImageCrafters/appimage-runtime), the produced bundle doesn't depend on glibc, avoiding the [issue described here](https://github.com/AppImage/AppImageKit/issues/877) and meaning it should be portable to more system.
Since the AppImage format itself (specifically [type 2 images](https://github.com/AppImage/AppImageSpec/blob/ce1910e6443357e3406a40d458f78ba3f34293b8/draft.md#type-2-image-format)) is essentially just the runtime binary concatenated with a squashfs file system, we also avoid unnecessary copies in the build step.

We do something similar to `nix-user-chroot`, but instead only mount in the `/nix` directory before running the entrypoint symlink.
