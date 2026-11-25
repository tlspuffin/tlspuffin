{ pkgs ? import (builtins.fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-25.11.tar.gz") {} }:

let
  java = pkgs.fetchzip {
    url = "https://download.oracle.com/java/25/archive/jdk-25.0.4.1_linux-x64_bin.tar.gz";
    sha256 = "1rbilj3xfig0mx7rggkv3scvfr43dwz6q02d8i4ahhajalz4p7qn";
    stripRoot = true;
  };
  node = pkgs.fetchzip {
    url = "https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-x64.tar.xz";
    sha256 = "03sz9hy31nh6lf3mai61hqkgqws9z3nx74rlv881b28bn86qvcvh";
    stripRoot = true;
  };
  artemis = pkgs.fetchzip {
    url = "https://archive.apache.org/dist/activemq/activemq-artemis/2.44.0/apache-artemis-2.44.0-bin.tar.gz";
    sha256 = "1w10xsbxcnfq0ky0f451lm37s24rh095h1ka8g9f9g0i8vgj85fl";
    stripRoot = true;
  };
in
pkgs.mkShell {
  packages = [
    pkgs.rustup
    pkgs.git
    pkgs.just
    pkgs.cmake
    pkgs.gcc
    pkgs.gnumake
    pkgs.pkg-config
    pkgs.llvmPackages.clang
    pkgs.llvmPackages.llvm
    pkgs.llvmPackages.libclang
    pkgs.autoconf
    pkgs.automake
    pkgs.libtool
    pkgs.openssl
    pkgs.maven
    pkgs.cacert
    pkgs.postgresql_16
  ];

  JAVA_HOME = "${java}";
  NODE_HOME = "${node}";
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
  SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
  GIT_SSL_CAINFO = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
  NIX_SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

  POSTGRES_DB = "control_component";
  POSTGRES_USER = "control_component";
  POSTGRES_PASSWORD = "control_component";

  shellHook = ''
    export PGDATA="''${PGDATA:-/tmp/pgdata-$(id -u)}"
    export PGHOST="''${PGHOST:-/tmp}"

    if [ ! -s "$PGDATA/PG_VERSION" ]; then
      initdb -D "$PGDATA" -U "$POSTGRES_USER" --auth=trust >/dev/null
      pg_ctl -D "$PGDATA" -l /tmp/pg.log -o "-k $PGHOST" -w start >/dev/null
      createdb -h "$PGHOST" -U "$POSTGRES_USER" "$POSTGRES_DB"
    elif ! pg_ctl -D "$PGDATA" status >/dev/null 2>&1; then
      pg_ctl -D "$PGDATA" -l /tmp/pg.log -o "-k $PGHOST" -w start >/dev/null
    fi

    export PATH="${java}/bin:${node}/bin:${artemis}/bin:$PATH"
    export ARTEMIS_HOME="${artemis}"
    export SPP_E_VOTING_ROOT="$(realpath "${toString ./.}/../../e-voting")"
    export SPP_CRYPTO_PRIMITIVES_ROOT="$(realpath "${toString ./.}/../../crypto-primitives")"
    export LIBAFL_EDGES_MAP_SIZE=262144

    sppuffin-build-java() {
      (cd "$SPP_CRYPTO_PRIMITIVES_ROOT" && mvn -DskipTests install) || return
      (cd "$SPP_E_VOTING_ROOT" && mvn -pl control-component -am -DskipTests install) || return
      (cd "$SPP_E_VOTING_ROOT/control-component" &&
        mvn -q dependency:build-classpath -Dmdep.outputFile=target/sppuffin-classpath.txt) || return

      export SPP_JAVA_CLASSPATH="$SPP_E_VOTING_ROOT/control-component/target/classes:$(cat "$SPP_E_VOTING_ROOT/control-component/target/sppuffin-classpath.txt")"
      echo "SPP_JAVA_CLASSPATH is ready for sppuffin."
    }

    if [ -f "$SPP_E_VOTING_ROOT/control-component/target/sppuffin-classpath.txt" ]; then
      export SPP_JAVA_CLASSPATH="$SPP_E_VOTING_ROOT/control-component/target/classes:$(cat "$SPP_E_VOTING_ROOT/control-component/target/sppuffin-classpath.txt")"
    fi

    echo "Java: $(java -version 2>&1 | head -n 1)"
    echo "Maven: $(mvn --version | head -n 1)"
    echo "Rust: $(rustc --version 2>/dev/null || echo 'installed by rustup on first use')"
    echo "Run sppuffin-build-java to compile the crypto-primitives and control-component Java code."
  '';
}
