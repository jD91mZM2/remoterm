with import <nixpkgs> {};
stdenv.mkDerivation rec {
  name = "remoterm";
  buildInputs = [ pkgconfig openssl ];
}
