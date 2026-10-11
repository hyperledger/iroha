# Iroha SDK — consumer ProGuard/R8 rules
#
# These rules are bundled into the AAR and applied automatically
# when the consuming app enables minification.

# BouncyCastle is a direct core-jvm dependency. Its JCA provider discovers
# algorithm implementations dynamically, so retain the provider entry point.
-dontwarn org.bouncycastle.**
-keep class org.bouncycastle.jce.provider.BouncyCastleProvider { *; }
