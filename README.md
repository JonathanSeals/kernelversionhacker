# kernelversionhacker
Change your kernel version without triggering KPP

xcrun -sdk iphoneos clang -arch armv7 -arch armv7s -arch arm64 kernelversionhacker.c -o kernelversionhacker; ldid -Stfp0.plist kernelversionhacker
