# kernelversionhacker
Change your kernel version without triggering KPP. Should also work on iPhoneOS 3.1->iOS 10.3.3 armv7/armv7s

xcrun -sdk iphoneos clang -arch armv7 -arch armv7s -arch arm64 -miphoneos-version-min=3.1 kernelversionhacker.c -o kernelversionhacker; ldid -Stfp0.plist kernelversionhacker
