mkdir output
make -C $(pwd) O=output msm8916_sec_defconfig VARIANT_DEFCONFIG=msm8916_sec_serranove3g_eur_defconfig SELINUX_DEFCONFIG=selinux_defconfig
make -j5 -C $(pwd) O=output
cp $(pwd)/output/arch/arm/boot/zImage $(pwd)/arch/arm/boot/zImage
