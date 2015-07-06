# make clean && make mrproper 
mkdir output
make -C $(pwd) O=output msm8916_sec_defconfig VARIANT_DEFCONFIG=msm8916_sec_serranove3g_eur_defconfig SELINUX_DEFCONFIG=selinux_defconfig
make -j5 -C $(pwd) O=output
cp $(pwd)/output/arch/arm/boot/zImage $(pwd)/arch/arm/boot/zImage

if [ ! -d $(pwd)/output/modules ];
    then
        mkdir $(pwd)/output/modules;
    fi
find $(pwd)/output -name '*.ko' -exec cp -v {} $(pwd)/output/modules \;

exit
