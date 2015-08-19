#!/bin/bash

case "$1" in
         3g)
            VARIANT="msm8916_sec_serranove3g_eur_defconfig"
            ;;

        lte)
            VARIANT="msm8916_sec_serranovelte_eur_defconfig"
            ;;

          *)
            VARIANT="msm8916_sec_serranove3g_eur_defconfig"
esac

if [ ! -d $(pwd)/output ];
    then
        mkdir $(pwd)/output;
    fi

make -C $(pwd) O=output msm8916_sec_defconfig VARIANT_DEFCONFIG=$VARIANT SELINUX_DEFCONFIG=selinux_defconfig
make -j5 -C $(pwd) O=output
cp $(pwd)/output/arch/arm/boot/zImage $(pwd)/arch/arm/boot/zImage

if [ ! -d $(pwd)/output/modules ];
    then
        mkdir $(pwd)/output/modules;
    fi
find $(pwd)/output -name '*.ko' -exec cp -v {} $(pwd)/output/modules \;

$(pwd)/dtbTool -2 -o $(pwd)/output/arch/arm/boot/dt.img -s 2048 -p $(pwd)/output/scripts/dtc/ $(pwd)/output/arch/arm/boot/dts/ -v

exit
