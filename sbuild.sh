#!/bin/bash
make msm8916_sec_defconfig VARIANT_DEFCONFIG=msm8916_sec_serranove3g_eur_defconfig SELINUX_DEFCONFIG=selinux_defconfig
#make -j5 > make_kernel.log
