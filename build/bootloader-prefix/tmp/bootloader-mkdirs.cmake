# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/acnz/esp/v5.4/esp-idf/components/bootloader/subproject"
  "/home/acnz/BM13XX_sim/build/bootloader"
  "/home/acnz/BM13XX_sim/build/bootloader-prefix"
  "/home/acnz/BM13XX_sim/build/bootloader-prefix/tmp"
  "/home/acnz/BM13XX_sim/build/bootloader-prefix/src/bootloader-stamp"
  "/home/acnz/BM13XX_sim/build/bootloader-prefix/src"
  "/home/acnz/BM13XX_sim/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/acnz/BM13XX_sim/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/acnz/BM13XX_sim/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
