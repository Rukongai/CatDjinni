# CatDjinni - CatGenie AI exploit research

This is still IN PROGRESS - and has not been made working yet. Do not go into this expecting results.

This repository is used to hold my current work and research around dumping the firmware from the CatGenie AI for the eventual purpose of modifying it to allow re-use of cartridges and routine modifications, better smarthome integration, and any other features that might arise.

The goal eventually is to create chip that will connect to the CatGenie AI board using the SWD header via a TC-2030 connector to allow reflashing the cat genie with a modified firmware.

This project borrows heavily from the following

* lolwheel: stm32f4-rdp-workaround https://github.com/lolwheel/stm32f4-rdp-workaround
* lolwheel: GPB_attack_board_8266 https://github.com/lolwheel/FPB_attack_board_8266
* Johannes Obermaier: Original researcher who detailed the FPB exploit https://github.com/JohannesObermaier/f103-analysis/tree/master/h3/rootshell

## attack

This folder contains the code for creating the firmware to be used on the attack board - in this case - an Espressif ESP32-Wroom-D32 from HiLetgo(I had a few on hand from another project)

I will update in a bit to show the pin mappings

## target

This folder contains the code for creating the firmware to be flashed to the SRAM of the target chip (STM32L4) prior to glitching it. 

## Current issues being worked through

### Reset Vector Entry Point
The original exploit uses a manually defined reset vector entry pointed defined in ram.ld of 0x108. This was required on the STM32F1 series, but i'm not certain if it's still relevant on the STM32L4. Still trying to understand the involved mechanisms

(Add hyperlinks)
rm0394 - STM32L4 - 2.6
rm0008 - STMF103 - 3.4

Once I figure this out - I should be able to continue

## Contributing

If anyone wants to assist I could use assistance on the following fronts

* Figuring out this exploit - STM32 REs please open an issue if you'd like to collaborate
* Developer to help make meaningful changes to the firmware once dumped and decompiled