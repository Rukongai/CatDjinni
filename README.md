# CatDjinni - CatGenie AI exploit research

This is still IN PROGRESS - and has not been made working yet. If you try and use this repo - you'll likely brick your Cat Genie AI.

This repository is used to hold my current work and research around dumping the firmware from the CatGenie AI for the eventual purpose of modifying it to allow re-use of cartridges and routine modifications, better smarthome integration, and any other features that might arise.

The goal eventually is to create chip that will connect to the CatGenie AI board using the SWD header via a TC-2030 connector to allow reflashing the cat genie with a modified firmware.

This project borrows heavily from the following

* lolwheel: [stm32f4-rdp-workaround](https://github.com/lolwheel/stm32f4-rdp-workaround)
* lolwheel: [GPB_attack_board_8266](https://github.com/lolwheel/FPB_attack_board_8266)
* Johannes Obermaier: [Original researcher](https://github.com/JohannesObermaier/f103-analysis/tree/master/h3/rootshell)

## target

This folder contains the code for creating the firmware to be flashed to the SRAM of the target chip (STM32L4) prior to glitching it.

## attack

This folder contains the code for creating the firmware to be used on the attack board - in this case - an Espressif [ESP32-Wroom-D32 from HiLetgo](https://www.amazon.com/HiLetgo-ESP-WROOM-32-Development-Microcontroller-Integrated/dp/B0718T232Z)

Esp32 to Cat Genie wiring

| esp32    | CG         |
|----------|------------|
| 17 - TX  | JP10 Pin 7 |
| 16 - RX  | JP10 Pin 6 |
| 2 - POW1 | JP10 Pin 1 |
| 4 - POW2 | JP12 Pin 1 |
| 15 - NRST| JP7 Pin 3  |
| 5 - BOOT0| JP12 Pin 2 |

Because JP7 is being used for SWD and connected with the TC-2030 - I wire
* Esp32 reset -> breadboard
* ST-Link reset -> breadboard
* breadboard -> TC-2030 pin 3

This way I can remove the debug connector connections without having to disconnect the TC-2030 or lose the NRST sampling from the esp32

## Current issues being worked through

### Reset Vector Entry Point
* I'm currently still trying to get a working shell running from glitched SRAM.
* The original exploit uses a manually defined reset vector entry pointed defined in ram.ld of 0x108. This was required on the STM32F1 series, but i'm not certain if it's still relevant on the STM32L4. Still trying to understand the involved mechanisms
* I don't know if I ported the 8266 attack board code to be used with the ESP32 properly

* [rm0394](research/Documents/rm0394-stm32l41xxx42xxx43xxx44xxx45xxx46xxx-advanced-armbased-32bit-mcus-stmicroelectronics.pdf) - STM32L4 - 2.6
* [rm0090](research/Documents/rm0090-stm32f405415-stm32f407417-stm32f427437-and-stm32f429439-advanced-armbased-32bit-mcus-stmicroelectronics.pdf) - STM32F4 - 2.4
* [rm0008](research/Documents/rm0008-stm32f101xx-stm32f102xx-stm32f103xx-stm32f105xx-and-stm32f107xx-advanced-armbased-32bit-mcus-stmicroelectronics.pdf) - STMF103 - 3.4

## High level process overview

### Preparation
* Wire up the devices as described [above](#attack)
* Load the firmware to the the attack board

### Attack Execution
* Power up both board
* Open a serial interface with target (9600 Baud, 8 bits, no parity, 1 stop bit)
* Connect to target board with OpenOCD
```bash
openocd -f interface/stlink.cfg -f target/stm32l4x.cfg
```
* Telnet to OpenOCD debug port
```bash
telnet localhost 4444
```
* Flash shellcode image to SRAM
```bash
load_image shellcode.bin 0x20000000
```
* Disconnect the debugger
* Reset attack board
* Hopefully one day, a shell will appear on the serial interface

## Contributing

If anyone wants to assist I could use assistance on the following fronts

* Figuring out this exploit - STM32 REs please open an issue if you'd like to collaborate
* Developer to help make meaningful changes to the firmware once dumped and decompiled