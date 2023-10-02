# STM32L4 readout protection exploit

This is still IN PROGRESS - and has not been made working yet. Do not go into this expecting results.

This repository contains an adaptation of the Flash Patch Breakpoint expoit originally described by Johannes Obermaier in https://www.usenix.org/system/files/woot20-paper-obermaier.pdf for STM32F1 family of embedded controllers.

This code was forked off of the work done by lolwheel on adapting it to the STM32F4 series (Cortex M4)

This code was further modified to hopefully work with the STM32L4 - which is the MCU used by CatGenie AI

## Things worth mentioning:
* The default baud rate of this rootshell is 256kb.
* The SRAM of F4 seems more sensitive to power loss. Data gets corrupted at room temprerature quickly so you'll have to freeze the chip right before glitching. An upside down dust blower pointed at the target chip works great for this. (Need to Verify this is the same for the L4)
* Do not bother sampling the NRST pin for power loss, just kill the power to the chip momentarily. I used an ESP8266 as an attack board and consecutive `digitalWrite(0); digitalWrite(1);` of the target chip power pins with no delay between them was consistently enough to reset it. (Need to Verify this is the same for the L4)
* Freezing the chip makes its internal oscillator deviate enoug to mangle the root shell UART output. Wait till the target chip warms back up to the room temperature. Keep typing "h" and hitting "Enter" in the terminal till you start seeing legible response from the root shell. (Need to verify this is the same for the L4)

The code is heavily based on the proof-of-concept sample published by Johannes Obermaier at https://github.com/JohannesObermaier/f103-analysis/tree/master/h3/rootshell
