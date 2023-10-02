all:
	arm-none-eabi-gcc -o test.o -c test.S -mthumb -mcpu=cortex-m4 -g3
	arm-none-eabi-gcc -o main.o -c main.c -mthumb -mcpu=cortex-m4 -Os -g3 -DSTM32L415xx -IInc -IDrivers/CMSIS/Device/ST/STM32L4xx/Include -IDrivers/CMSIS/Include
	arm-none-eabi-gcc -o system_stm32l4xx.o -c system_stm32l4xx.c -mthumb -mcpu=cortex-m4 -Os -g3 -DSTM32L415xx -IInc -IDrivers/CMSIS/Device/ST/STM32L4xx/Include -IDrivers/CMSIS/Include
	arm-none-eabi-gcc -o sram.elf ./test.o ./main.o ./system_stm32l4xx.o -nostartfiles -nostdlib -Tram.ld -mcpu=cortex-m4 -mthumb -g3
	arm-none-eabi-objcopy -O binary sram.elf shellcode.bin
	
clean:
	-rm -fR *.o *.elf