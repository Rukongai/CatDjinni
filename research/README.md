# This folder contains my notes and findings on the CatGenie AI

Board images and xrays taken from Rober Delien from the following Google Group and myself
https://groups.google.com/g/catgenius/c/3AZXsqBmoig

![AC Board Front](images/CatGenie%20AC%20board%20rev2%20-%20front.jpeg) ![AC Board Xray](images/CatGenie%20AC%20board%20rev2.png)
![Mainboard Front](images/CatGenie%20DC%20board%20v2.5%20rev8.3.767R%20-%20front.jpeg) ![Mainboard Xray](images/CatGenie%20DC%20board%20v2.5%20rev8.3.767R%20(wide%20dnr).png) ![Mainboard Back](images/IMG_2215.jpg)
![Touch Panel Back](images/CatGenie%20control%20panel%20v2%20rev734%20-%20back.jpeg) ![Touch Panel Xray](images/CatGenie%20control%20panel%20v2%20rev734.png)

## Hardware

### MCU
STM32L462RET6
* RDP Level 1 Enabled

![STM32L4 LQFP64 Pin Map](images/STM32L4xx%20-%20Pinout.png)

Note: The L4 does not have a physical Boot 1 pin - it's an option bit. Also - to boot to SRAM - instead of having 0/1 high, L4 requires 0 high and the OB for 1 unset (low)

### Flash Memory
W25Q128JV
* 128M-Bit

![W25Q128JV SOC-8 Pin Map](images/W25Q128JV%20-%20Pinout.png)

### WNIC
ATWINC1500 

![ATWINC1500 Pin Map](images/ATWINC15x0%20-%20Pinout.png)

### RFID
CR95HF

![CR95HF Pin Map](images/CR95HF-%20Pinout.png)

### Headers
| JP12 | WNIC     | STM32     |
|------|----------|-----------|
| 1    | VCC      | VCC       |
| 2    | CHIP_EN  | PH3-BOOT0 |
| 3    | I2C_SDA  |           |
| 4    | RESET_N  | PA11      |
| 5    | I2C_SCL  |           |
| 6    | UART_RXD |           |
| 7    | UART_TXD |           |
| 8    | GND      | GND       |

| JP10 | JP7       | STM32     |
|------|-----------|-----------|
| 1    | 1         | VCC       |
| 2    | 6 (SWO)   | PB3       |
| 3    |           | PB13      |
| 4    |           | PC0       |
| 5    |           | PC1       |
| 6    | USART1_TXD| PA9       |
| 7    | USART1_RXD| PA10      |
| 8    | 5         | GND       |

USART1 seems to be disabled? Will be still using this header for developing the initial exploit, enabling it via the custom SRAM firmware

| JP7 | STM32 | SWD     |
|-----|-------|---------|
| 1   | VCC   | VCC     |
| 2   | PA13  | SWDIO   |
| 3   | NRST  | #RESET  |
| 4   | PA14  | SWCLK   |
| 5   | GND   | GND     |
| 6   | PB3   | SWO     |


JP7 is the SWD header - the connector uses TagConnect TC2030 connection

Flash Memory
| Pin | Flash | STM32   |
|-----|-------|---------|
| 1   | CS    | PB11    |
| 2   | DO    | PB0     |
| 3   | WP    | PA7     |
| 4   | GND   | GND     |
| 5   | VCC   | VCC     |
| 6   | HOLD  | PA6     |
| 7   | CLK   | PB10    |
| 8   | DI    | PB1     |
