# This folder contains my notes and findings on the CatGenie AI

Board images and xrays taken from Rober Delien from the following Google Group
https://groups.google.com/g/catgenius/c/3AZXsqBmoig



| JP12 | WNIC | STM32 |
|------|--------|---------|
| 1 | VCC | VCC |
| 2 | CHIP_EN | PH3-BOOT0 |
| 3 | I2C_SDA | |
| 4 | RESET_N | PA11 |
| 5 | I2C_SCL | |
| 6 | UART_RXD | |
| 7 | UART_TXD | |
| 8 | GND | GND |

| JP10 | JP7 | STM32 |
|------|------|--------|
| 1 | 1 | VCC |
| 2 | 6 (SWO) | PB3 |
| 3 |  | PB13 |
| 4 |  | PC0 |
| 5 |  | PC1 |
| 6 | USART1_TXD | PA9 |
| 7 | USART1_RXD | PA10 |
| 8 | 5 | GND |

USART1 seems to be disabled? Will be still using this header for developing the initial exploit, enabling it via the custom SRAM firmware

| JP7 | STM32 | SWD |
|-----|---------|-------|
| 1 | VCC | VCC |
| 2 | PA13 | SWDIO |
| 3 | NRST | #RESET |
| 4 | PA14 | SWCLK |
| 5 | GND | GND |
| 6 | PB3 | SWO |

JP7 is the SWD header - the connector uses TagConnect TC2030 connection

Flash Memory
| Pin | Flash | STM32 |
|-----|-------|---------|
| 1 | CS | PB11 |
| 2 | DO | PB0 |
| 3 | WP | PA7 |
| 4 | GND | GND |
| 5 | VCC | VCC |
| 6 | HOLD | PA6 |
| 7 | CLK | PB10 |
| 8 | DI | PB1 |

<img width="640" alt="CR95HF" src="https://github.com/davidhampgonsalves/CR14-emulator-for-CatGenie-120/assets/11468686/dcfc4783-19c5-4e84-85b4-d3aedbd368c4">
<img width="792" alt="STM32L462RET6" src="https://github.com/davidhampgonsalves/CR14-emulator-for-CatGenie-120/assets/11468686/11c17076-8a46-4d6b-8f21-df0dc4f3d1ab">
<img width="381" alt="W25Q128JV" src="https://github.com/davidhampgonsalves/CR14-emulator-for-CatGenie-120/assets/11468686/548540f6-8819-48f4-ac90-11bcd24e7cd2">
<img width="545" alt="WNIC" src="https://github.com/davidhampgonsalves/CR14-emulator-for-CatGenie-120/assets/11468686/c5f1ca78-dec0-40de-b446-eef2274171c2">
