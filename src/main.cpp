#include <Arduino.h>
#include <PN532_I2C.h>
#include <PN532.h>
#include <Wire.h>
#include <NfcAdapter.h>

PN532_I2C pn532_i2c(Wire);
PN532 nfcDriver(pn532_i2c);
NfcAdapter nfcAdapter = NfcAdapter(pn532_i2c);
bool isFormatMode = false;
#define XOFF 0x13
#define XON  0x11
#define BUFFER_HIGH_WATERMARK 20  // ~75% of 64 bytes, ask to stop sending
#define BUFFER_LOW_WATERMARK  16 

bool xoffSent = false;

void checkFlowControl(int available) {
    /*
    if (available > 0) {
        Serial.print(F("Available bytes: "));
        Serial.println(available);
    }
    //*/
    if (!xoffSent && available >= BUFFER_HIGH_WATERMARK) {
        Serial.write(XOFF);
        //Serial.println(F("Flow control: XOFF sent"));
        xoffSent = true;
    } else if (xoffSent && available <= BUFFER_LOW_WATERMARK) {
        Serial.write(XON);
        //Serial.println(F("Flow control: XON sent"));
        xoffSent = false;
    }
}

//*
bool tryAuthAndWrite(int block, uint8_t* key, uint8_t* data) {
    uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };
    uint8_t uidLen;

    if (!nfcDriver.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 50)) return false;

    if (nfcDriver.mifareclassic_AuthenticateBlock(uid, uidLen, block, 0, key)) {
        if (nfcDriver.mifareclassic_WriteDataBlock(block, data)) return true;
    }

    if (!nfcDriver.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 50)) return false;
    
    if (nfcDriver.mifareclassic_AuthenticateBlock(uid, uidLen, block, 1, key)) {
        if (nfcDriver.mifareclassic_WriteDataBlock(block, data)) return true;
    }

    return false;
}

void formatTag() {
    uint8_t factoryTrailer0[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x78, 0x77, 0x88, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    uint8_t factoryTrailer1[] = { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0x7F, 0x07, 0x88, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    // Csak a két legvalószínűbb kulcs (Gyári és NDEF)
    uint8_t k1[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t k2[] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};

    bool success = tryAuthAndWrite(3, k1, factoryTrailer0);
    uint8_t header1[] = { 0x14, 0x01, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 };
    uint8_t header2[] = { 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 };
    success = nfcDriver.mifareclassic_WriteDataBlock(1, header1);
    success = nfcDriver.mifareclassic_WriteDataBlock(2, header2);
    uint8_t emptyBlock[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    
    for (int sector = 1; sector < 16 && success; sector++) {
        int trailerBlock = (sector * 4) + 3;
        success = false;

        if (tryAuthAndWrite(trailerBlock, k1, factoryTrailer1)) success = true;
        
        if (!success && tryAuthAndWrite(trailerBlock, k2, factoryTrailer1)) success = true;

        if (success) {
            for(int i=0; i<3; i++) {
                int block = (sector * 4) + i;
                success = nfcDriver.mifareclassic_WriteDataBlock(block, emptyBlock);
                if (!success) break;
            }
        }

        Serial.print(F("Sector reset "));
        Serial.print(sector);
        Serial.println(success ? F(" Success") : F(" Failure"));
    }
}


void writeVCard(char* name, char* phone, char* email) {

    NdefMessage message = NdefMessage();
    
    byte vCard[720]; // 752 bytes is the max size for a Mifare Classic 1K, but we need to leave some space for the NDEF header and record header, so we use 720 bytes for the vCard data.
    snprintf((char*)vCard, sizeof(vCard), "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:%s\r\nTEL:%s\r\nEMAIL:%s\r\nEND:VCARD", name, phone, email);

#ifdef DEBUG
    Serial.println(F("Generated vCard:"));
    for(int i = 0; i < strlen((char*)vCard); i++) {
        Serial.print(vCard[i]);
        if (i % 10 == 0) {
            delay(100);
        };
    }
    Serial.println();
#endif

    message.addMimeMediaRecord(F("text/vcard"), vCard, strlen((char*)vCard));

    bool success = nfcAdapter.write(message);
    
    if (success) {
        Serial.println(F("SUCCESS! vCard 3.0 recorded."));
    } else {
        Serial.println(F("ERROR! Try factory reset..."));
    }
    delay(5000);
}
//*/

int idx = 0;
int idxInput = 0;
byte inputValues[3][128] = { {0}, {0}, {0} };

void setup() {
    Serial.begin(115200);
    while (!Serial){}
    Serial.println(F("Initialize wire and PN532 detection..."));
    Wire.begin();
    Serial.println(F("Wire initialized."));
    Serial.println(F("Initializing PN532..."));
    nfcDriver.begin();
    Serial.println(F("PN532 initialized."));
    nfcDriver.SAMConfig();
  
  // read version
  
    uint32_t versiondata = nfcDriver.getFirmwareVersion();
    if (!versiondata) {
        Serial.println(F("No PN532 module found. Please check the connection!"));
        while (1); // stop here
    }
    Serial.print(F("Found PN532 module. Version: "));
    Serial.print((versiondata >> 24) & 0xFF, HEX);
    Serial.print('.');
    Serial.print((versiondata >> 16) & 0xFF, HEX);
    Serial.print('.');
    Serial.println((versiondata >> 8) & 0xFF, HEX); 
}

byte buffer[128];

void loop() {
    int available = Serial.available();
    //checkFlowControl(available);
    if (available > 0) {
        Serial.print(F("Available bytes: "));
        Serial.println(available);
        Serial.readBytes(buffer, available);
        for(int i = 0; i < available; i++) {
            char ch = buffer[i];
#ifdef DEBUG
            Serial.print(ch);
#endif
            if (idx < 3 && ch != ';' && ch != '\n' && ch != '\r' && ch != '\t') {
                inputValues[idx][idxInput++] = ch;
            }
            if (ch == '\n') {
                inputValues[idx][idxInput++] = '\0';
                Serial.println(String(F("Name: ")) + (char*)inputValues[0]);
                delay(100);
                Serial.println(String(F("Phone: ")) + (char*)inputValues[1]);
                delay(100);
                Serial.println(String(F("Email: ")) + (char*)inputValues[2]);
            }
            if (ch == ';') {
                inputValues[idx][idxInput++] = '\0';
                idx++;
                idxInput = 0;
            }
            if (ch == '\r') {
                idxInput = 0;
                idx = 0;
            }
            if (ch == '\t') {
                isFormatMode = !isFormatMode;
                Serial.println(isFormatMode ? F("Format mode enabled.") : F("Format mode disabled."));
            }
        }
    }

Serial.write(XOFF);
Serial.flush();
    if (nfcAdapter.tagPresent()) {
        if (isFormatMode) {
            Serial.println(F("Formatting tag..."));
            formatTag();
            delay(5000);
        } else {
            Serial.println(F("Writing vCard..."));
            writeVCard((char*)inputValues[0], (char*)inputValues[1], (char*)inputValues[2]);
        }
    }
Serial.write(XON);
Serial.flush();

}