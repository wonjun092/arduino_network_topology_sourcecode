#include <SPI.h>
#include <mcp_can.h>

const int SPI_CS_PIN = 10; 
MCP_CAN CAN(SPI_CS_PIN);

// [실험 설정 변수]
const byte MY_NODE_ID = 2;       
const byte TARGET_NODE_ID = 5;   
const unsigned long SEND_INTERVAL = 100; 
const int MAX_PACKET_COUNT = 100;        
const int ERROR_PERCENT = 0;   // 장애 실험 시 20~30으로 변경

unsigned long lastSendTime = 0;
int sentPacketCount = 0;
bool isExperimentStarted = false;        
unsigned long lastErrorCheckTime = 0;
bool isNodeDead = false;                 
unsigned long deadStartTime = 0;

const unsigned int CAN_ID_BASE = 0x100;
byte localSeq = 0; 

void setup() {
  Serial.begin(115200);
  while (CAN_OK != CAN.begin(MCP_ANY, CAN_500KBPS, MCP_8MHZ)) { delay(500); }
  CAN.setMode(MCP_NORMAL);
  Serial.println("=== BUS Topology System ===");
}

void loop() {
  unsigned long time_now = millis();

  if (isNodeDead) {
    if (time_now - deadStartTime >= 1500) { 
      isNodeDead = false;
      lastErrorCheckTime = time_now; 
      Serial.print("W,"); Serial.print(millis()); Serial.print(","); Serial.println(MY_NODE_ID);
    } else {
      if (CAN_MSGAVAIL == CAN.checkReceive()) {
        long unsigned int rxId; unsigned char len = 0; unsigned char rxBuf[8];
        CAN.readMsgBuf(&rxId, &len, rxBuf);
      }
      return; 
    }
  } else {
    if (Serial.available() > 0) {
      char cmd = Serial.read();
      if (cmd == 'g' || cmd == 'G') {
        isExperimentStarted = true;
        sentPacketCount = 0;
        localSeq = 0;
        lastSendTime = time_now;
        Serial.println("# [START] BUS Experiment Started.");
      }
    }

    if (isExperimentStarted && (sentPacketCount < MAX_PACKET_COUNT)) {
      if (time_now - lastSendTime >= SEND_INTERVAL) {
        lastSendTime = time_now;
        localSeq++;
        sentPacketCount++;
        
        Serial.print("S,"); Serial.print(millis()); Serial.print(","); 
        Serial.print(MY_NODE_ID); Serial.print(","); Serial.print(localSeq); Serial.print(","); Serial.println(TARGET_NODE_ID);
        
        // BUS 구조: 목적지로 직접 다이렉트 전송
        sendPacket(TARGET_NODE_ID, MY_NODE_ID, TARGET_NODE_ID, localSeq);
        
        if (sentPacketCount == MAX_PACKET_COUNT) { isExperimentStarted = false; }
      }
    }

    if (ERROR_PERCENT > 0 && (time_now - lastErrorCheckTime > 1000)) {
      lastErrorCheckTime = time_now;
      if (random(1, 101) <= ERROR_PERCENT) {
        isNodeDead = true;
        deadStartTime = time_now;
        Serial.print("E,"); Serial.print(millis()); Serial.print(","); Serial.println(MY_NODE_ID);
        return;
      }
    }

    handleCANReceive();
  }
}

void handleCANReceive() {
  long unsigned int rxId; unsigned char len = 0; unsigned char rxBuf[8];
  if (CAN_MSGAVAIL == CAN.checkReceive()) {
    CAN.readMsgBuf(&rxId, &len, rxBuf);
    byte logicalNextHop = (byte)(rxId - CAN_ID_BASE);
    
    if (logicalNextHop == MY_NODE_ID) {
      byte origin = rxBuf[0]; byte target = rxBuf[1]; byte seq = rxBuf[2];
      if (target == MY_NODE_ID) {
        Serial.print("R,"); Serial.print(millis()); Serial.print(","); 
        Serial.print(origin); Serial.print(","); Serial.print(seq); Serial.print(","); Serial.println(target);
      }
    }
  }
}

void sendPacket(byte nextHop, byte origin, byte target, byte seq) {
  unsigned char buf[8] = {origin, target, seq, 0, 0, 0, 0, 0};
  CAN.sendMsgBuf(CAN_ID_BASE + nextHop, 0, 8, buf);
}