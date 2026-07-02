#include <SPI.h>
#include <mcp_can.h>

const int SPI_CS_PIN = 10;
MCP_CAN CAN(SPI_CS_PIN);

// Experiment settings. Change MY_NODE_ID on each board.
const byte MY_NODE_ID = 2;
const byte TARGET_NODE_ID = 5;
const unsigned long SEND_INTERVAL = 100;
const int MAX_PACKET_COUNT = 100;
const int ERROR_PERCENT = 0;

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
  while (CAN_OK != CAN.begin(MCP_ANY, CAN_500KBPS, MCP_8MHZ)) {
    delay(500);
  }
  CAN.setMode(MCP_NORMAL);
  Serial.println("=== TREE Topology System ===");
}

// Tree structure:
//       1
//     /   \
//    2     3
//   / \
//  4   5
byte getTreeNextHop(byte target) {
  if (MY_NODE_ID == 1) {
    if (target == 4 || target == 5 || target == 2) return 2;
    if (target == 3) return 3;
  } else if (MY_NODE_ID == 2) {
    if (target == 4) return 4;
    if (target == 5) return 5;
    if (target == 1 || target == 3) return 1;
  } else if (MY_NODE_ID == 3) {
    return 1;
  } else if (MY_NODE_ID == 4 || MY_NODE_ID == 5) {
    return 2;
  }
  return 0;
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
        long unsigned int rxId;
        unsigned char len = 0;
        unsigned char rxBuf[8];
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
        Serial.println("# [START] TREE Experiment Started.");
      }
    }

    if (isExperimentStarted && (sentPacketCount < MAX_PACKET_COUNT)) {
      if (time_now - lastSendTime >= SEND_INTERVAL) {
        lastSendTime = time_now;
        localSeq++;
        sentPacketCount++;

        Serial.print("S,"); Serial.print(millis()); Serial.print(",");
        Serial.print(MY_NODE_ID); Serial.print(","); Serial.print(localSeq); Serial.print(","); Serial.println(TARGET_NODE_ID);

        byte next = getTreeNextHop(TARGET_NODE_ID);
        if (next != 0) {
          sendPacket(next, MY_NODE_ID, TARGET_NODE_ID, localSeq);
        }

        if (sentPacketCount == MAX_PACKET_COUNT) {
          isExperimentStarted = false;
        }
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
  long unsigned int rxId;
  unsigned char len = 0;
  unsigned char rxBuf[8];

  if (CAN_MSGAVAIL == CAN.checkReceive()) {
    CAN.readMsgBuf(&rxId, &len, rxBuf);
    byte logicalNextHop = (byte)(rxId - CAN_ID_BASE);

    if (logicalNextHop == MY_NODE_ID) {
      byte origin = rxBuf[0];
      byte target = rxBuf[1];
      byte seq = rxBuf[2];

      if (target == MY_NODE_ID) {
        Serial.print("R,"); Serial.print(millis()); Serial.print(",");
        Serial.print(origin); Serial.print(","); Serial.print(seq); Serial.print(","); Serial.println(target);
      } else {
        byte next = getTreeNextHop(target);
        if (next != 0) {
          Serial.print("F,"); Serial.print(millis()); Serial.print(",");
          Serial.print(origin); Serial.print(","); Serial.print(seq); Serial.print(",");
          Serial.print(MY_NODE_ID); Serial.print(","); Serial.println(target);
          delay(2);
          sendPacket(next, origin, target, seq);
        }
      }
    }
  }
}

void sendPacket(byte nextHop, byte origin, byte target, byte seq) {
  unsigned char buf[8] = {origin, target, seq, 0, 0, 0, 0, 0};
  CAN.sendMsgBuf(CAN_ID_BASE + nextHop, 0, 8, buf);
}
