import serial
import time
import sys
from serial import SerialException
import pyudev

def find_due_port():
    """动态检测 Arduino Due 的当前串口（支持复位后端口变化）"""
    context = pyudev.Context()
    for device in context.list_devices(subsystem='tty'):
        # 根据实际设备 ID 调整匹配规则
        if 'Arduino_Due' in device.get('ID_MODEL', ''):
            return device.device_node
    return None

def send_fuzz_payload(port, payload, max_retries=3):
    """发送 Payload 并检测崩溃"""
    for attempt in range(max_retries):
        try:
            with serial.Serial(port, 38400, timeout=2) as ser:
                # 1. 等待 Arduino 请求数据 ('A')
                request = ser.read(1)
                if request != b'A':
                    print(f"[Attempt {attempt+1}] Protocol error: Expected 'A', got {request}")
                    continue

                # 2. 发送数据
                length = len(payload).to_bytes(4, byteorder='little')
                ser.write(length + payload)
                print(f"[Attempt {attempt+1}] Sent: {payload[:12]}... (Length: {len(payload)})")

                # 3. 捕获可能的崩溃前输出
                time.sleep(1)  # 等待串口输出
                output = ser.read_all().decode('utf-8', errors='ignore')
                if "WARNING: Use-After-Free!" in output:
                    print("!!! UAF Warning detected !!!")

                # 4. 主动探测是否存活
                ser.write(b'PING')
                response = ser.read(1)
                if response == b'A':
                    print("[STATUS] Arduino responded normally.")
                    return False  # 未崩溃
                else:
                    print("[CRASH] No response to probe.")
                    return True  # 崩溃

        except SerialException as e:
            print(f"[CRASH] Serial port error: {str(e)}")
            return True  # 崩溃
        except Exception as e:
            print(f"[ERROR] Unexpected error: {str(e)}")
            time.sleep(2)
    
    print("[WARNING] Max retries reached.")
    return False

def main():
    # ARM 架构专用测试用例
    payloads = [
        # 1. 触发总线错误（向 ARM 保留地址 0x1FFF0000 写入）
        # b"bug!" + b"\x00\x00\xFF\x1F" * 20,  # 0x1FFF0000 是 Cortex-M3 保留区域
        b"hel"
        
        # 2. 格式化字符串攻击（连续写入 %n）
        # b"bug!%250x%n%n%n%n%n",  # 覆盖多个栈地址
        
        # 3. 超长数据触发堆溢出（全局缓冲区 buf 大小 2048）
        # b"bug!" + b"B"*3000,
    ]

    for idx, payload in enumerate(payloads):
        print(f"\n=== Testing Payload {idx+1} ===")
        due_port = find_due_port()
        
        if not due_port:
            print("ERROR: Arduino Due not found!")
            sys.exit(1)

        # 发送 payload 并检测崩溃
        crash_detected = send_fuzz_payload(due_port, payload)
        
        if crash_detected:
            print("*** Crash confirmed! ***")
            # 等待 Due 复位完成
            time.sleep(5)
        else:
            print("Target survived.")

if __name__ == "__main__":
    main()